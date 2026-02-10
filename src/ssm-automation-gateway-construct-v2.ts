import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as s3n from 'aws-cdk-lib/aws-s3-notifications';
import * as cr from 'aws-cdk-lib/custom-resources';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as logs from 'aws-cdk-lib/aws-logs';
import { Construct } from 'constructs';
import * as path from 'path';

export interface SsmAutomationGatewayV2Props {
  /**
   * Name for the AgentCore Gateway
   * @default 'EksNodeLogMcpGW'
   */
  readonly gatewayName?: string;

  /**
   * Name for the Cognito User Pool
   * @default 'ssm-automation-gateway-pool'
   */
  readonly cognitoUserPoolName?: string;

  /**
   * Name for the Cognito Resource Server
   * @default 'ssm-automation-gateway-id'
   */
  readonly resourceServerName?: string;

  /**
   * Number of days to retain logs in S3
   * @default 1
   */
  readonly logRetentionDays?: number;

  /**
   * Enable KMS encryption for S3 bucket
   * @default true
   */
  readonly enableEncryption?: boolean;

  /**
   * Enable CloudTrail data events for S3
   * @default false (requires CloudTrail to be configured separately)
   */
  readonly enableS3DataEvents?: boolean;
}

/**
 * Production-grade MCP Server for EKS Node Log Collection
 * 
 * Features:
 * - Async task pattern with idempotency
 * - Byte-range streaming for multi-GB files
 * - Manifest validation and completeness verification
 * - Pre-indexed error findings
 * - Secure artifact references with presigned URLs
 * - KMS encryption at rest
 * - Comprehensive audit logging
 */
export class SsmAutomationGatewayV2Construct extends Construct {
  public readonly logsBucket: s3.Bucket;
  public readonly ssmAutomationFunction: lambda.Function;
  public readonly unzipFunction: lambda.Function;
  public readonly findingsIndexerFunction: lambda.Function;
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly ssmAutomationRole: iam.Role;
  public readonly gatewayExecutionRole: iam.Role;
  public readonly encryptionKey?: kms.Key;

  constructor(scope: Construct, id: string, props: SsmAutomationGatewayV2Props = {}) {
    super(scope, id);

    const gatewayName = props.gatewayName ?? 'EksNodeLogMcpGW';
    const cognitoUserPoolName = props.cognitoUserPoolName ?? 'ssm-automation-gateway-pool';
    const resourceServerName = props.resourceServerName ?? 'ssm-automation-gateway-id';
    const logRetentionDays = props.logRetentionDays ?? 1;
    const enableEncryption = props.enableEncryption ?? true;

    // ========================================================================
    // KMS ENCRYPTION KEY (if enabled)
    // ========================================================================

    if (enableEncryption) {
      this.encryptionKey = new kms.Key(this, 'LogsEncryptionKey', {
        alias: `${cdk.Stack.of(this).stackName}-logs-key`,
        description: 'KMS key for EKS node log encryption',
        enableKeyRotation: true,
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });
    }

    // ========================================================================
    // IAM ROLES
    // ========================================================================

    // Role for SSM Automation to assume
    this.ssmAutomationRole = new iam.Role(this, 'SSMAutomationRole', {
      roleName: `${cdk.Stack.of(this).stackName}-ssm-automation-role`,
      assumedBy: new iam.ServicePrincipal('ssm.amazonaws.com'),
    });

    // SSM Automation permissions
    this.ssmAutomationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'SSMAutomationPermissions',
      effect: iam.Effect.ALLOW,
      actions: [
        'ssm:StartAutomationExecution',
        'ssm:StopAutomationExecution',
        'ssm:GetAutomationExecution',
        'ssm:DescribeAutomationExecutions',
        'ssm:DescribeAutomationStepExecutions',
        'ssm:SendCommand',
        'ssm:GetCommandInvocation',
        'ssm:ListCommandInvocations',
        'ssm:ListCommands',
        'ssm:CancelCommand',
        'ssm:GetDocument',
        'ssm:DescribeDocument',
        'ssm:GetParameters',
        'ssm:GetParameter',
        'ssm:DescribeInstanceInformation',
        'ssm:GetConnectionStatus',
      ],
      resources: ['*'],
    }));

    // EKS and EC2 permissions for log collection
    this.ssmAutomationRole.addToPolicy(new iam.PolicyStatement({
      sid: 'EKSAndEC2Permissions',
      effect: iam.Effect.ALLOW,
      actions: [
        'ec2:DescribeInstances',
        'ec2:DescribeTags',
        'ec2:DescribeInstanceStatus',
        'eks:DescribeCluster',
        'eks:ListClusters',
      ],
      resources: ['*'],
    }));

    // ========================================================================
    // S3 BUCKET - Log Storage with Encryption
    // ========================================================================

    const bucketProps: s3.BucketProps = {
      bucketName: `${cdk.Stack.of(this).stackName.toLowerCase()}-logs-${cdk.Stack.of(this).account}`,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      lifecycleRules: [
        {
          id: 'DeleteOldLogs',
          enabled: true,
          expiration: cdk.Duration.days(logRetentionDays),
        },
        {
          id: 'DeleteOldIdempotencyMappings',
          enabled: true,
          prefix: 'idempotency/',
          expiration: cdk.Duration.days(7),
        },
        {
          id: 'DeleteOldExecutionRegionMappings',
          enabled: true,
          prefix: 'execution-regions/',
          expiration: cdk.Duration.days(7),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    };

    // Add encryption if enabled
    if (this.encryptionKey) {
      Object.assign(bucketProps, {
        encryption: s3.BucketEncryption.KMS,
        encryptionKey: this.encryptionKey,
        bucketKeyEnabled: true,
      });
    } else {
      Object.assign(bucketProps, {
        encryption: s3.BucketEncryption.S3_MANAGED,
      });
    }

    this.logsBucket = new s3.Bucket(this, 'LogsBucket', bucketProps);

    // Grant SSM Automation role access to the bucket
    this.logsBucket.grantReadWrite(this.ssmAutomationRole);
    if (this.encryptionKey) {
      this.encryptionKey.grantEncryptDecrypt(this.ssmAutomationRole);
    }

    // Bucket policy to allow EC2 instances in the account to upload logs
    this.logsBucket.addToResourcePolicy(new iam.PolicyStatement({
      sid: 'AllowEC2InstancesUpload',
      effect: iam.Effect.ALLOW,
      principals: [new iam.AccountRootPrincipal()],
      actions: ['s3:PutObject', 's3:GetBucketPolicyStatus', 's3:GetBucketAcl'],
      resources: [this.logsBucket.bucketArn, `${this.logsBucket.bucketArn}/*`],
      conditions: {
        StringEquals: {
          'aws:PrincipalAccount': cdk.Stack.of(this).account,
        },
      },
    }));

    // ========================================================================
    // UNZIP LAMBDA FUNCTION
    // ========================================================================

    const unzipLambdaRole = new iam.Role(this, 'UnzipLambdaRole', {
      roleName: `${cdk.Stack.of(this).stackName}-unzip-lambda-role`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    this.logsBucket.grantReadWrite(unzipLambdaRole);
    if (this.encryptionKey) {
      this.encryptionKey.grantEncryptDecrypt(unzipLambdaRole);
    }

    // Create findings indexer first so we can reference it
    const findingsIndexerRole = new iam.Role(this, 'FindingsIndexerRole', {
      roleName: `${cdk.Stack.of(this).stackName}-findings-indexer-role`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    this.logsBucket.grantReadWrite(findingsIndexerRole);
    if (this.encryptionKey) {
      this.encryptionKey.grantEncryptDecrypt(findingsIndexerRole);
    }

    this.findingsIndexerFunction = new lambda.Function(this, 'FindingsIndexerFunction', {
      functionName: `${cdk.Stack.of(this).stackName}-findings-indexer`,
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'index.lambda_handler',
      role: findingsIndexerRole,
      timeout: cdk.Duration.minutes(5),
      memorySize: 1024,
      environment: {
        LOGS_BUCKET_NAME: this.logsBucket.bucketName,
      },
      code: lambda.Code.fromInline(this.getFindingsIndexerCode()),
      logRetention: logs.RetentionDays.TWO_WEEKS,
    });

    // Now create unzip function with reference to findings indexer
    this.unzipFunction = new lambda.Function(this, 'UnzipFunction', {
      functionName: `${cdk.Stack.of(this).stackName}-unzip-function`,
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'index.lambda_handler',
      role: unzipLambdaRole,
      timeout: cdk.Duration.minutes(5),
      memorySize: 1024,
      environment: {
        FINDINGS_INDEXER_FUNCTION: this.findingsIndexerFunction.functionName,
      },
      code: lambda.Code.fromInline(this.getUnzipLambdaCode()),
      logRetention: logs.RetentionDays.TWO_WEEKS,
    });

    // Grant unzip function permission to invoke findings indexer
    this.findingsIndexerFunction.grantInvoke(unzipLambdaRole);

    // Add S3 notification to trigger unzip on archive uploads
    this.logsBucket.addEventNotification(
      s3.EventType.OBJECT_CREATED,
      new s3n.LambdaDestination(this.unzipFunction),
      { suffix: '.zip' }
    );
    this.logsBucket.addEventNotification(
      s3.EventType.OBJECT_CREATED,
      new s3n.LambdaDestination(this.unzipFunction),
      { suffix: '.tar.gz' }
    );

    // ========================================================================
    // SSM AUTOMATION LAMBDA FUNCTION (Enhanced)
    // ========================================================================

    const lambdaExecutionRole = new iam.Role(this, 'LambdaExecutionRole', {
      roleName: `${cdk.Stack.of(this).stackName}-lambda-execution-role`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    // SSM Automation access
    lambdaExecutionRole.addToPolicy(new iam.PolicyStatement({
      sid: 'SSMAutomationAccess',
      effect: iam.Effect.ALLOW,
      actions: [
        'ssm:StartAutomationExecution',
        'ssm:GetAutomationExecution',
        'ssm:DescribeAutomationExecutions',
        'ssm:StopAutomationExecution',
        'ssm:DescribeInstanceInformation',
        'ssm:ListCommands',
        'ssm:ListCommandInvocations',
      ],
      resources: ['*'],
    }));

    // SSM Document access (cross-region support)
    lambdaExecutionRole.addToPolicy(new iam.PolicyStatement({
      sid: 'SSMDocumentAccess',
      effect: iam.Effect.ALLOW,
      actions: ['ssm:GetDocument', 'ssm:DescribeDocument'],
      resources: [
        `arn:aws:ssm:*::document/AWSSupport-CollectEKSInstanceLogs`,
        `arn:aws:ssm:*:${cdk.Stack.of(this).account}:document/*`,
      ],
    }));

    // EC2 DescribeInstances for cross-region instance auto-detection
    lambdaExecutionRole.addToPolicy(new iam.PolicyStatement({
      sid: 'EC2DescribeForRegionDetection',
      effect: iam.Effect.ALLOW,
      actions: [
        'ec2:DescribeInstances',
        'ec2:DescribeRegions',
      ],
      resources: ['*'],
    }));

    // S3 access
    this.logsBucket.grantReadWrite(lambdaExecutionRole);
    if (this.encryptionKey) {
      this.encryptionKey.grantEncryptDecrypt(lambdaExecutionRole);
    }

    // PassRole for SSM
    lambdaExecutionRole.addToPolicy(new iam.PolicyStatement({
      sid: 'PassRoleForSSM',
      effect: iam.Effect.ALLOW,
      actions: ['iam:PassRole'],
      resources: [this.ssmAutomationRole.roleArn],
      conditions: {
        StringEquals: {
          'iam:PassedToService': 'ssm.amazonaws.com',
        },
      },
    }));

    this.ssmAutomationFunction = new lambda.Function(this, 'SSMAutomationFunction', {
      functionName: `${cdk.Stack.of(this).stackName}-ssm-automation`,
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'ssm-automation-enhanced.lambda_handler',
      role: lambdaExecutionRole,
      timeout: cdk.Duration.minutes(2),
      memorySize: 1024,
      environment: {
        LOGS_BUCKET_NAME: this.logsBucket.bucketName,
        SSM_AUTOMATION_ROLE_ARN: this.ssmAutomationRole.roleArn,
      },
      code: lambda.Code.fromAsset(path.join(__dirname, 'lambda')),
      logRetention: logs.RetentionDays.TWO_WEEKS,
    });

    // ========================================================================
    // GATEWAY EXECUTION ROLE
    // ========================================================================

    this.gatewayExecutionRole = new iam.Role(this, 'GatewayExecutionRole', {
      roleName: `${cdk.Stack.of(this).stackName}-gateway-execution-role`,
      assumedBy: new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com'),
    });

    this.gatewayExecutionRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['lambda:InvokeFunction'],
      resources: [this.ssmAutomationFunction.functionArn],
    }));

    this.gatewayExecutionRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['logs:CreateLogGroup', 'logs:CreateLogStream', 'logs:PutLogEvents'],
      resources: ['*'],
    }));

    // Add Lambda resource-based policy to allow AgentCore to invoke
    this.ssmAutomationFunction.addPermission('AllowAgentCoreInvoke', {
      principal: new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com'),
      action: 'lambda:InvokeFunction',
      sourceAccount: cdk.Stack.of(this).account,
    });

    // ========================================================================
    // COGNITO - Authentication
    // ========================================================================

    this.userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: cognitoUserPoolName,
      passwordPolicy: {
        minLength: 8,
        requireUppercase: false,
        requireLowercase: false,
        requireDigits: false,
        requireSymbols: false,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const resourceServer = new cognito.UserPoolResourceServer(this, 'ResourceServer', {
      userPool: this.userPool,
      identifier: resourceServerName,
      scopes: [
        { scopeName: 'gateway:read', scopeDescription: 'Read access to gateway' },
        { scopeName: 'gateway:write', scopeDescription: 'Write access to gateway' },
      ],
    });

    this.userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
      userPool: this.userPool,
      userPoolClientName: 'ssm-automation-gateway-client',
      generateSecret: true,
      oAuth: {
        flows: { clientCredentials: true },
        scopes: [
          cognito.OAuthScope.custom(`${resourceServerName}/gateway:read`),
          cognito.OAuthScope.custom(`${resourceServerName}/gateway:write`),
        ],
      },
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
    });
    this.userPoolClient.node.addDependency(resourceServer);

    const userPoolDomain = new cognito.UserPoolDomain(this, 'UserPoolDomain', {
      userPool: this.userPool,
      cognitoDomain: {
        domainPrefix: `${cdk.Stack.of(this).stackName.toLowerCase()}-${cdk.Stack.of(this).account}`,
      },
    });

    // ========================================================================
    // CLIENT SECRET RETRIEVAL - Custom Resource
    // ========================================================================

    const clientSecretRetrieverRole = new iam.Role(this, 'ClientSecretRetrieverRole', {
      roleName: `${cdk.Stack.of(this).stackName}-secret-retriever-role`,
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasicExecutionRole'),
      ],
    });

    clientSecretRetrieverRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['cognito-idp:DescribeUserPoolClient'],
      resources: [this.userPool.userPoolArn],
    }));

    const clientSecretRetrieverFunction = new lambda.Function(this, 'ClientSecretRetrieverFunction', {
      functionName: `${cdk.Stack.of(this).stackName}-secret-retriever`,
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'index.handler',
      role: clientSecretRetrieverRole,
      timeout: cdk.Duration.seconds(30),
      code: lambda.Code.fromInline(this.getClientSecretRetrieverCode()),
    });

    const clientSecretRetriever = new cr.AwsCustomResource(this, 'ClientSecretRetriever', {
      onCreate: {
        service: 'Lambda',
        action: 'invoke',
        parameters: {
          FunctionName: clientSecretRetrieverFunction.functionName,
          Payload: JSON.stringify({
            RequestType: 'Create',
            ResourceProperties: {
              UserPoolId: this.userPool.userPoolId,
              ClientId: this.userPoolClient.userPoolClientId,
            },
          }),
        },
        physicalResourceId: cr.PhysicalResourceId.of('ClientSecretRetriever'),
      },
      policy: cr.AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['lambda:InvokeFunction'],
          resources: [clientSecretRetrieverFunction.functionArn],
        }),
      ]),
    });
    clientSecretRetriever.node.addDependency(this.userPoolClient);

    // ========================================================================
    // AGENTCORE GATEWAY
    // ========================================================================

    const gateway = new cdk.CfnResource(this, 'AgentCoreGateway', {
      type: 'AWS::BedrockAgentCore::Gateway',
      properties: {
        Name: gatewayName,
        Description: 'Production-grade EKS Node Log MCP Server with byte-range streaming and pre-indexed findings',
        ProtocolType: 'MCP',
        AuthorizerType: 'CUSTOM_JWT',
        AuthorizerConfiguration: {
          CustomJWTAuthorizer: {
            AllowedClients: [this.userPoolClient.userPoolClientId],
            DiscoveryUrl: `https://cognito-idp.${cdk.Stack.of(this).region}.amazonaws.com/${this.userPool.userPoolId}/.well-known/openid-configuration`,
          },
        },
        RoleArn: this.gatewayExecutionRole.roleArn,
      },
    });
    gateway.node.addDependency(this.userPoolClient);
    gateway.node.addDependency(userPoolDomain);

    // Gateway Target for Lambda
    const gatewayTarget = new cdk.CfnResource(this, 'LambdaGatewayTarget', {
      type: 'AWS::BedrockAgentCore::GatewayTarget',
      properties: {
        GatewayIdentifier: gateway.ref,
        Name: 'NodeLog',
        Description: 'Enhanced EKS Node Log Collection Target',
        TargetConfiguration: {
          Mcp: {
            Lambda: {
              LambdaArn: this.ssmAutomationFunction.functionArn,
              ToolSchema: {
                InlinePayload: this.getToolSchemaDefinitions(),
              },
            },
          },
        },
        CredentialProviderConfigurations: [
          { CredentialProviderType: 'GATEWAY_IAM_ROLE' },
        ],
      },
    });
    gatewayTarget.node.addDependency(this.ssmAutomationFunction);
    gatewayTarget.node.addDependency(this.gatewayExecutionRole);

    // ========================================================================
    // OUTPUTS
    // ========================================================================

    new cdk.CfnOutput(this, 'GatewayId', {
      description: 'ID of the AgentCore Gateway',
      value: gateway.ref,
      exportName: `${cdk.Stack.of(this).stackName}-GatewayId`,
    });

    new cdk.CfnOutput(this, 'GatewayUrl', {
      description: 'MCP Server URL',
      value: gateway.getAtt('GatewayUrl').toString(),
      exportName: `${cdk.Stack.of(this).stackName}-GatewayUrl`,
    });

    new cdk.CfnOutput(this, 'CognitoUserPoolId', {
      description: 'Cognito User Pool ID',
      value: this.userPool.userPoolId,
      exportName: `${cdk.Stack.of(this).stackName}-CognitoUserPoolId`,
    });

    new cdk.CfnOutput(this, 'CognitoClientId', {
      description: 'OAuth Client ID',
      value: this.userPoolClient.userPoolClientId,
      exportName: `${cdk.Stack.of(this).stackName}-CognitoClientId`,
    });

    new cdk.CfnOutput(this, 'OAuthExchangeUrl', {
      description: 'OAuth Token URL',
      value: `https://${cdk.Stack.of(this).stackName.toLowerCase()}-${cdk.Stack.of(this).account}.auth.${cdk.Stack.of(this).region}.amazoncognito.com/oauth2/token`,
      exportName: `${cdk.Stack.of(this).stackName}-OAuthExchangeUrl`,
    });

    new cdk.CfnOutput(this, 'OAuthScope', {
      description: 'OAuth Scope',
      value: `${resourceServerName}/gateway:read`,
      exportName: `${cdk.Stack.of(this).stackName}-OAuthScope`,
    });

    new cdk.CfnOutput(this, 'LogsBucketName', {
      description: 'S3 bucket for collected logs',
      value: this.logsBucket.bucketName,
      exportName: `${cdk.Stack.of(this).stackName}-LogsBucketName`,
    });

    new cdk.CfnOutput(this, 'SSMAutomationRoleArn', {
      description: 'SSM Automation Role ARN',
      value: this.ssmAutomationRole.roleArn,
      exportName: `${cdk.Stack.of(this).stackName}-SSMAutomationRoleArn`,
    });

    if (this.encryptionKey) {
      new cdk.CfnOutput(this, 'EncryptionKeyArn', {
        description: 'KMS Encryption Key ARN',
        value: this.encryptionKey.keyArn,
        exportName: `${cdk.Stack.of(this).stackName}-EncryptionKeyArn`,
      });
    }
  }


  /**
   * Returns the enhanced tool schema definitions for the MCP Gateway
   */
  private getToolSchemaDefinitions(): object[] {
    return [
      // =====================================================================
      // TIER 1: CORE OPERATIONS
      // =====================================================================
      {
        Name: 'collect',
        Description: 'Start EKS log collection from a worker node. Returns immediately with executionId for async polling. Supports idempotency tokens to prevent duplicate executions. Supports cross-region: auto-detects instance region or accepts explicit region parameter.',
        InputSchema: {
          Type: 'object',
          Properties: {
            instanceId: {
              Type: 'string',
              Description: 'The EC2 instance ID of the EKS worker node (e.g., i-0123456789abcdef0)',
            },
            idempotencyToken: {
              Type: 'string',
              Description: 'Optional token to prevent duplicate executions. If provided and a matching execution exists, returns the existing executionId.',
            },
            region: {
              Type: 'string',
              Description: 'AWS region where the instance runs (e.g., us-west-2). Optional: auto-detected from instance if omitted.',
            },
          },
          Required: ['instanceId'],
        },
      },
      {
        Name: 'status',
        Description: 'Get detailed status of a log collection execution including progress percentage, step details, and failure reasons. Automatically resolves the region where the execution was started.',
        InputSchema: {
          Type: 'object',
          Properties: {
            executionId: {
              Type: 'string',
              Description: 'The SSM Automation execution ID returned from collect',
            },
            includeStepDetails: {
              Type: 'boolean',
              Description: 'Include individual step status (default: true)',
            },
            region: {
              Type: 'string',
              Description: 'AWS region of the execution. Optional: auto-resolved from stored execution metadata if omitted.',
            },
          },
          Required: ['executionId'],
        },
      },
      {
        Name: 'validate',
        Description: 'Verify all expected files were extracted from the log bundle. Returns manifest with file counts, sizes, and missing patterns.',
        InputSchema: {
          Type: 'object',
          Properties: {
            executionId: {
              Type: 'string',
              Description: 'SSM execution ID to validate',
            },
            instanceId: {
              Type: 'string',
              Description: 'Alternative: Instance ID to locate bundle',
            },
          },
        },
      },
      {
        Name: 'errors',
        Description: 'Get pre-indexed error findings (fast path). Returns categorized errors by severity without scanning raw files.',
        InputSchema: {
          Type: 'object',
          Properties: {
            instanceId: {
              Type: 'string',
              Description: 'The EC2 instance ID to get error summary for',
            },
            severity: {
              Type: 'string',
              Description: 'Filter by severity: critical, warning, info, or all (default: all)',
            },
          },
          Required: ['instanceId'],
        },
      },
      {
        Name: 'read',
        Description: 'Read a chunk of a log file using byte-range streaming. NO TRUNCATION. Supports both byte-range and line-based reading for multi-GB files.',
        InputSchema: {
          Type: 'object',
          Properties: {
            logKey: {
              Type: 'string',
              Description: 'The S3 key of the log file (from validate_bundle_completeness manifest)',
            },
            startByte: {
              Type: 'integer',
              Description: 'Starting byte offset (default: 0)',
            },
            endByte: {
              Type: 'integer',
              Description: 'Ending byte offset (default: startByte + 1MB)',
            },
            startLine: {
              Type: 'integer',
              Description: 'Alternative: Starting line number (1-based)',
            },
            lineCount: {
              Type: 'integer',
              Description: 'Number of lines to return when using startLine (default: 1000)',
            },
          },
          Required: ['logKey'],
        },
      },

      // =====================================================================
      // TIER 2: ADVANCED ANALYSIS
      // =====================================================================
      {
        Name: 'search',
        Description: 'Full-text regex search across all logs without truncation. Use for detailed investigation after reviewing error summary.',
        InputSchema: {
          Type: 'object',
          Properties: {
            instanceId: {
              Type: 'string',
              Description: 'The EC2 instance ID to search logs for',
            },
            query: {
              Type: 'string',
              Description: 'Regex pattern to search for (e.g., "OOMKilled|MemoryPressure")',
            },
            logTypes: {
              Type: 'string',
              Description: 'Comma-separated log types to search. Available types: kubelet, containerd, docker, dmesg, kernel, messages, system, security, networking, storage, ipamd, pods, aws-node, coredns, nodeadm, sandbox-image, eks-agents, config, modinfo, sysctls, gpu, multus, soci-snapshotter, throttling (default: all)',
            },
            maxResults: {
              Type: 'integer',
              Description: 'Maximum results per file (default: 100, max: 500)',
            },
          },
          Required: ['instanceId', 'query'],
        },
      },
      {
        Name: 'correlate',
        Description: 'Cross-file timeline correlation for incident analysis. Groups events by component and identifies patterns.',
        InputSchema: {
          Type: 'object',
          Properties: {
            instanceId: {
              Type: 'string',
              Description: 'The EC2 instance ID to correlate events for',
            },
            timeWindow: {
              Type: 'integer',
              Description: 'Seconds around pivot event (default: 60)',
            },
            pivotEvent: {
              Type: 'string',
              Description: 'Event to correlate around (optional)',
            },
            components: {
              Type: 'array',
              Description: 'Components to include (optional)',
            },
          },
          Required: ['instanceId'],
        },
      },
      {
        Name: 'artifact',
        Description: 'Get secure presigned URL for large artifacts. Use for files too large to return directly.',
        InputSchema: {
          Type: 'object',
          Properties: {
            logKey: {
              Type: 'string',
              Description: 'The S3 key of the artifact',
            },
            expirationMinutes: {
              Type: 'integer',
              Description: 'URL expiration in minutes (default: 15, max: 60)',
            },
          },
          Required: ['logKey'],
        },
      },
      {
        Name: 'summarize',
        Description: 'Generate AI-ready structured incident summary with critical findings, affected components, and recommendations.',
        InputSchema: {
          Type: 'object',
          Properties: {
            instanceId: {
              Type: 'string',
              Description: 'The EC2 instance ID to summarize',
            },
            includeRecommendations: {
              Type: 'boolean',
              Description: 'Include remediation suggestions (default: true)',
            },
          },
          Required: ['instanceId'],
        },
      },
      {
        Name: 'history',
        Description: 'List historical log collections for audit and comparison. Supports cross-region listing.',
        InputSchema: {
          Type: 'object',
          Properties: {
            instanceId: {
              Type: 'string',
              Description: 'Filter by instance ID (optional)',
            },
            maxResults: {
              Type: 'integer',
              Description: 'Maximum results (default: 20, max: 50)',
            },
            status: {
              Type: 'string',
              Description: 'Filter by status: Success, Failed, InProgress (optional)',
            },
            region: {
              Type: 'string',
              Description: 'AWS region to list executions from (default: Lambda region). Specify to list executions from a different region.',
            },
          },
        },
      },
    ];
  }

  /**
   * Returns the Unzip Lambda function code with findings indexer trigger
   */
  private getUnzipLambdaCode(): string {
    return `
import json
import boto3
import zipfile
import tarfile
import io
import os

s3_client = boto3.client('s3')
lambda_client = boto3.client('lambda')

FINDINGS_INDEXER_FUNCTION = os.environ.get('FINDINGS_INDEXER_FUNCTION', '')

def get_content_type(file_name):
    if file_name.endswith('.log') or file_name.endswith('.txt'):
        return 'text/plain'
    elif file_name.endswith('.json'):
        return 'application/json'
    elif file_name.endswith('.yaml') or file_name.endswith('.yml'):
        return 'text/yaml'
    return 'application/octet-stream'

def sanitize_archive_path(file_name):
    """Sanitize archive member path to prevent zip-slip path traversal."""
    # Normalize and reject any path with .. components
    normalized = os.path.normpath(file_name)
    if normalized.startswith('..') or '/../' in normalized or normalized.startswith('/'):
        print(f"SECURITY: Skipping suspicious archive path: {file_name}")
        return None
    # Strip leading ./ if present
    return normalized.lstrip('./')

def extract_zip(bucket, key, content):
    base_path = key[:-4]
    extract_prefix = f"{base_path}/extracted/"
    extracted_files = []
    with zipfile.ZipFile(io.BytesIO(content), 'r') as zip_ref:
        for file_info in zip_ref.infolist():
            if file_info.is_dir():
                continue
            file_name = sanitize_archive_path(file_info.filename)
            if file_name is None:
                continue
            file_content = zip_ref.read(file_info.filename)
            extract_key = f"{extract_prefix}{file_name}"
            s3_client.put_object(
                Bucket=bucket, 
                Key=extract_key, 
                Body=file_content, 
                ContentType=get_content_type(file_name)
            )
            extracted_files.append(extract_key)
            print(f"Extracted: {extract_key}")
    return extracted_files, extract_prefix

def extract_targz(bucket, key, content):
    if key.endswith('.tar.gz'):
        base_path = key[:-7]
    else:
        base_path = key[:-4]
    extract_prefix = f"{base_path}/extracted/"
    extracted_files = []
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as tar_ref:
        for member in tar_ref.getmembers():
            if not member.isfile():
                continue
            file_name = sanitize_archive_path(member.name)
            if file_name is None:
                continue
            file_obj = tar_ref.extractfile(member)
            if file_obj is None:
                continue
            file_content = file_obj.read()
            extract_key = f"{extract_prefix}{file_name}"
            s3_client.put_object(
                Bucket=bucket, 
                Key=extract_key, 
                Body=file_content, 
                ContentType=get_content_type(file_name)
            )
            extracted_files.append(extract_key)
            print(f"Extracted: {extract_key}")
    return extracted_files, extract_prefix

def trigger_findings_indexer(bucket, prefix, file_count):
    """Trigger the findings indexer Lambda after extraction."""
    if not FINDINGS_INDEXER_FUNCTION:
        print("No findings indexer function configured, skipping")
        return
    
    try:
        lambda_client.invoke(
            FunctionName=FINDINGS_INDEXER_FUNCTION,
            InvocationType='Event',  # Async invocation
            Payload=json.dumps({
                'bucket': bucket,
                'prefix': prefix,
                'fileCount': file_count
            })
        )
        print(f"Triggered findings indexer for prefix: {prefix}")
    except Exception as e:
        print(f"Failed to trigger findings indexer: {str(e)}")

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    for record in event.get('Records', []):
        bucket = record['s3']['bucket']['name']
        key = record['s3']['object']['key']
        
        if '/extracted/' in key:
            print(f"Skipping already extracted file: {key}")
            continue
        
        is_zip = key.lower().endswith('.zip')
        is_targz = key.lower().endswith('.tar.gz') or key.lower().endswith('.tgz')
        
        if not is_zip and not is_targz:
            print(f"Skipping unsupported file type: {key}")
            continue
        
        print(f"Processing archive: s3://{bucket}/{key}")
        
        try:
            response = s3_client.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read()
            
            if is_zip:
                extracted_files, prefix = extract_zip(bucket, key, content)
            else:
                extracted_files, prefix = extract_targz(bucket, key, content)
            
            print(f"Successfully extracted {len(extracted_files)} files from {key}")
            
            # Trigger findings indexer
            trigger_findings_indexer(bucket, prefix, len(extracted_files))
            
        except (zipfile.BadZipFile, tarfile.TarError) as e:
            print(f"Error: {key} is not a valid archive: {str(e)}")
        except Exception as e:
            print(f"Error processing {key}: {str(e)}")
            raise e
    
    return {
        'statusCode': 200, 
        'body': json.dumps({'message': 'Archive extraction complete'})
    }
`;
  }

  /**
   * Returns the Findings Indexer Lambda function code
   */
  private getFindingsIndexerCode(): string {
    return `
import json
import boto3
import os
import re
from datetime import datetime

s3_client = boto3.client('s3')
LOGS_BUCKET = os.environ['LOGS_BUCKET_NAME']

# Files worth scanning (log files with actual runtime output).
# Skip config dumps, static system info, metrics, and package lists
# which produce massive false positives.
SCANNABLE_FILE_PATTERNS = [
    r'kubelet[/.]',
    r'containerd[/-]log',
    r'docker[/.]',
    r'dmesg',
    r'messages$',
    r'secure$',
    r'cloud-init.*\\.log',
    r'ipamd\\.log',
    r'aws-routed-eni/.*\\.log',
    r'kube-proxy.*\\.log',
    r'coredns.*\\.log',
    r'var_log/.*\\.log',
    r'nodeadm',
    r'sandbox-image',
]
SCANNABLE_REGEXES = [re.compile(p, re.IGNORECASE) for p in SCANNABLE_FILE_PATTERNS]

# Files to always skip - these contain config/static data, not errors
SKIP_FILE_PATTERNS = [
    r'sysctl',
    r'ethtool',
    r'ifconfig',
    r'conntrack\\.txt',
    r'pkglist',
    r'ps\\.txt',
    r'ps-threads',
    r'top\\.txt',
    r'allprocstat',
    r'mounts\\.txt',
    r'containerd-config\\.txt',
    r'containerd-plugins\\.txt',
    r'containerd-containers\\.txt',
    r'containerd-images\\.txt',
    r'containerd-namespaces\\.txt',
    r'containerd-tasks\\.txt',
    r'containerd-version\\.txt',
    r'metrics\\.json',
    r'modinfo',
    r'iptables',
    r'\\.json$',
    r'\\.yaml$',
    r'\\.yml$',
    r'\\.conf$',
    r'\\.toml$',
    r'\\.service$',
]
SKIP_REGEXES = [re.compile(p, re.IGNORECASE) for p in SKIP_FILE_PATTERNS]

# Precise error patterns - these require actual error context, not config values.
# Each pattern is a tuple of (regex, description) for better reporting.
ERROR_PATTERNS = {
    'critical': [
        (r'kernel panic', 'kernel panic'),
        (r'BUG:.*', 'kernel bug'),
        (r'watchdog: BUG: soft lockup', 'soft lockup'),
        (r'invoked oom-killer', 'OOM killer invoked'),
        (r'Out of memory: Kill', 'OOM kill'),
        (r'Killed process \\d+.*total-vm', 'OOM kill with details'),
        (r'Memory cgroup out of memory.*process', 'cgroup OOM'),
        (r'segfault at', 'segfault'),
        (r'PLEG is not healthy', 'PLEG unhealthy'),
        (r'failed to run Kubelet:', 'kubelet launch failure'),
        (r'Unit kubelet.*entered failed state', 'kubelet failed'),
        (r'Node became not ready', 'node NotReady'),
        (r'OCI runtime create failed:', 'container runtime failure'),
        (r'no networks found in /etc/cni/net\\.d', 'CNI missing'),
        (r'Container runtime network not ready', 'runtime network not ready'),
        (r'InsufficientFreeAddressesInSubnet', 'IP exhaustion'),
        (r'Unable to register node', 'node registration failed'),
        (r'failed to register node', 'node registration failed'),
        (r'Instances failed to join', 'cluster join failure'),
        (r'certificate has expired', 'expired certificate'),
        (r'x509: certificate', 'certificate error'),
        (r'Unauthorized', 'auth failure'),
        (r'nodeadm.*(?:failed|error)', 'nodeadm failure'),
        (r'Failed to pull image', 'image pull failure'),
        (r'CrashLoopBackOff', 'crash loop'),
        (r'fork/exec.*resource temporarily unavailable', 'PID exhaustion'),
    ],
    'warning': [
        (r'(?:Readiness|Liveness|Startup) probe.*failed', 'probe failure'),
        (r'Back-off restarting failed container', 'container restart backoff'),
        (r'ImagePullBackOff', 'image pull backoff'),
        (r'ErrImagePull', 'image pull error'),
        (r'FailedScheduling', 'scheduling failure'),
        (r'FailedMount', 'mount failure'),
        (r'FailedAttachVolume', 'volume attach failure'),
        (r'Insufficient cpu', 'insufficient CPU'),
        (r'Insufficient memory', 'insufficient memory'),
        (r'OOMKilled', 'container OOMKilled'),
        (r'Evicted', 'pod evicted'),
        (r'NetworkNotReady', 'network not ready'),
        (r'dial tcp.*connection refused', 'connection refused'),
        (r'dial tcp.*i/o timeout', 'connection timeout'),
        (r'TLS handshake timeout', 'TLS timeout'),
        (r'no such host', 'DNS resolution failure'),
        (r'NXDOMAIN', 'DNS NXDOMAIN'),
        (r'SERVFAIL', 'DNS SERVFAIL'),
        (r'is not authorized to perform', 'IAM permission denied'),
        (r'systemd.*Failed to start', 'service start failure'),
        (r'nfs: server.*not responding', 'NFS not responding'),
    ],
    'info': [
        (r'(?i)level=(?:warn|warning)', 'log-level warning'),
        (r'DEPRECATION:', 'deprecation notice'),
        (r'context deadline exceeded', 'context deadline'),
        (r'net_ratelimit:.*callbacks suppressed', 'kernel rate limiting'),
    ],
}

# Pre-compile all patterns
COMPILED_PATTERNS = {}
for _sev, _pats in ERROR_PATTERNS.items():
    COMPILED_PATTERNS[_sev] = []
    for _pat, _desc in _pats:
        try:
            COMPILED_PATTERNS[_sev].append((re.compile(_pat), _desc))
        except re.error:
            pass

def is_scannable(filename):
    """Check if a file is worth scanning (actual log output, not config/static data)."""
    # First check skip list
    for skip_re in SKIP_REGEXES:
        if skip_re.search(filename):
            return False
    # Then check if it matches known log patterns
    for scan_re in SCANNABLE_REGEXES:
        if scan_re.search(filename):
            return True
    # Default: scan if it looks like a log file
    if filename.endswith('.log') or filename.endswith('.txt'):
        # Only scan files in directories that typically contain logs
        log_dirs = ['kubelet', 'var_log', 'kernel', 'system/messages']
        return any(d in filename for d in log_dirs)
    return False

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    bucket = event.get('bucket', LOGS_BUCKET)
    prefix = event.get('prefix', '')
    
    if not prefix:
        print("No prefix provided, skipping")
        return {'statusCode': 400, 'body': 'No prefix provided'}
    
    try:
        # List all extracted files
        files_to_scan = []
        files_skipped = 0
        paginator = s3_client.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for obj in page.get('Contents', []):
                key = obj['Key']
                # Skip non-text files
                if any(key.endswith(ext) for ext in ['.tar.gz', '.zip', '.gz', '.bin', '.so']):
                    continue
                # Skip very large files
                if obj['Size'] > 5242880:  # 5MB
                    continue
                # Only scan actual log files, not config/static data
                filename = key.split('/extracted/')[-1] if '/extracted/' in key else key
                if not is_scannable(filename):
                    files_skipped += 1
                    continue
                files_to_scan.append({
                    'key': key,
                    'size': obj['Size']
                })
        
        print(f"Scanning {len(files_to_scan)} log files ({files_skipped} non-log files skipped)")
        
        # Scan files
        all_findings = []
        for file_info in files_to_scan[:200]:  # Limit to prevent timeout
            findings = scan_file(bucket, file_info['key'])
            all_findings.extend(findings)
        
        # Deduplicate
        deduplicated = deduplicate_findings(all_findings)
        
        # Calculate summary
        summary = {
            'critical': len([f for f in deduplicated if f.get('severity') == 'critical']),
            'warning': len([f for f in deduplicated if f.get('severity') == 'warning']),
            'info': len([f for f in deduplicated if f.get('severity') == 'info']),
        }
        
        # Write index file
        index_data = {
            'indexedAt': datetime.utcnow().isoformat(),
            'prefix': prefix,
            'filesScanned': len(files_to_scan),
            'filesSkipped': files_skipped,
            'findings': deduplicated[:500],  # Limit stored findings
            'summary': summary,
        }
        
        index_key = f"{prefix}findings_index.json"
        s3_client.put_object(
            Bucket=bucket,
            Key=index_key,
            Body=json.dumps(index_data, default=str),
            ContentType='application/json'
        )
        
        print(f"Wrote findings index to {index_key}")
        print(f"Summary: {summary}")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Findings indexed successfully',
                'indexKey': index_key,
                'summary': summary
            })
        }
        
    except Exception as e:
        print(f"Error indexing findings: {str(e)}")
        return {'statusCode': 500, 'body': str(e)}

def scan_file(bucket, key):
    findings = []
    
    try:
        response = s3_client.get_object(
            Bucket=bucket,
            Key=key,
            Range='bytes=0-1048575'  # First 1MB
        )
        
        content = response['Body'].read()
        try:
            content_str = content.decode('utf-8')
        except:
            content_str = content.decode('latin-1', errors='ignore')
        
        filename = key.split('/extracted/')[-1] if '/extracted/' in key else key
        lines = content_str.split('\\n')[:5000]
        
        for severity, compiled_list in COMPILED_PATTERNS.items():
            for regex, description in compiled_list:
                match_count = 0
                for i, line in enumerate(lines):
                    if regex.search(line):
                        findings.append({
                            'file': filename,
                            'fullKey': key,
                            'severity': severity,
                            'pattern': description,
                            'line': i + 1,
                            'sample': line.strip()[:300]
                        })
                        match_count += 1
                        if match_count > 50 or len(findings) > 200:
                            break
                if len(findings) > 200:
                    return findings
    except Exception as e:
        print(f"Error scanning {key}: {str(e)}")
    
    return findings

def deduplicate_findings(findings):
    seen = {}
    
    for finding in findings:
        dedup_key = f"{finding.get('file')}:{finding.get('pattern')}"
        
        if dedup_key not in seen:
            seen[dedup_key] = {
                **finding,
                'count': 1,
                'lines': [finding.get('line')]
            }
        else:
            seen[dedup_key]['count'] += 1
            if len(seen[dedup_key]['lines']) < 10:
                seen[dedup_key]['lines'].append(finding.get('line'))
    
    severity_order = {'critical': 0, 'warning': 1, 'info': 2}
    result = sorted(
        seen.values(),
        key=lambda x: (severity_order.get(x.get('severity'), 3), -x.get('count', 0))
    )
    
    return result
`;
  }

  /**
   * Returns the Client Secret Retriever Lambda function code
   */
  private getClientSecretRetrieverCode(): string {
    return `
import boto3
import json

def handler(event, context):
    try:
        if isinstance(event, str):
            event = json.loads(event)
        if 'Payload' in event:
            event = json.loads(event['Payload'])
        if event.get('RequestType') == 'Delete':
            return {'statusCode': 200, 'body': json.dumps({'ClientSecret': ''})}
        
        props = event.get('ResourceProperties', event)
        user_pool_id = props['UserPoolId']
        client_id = props['ClientId']
        
        cognito = boto3.client('cognito-idp')
        response = cognito.describe_user_pool_client(
            UserPoolId=user_pool_id, 
            ClientId=client_id
        )
        client_secret = response['UserPoolClient'].get('ClientSecret', '')
        
        return {
            'statusCode': 200, 
            'body': json.dumps({'ClientSecret': client_secret})
        }
    except Exception as e:
        print(f"Error: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps({'Error': str(e)})}
`;
  }
}
