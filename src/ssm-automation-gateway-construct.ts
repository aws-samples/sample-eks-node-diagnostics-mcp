import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as s3n from 'aws-cdk-lib/aws-s3-notifications';
import * as cr from 'aws-cdk-lib/custom-resources';
import { Construct } from 'constructs';

export interface SsmAutomationGatewayProps {
  /**
   * Name for the AgentCore Gateway
   * @default 'SSMAutomationGW'
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
   * @default 30
   */
  readonly logRetentionDays?: number;
}

export class SsmAutomationGatewayConstruct extends Construct {
  public readonly logsBucket: s3.Bucket;
  public readonly ssmAutomationFunction: lambda.Function;
  public readonly unzipFunction: lambda.Function;
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;
  public readonly ssmAutomationRole: iam.Role;
  public readonly gatewayExecutionRole: iam.Role;

  constructor(scope: Construct, id: string, props: SsmAutomationGatewayProps = {}) {
    super(scope, id);

    const gatewayName = props.gatewayName ?? 'EksNodeLogMcpGW';
    const cognitoUserPoolName = props.cognitoUserPoolName ?? 'ssm-automation-gateway-pool';
    const resourceServerName = props.resourceServerName ?? 'ssm-automation-gateway-id';
    const logRetentionDays = props.logRetentionDays ?? 30;

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
    // S3 BUCKET - Log Storage
    // ========================================================================

    this.logsBucket = new s3.Bucket(this, 'LogsBucket', {
      bucketName: `${cdk.Stack.of(this).stackName.toLowerCase()}-logs-${cdk.Stack.of(this).account}`,
      versioned: true,
      blockPublicAccess: new s3.BlockPublicAccess({
        blockPublicAcls: true,
        blockPublicPolicy: false,
        ignorePublicAcls: true,
        restrictPublicBuckets: false,
      }),
      lifecycleRules: [{
        id: 'DeleteOldLogs',
        enabled: true,
        expiration: cdk.Duration.days(logRetentionDays),
      }],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });

    // Grant SSM Automation role access to the bucket
    this.logsBucket.grantReadWrite(this.ssmAutomationRole);

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

    this.unzipFunction = new lambda.Function(this, 'UnzipFunction', {
      functionName: `${cdk.Stack.of(this).stackName}-unzip-function`,
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'index.lambda_handler',
      role: unzipLambdaRole,
      timeout: cdk.Duration.seconds(300),
      memorySize: 512,
      code: lambda.Code.fromInline(this.getUnzipLambdaCode()),
    });

    // Add S3 notification to trigger unzip on .zip and .tar.gz uploads
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
    // SSM AUTOMATION LAMBDA FUNCTION
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

    // SSM Document access
    lambdaExecutionRole.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['ssm:GetDocument', 'ssm:DescribeDocument'],
      resources: [
        `arn:aws:ssm:${cdk.Stack.of(this).region}::document/AWSSupport-CollectEKSInstanceLogs`,
        `arn:aws:ssm:${cdk.Stack.of(this).region}:${cdk.Stack.of(this).account}:document/*`,
      ],
    }));

    // S3 access
    this.logsBucket.grantReadWrite(lambdaExecutionRole);

    // PassRole for SSM
    lambdaExecutionRole.addToPolicy(new iam.PolicyStatement({
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
      handler: 'index.lambda_handler',
      role: lambdaExecutionRole,
      timeout: cdk.Duration.seconds(60),
      environment: {
        LOGS_BUCKET_NAME: this.logsBucket.bucketName,
        SSM_AUTOMATION_ROLE_ARN: this.ssmAutomationRole.roleArn,
      },
      code: lambda.Code.fromInline(this.getSsmAutomationLambdaCode()),
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
    const lambdaPermission = this.ssmAutomationFunction.addPermission('AllowAgentCoreInvoke', {
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
    // AGENTCORE GATEWAY - Using CfnResource (L1 construct)
    // ========================================================================

    const gateway = new cdk.CfnResource(this, 'AgentCoreGateway', {
      type: 'AWS::BedrockAgentCore::Gateway',
      properties: {
        Name: gatewayName,
        Description: 'SSM Automation Gateway - Run EKS log collection and other SSM automations',
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
        Name: 'SSMAutomationTarget',
        Description: 'SSM Automation Lambda Target',
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
    // Ensure Lambda permission is created before the gateway target
    gatewayTarget.node.addDependency(this.ssmAutomationFunction);
    gatewayTarget.node.addDependency(this.gatewayExecutionRole);

    // ========================================================================
    // OUTPUTS
    // ========================================================================

    new cdk.CfnOutput(this, 'GatewayId', {
      description: 'ID of the created AgentCore Gateway',
      value: gateway.ref,
      exportName: `${cdk.Stack.of(this).stackName}-GatewayId`,
    });

    new cdk.CfnOutput(this, 'GatewayUrl', {
      description: 'URL of the created AgentCore Gateway (use this as MCP Server URL)',
      value: gateway.getAtt('GatewayUrl').toString(),
      exportName: `${cdk.Stack.of(this).stackName}-GatewayUrl`,
    });

    new cdk.CfnOutput(this, 'CognitoUserPoolId', {
      description: 'Cognito User Pool ID',
      value: this.userPool.userPoolId,
      exportName: `${cdk.Stack.of(this).stackName}-CognitoUserPoolId`,
    });

    new cdk.CfnOutput(this, 'CognitoClientId', {
      description: 'Cognito Client ID (use this for OAuth Client ID)',
      value: this.userPoolClient.userPoolClientId,
      exportName: `${cdk.Stack.of(this).stackName}-CognitoClientId`,
    });

    new cdk.CfnOutput(this, 'OAuthExchangeUrl', {
      description: 'OAuth Token URL (use this for Token URL in OAuth settings)',
      value: `https://${cdk.Stack.of(this).stackName.toLowerCase()}-${cdk.Stack.of(this).account}.auth.${cdk.Stack.of(this).region}.amazoncognito.com/oauth2/token`,
      exportName: `${cdk.Stack.of(this).stackName}-OAuthExchangeUrl`,
    });

    new cdk.CfnOutput(this, 'OAuthScope', {
      description: 'OAuth Scope (use this for Scope in OAuth settings - use only ONE scope)',
      value: `${resourceServerName}/gateway:read`,
      exportName: `${cdk.Stack.of(this).stackName}-OAuthScope`,
    });

    new cdk.CfnOutput(this, 'LogsBucketName', {
      description: 'Name of the S3 bucket for collected logs (auto-unzips .zip files)',
      value: this.logsBucket.bucketName,
      exportName: `${cdk.Stack.of(this).stackName}-LogsBucketName`,
    });

    new cdk.CfnOutput(this, 'SSMAutomationRoleArn', {
      description: 'ARN of the SSM Automation Role',
      value: this.ssmAutomationRole.roleArn,
      exportName: `${cdk.Stack.of(this).stackName}-SSMAutomationRoleArn`,
    });
  }

  /**
   * Returns the tool schema definitions for the MCP Gateway
   */
  private getToolSchemaDefinitions(): object[] {
    return [
      {
        Name: 'run_eks_log_collection',
        Description: 'Run AWSSupport-CollectEKSInstanceLogs to collect logs from an EKS worker node and store in S3',
        InputSchema: {
          Type: 'object',
          Properties: {
            instanceId: {
              Type: 'string',
              Description: 'The EC2 instance ID of the EKS worker node (e.g., i-0123456789abcdef0)',
            },
          },
          Required: ['instanceId'],
        },
      },
      {
        Name: 'get_automation_status',
        Description: 'Get the status of an SSM Automation execution',
        InputSchema: {
          Type: 'object',
          Properties: {
            executionId: {
              Type: 'string',
              Description: 'The SSM Automation execution ID',
            },
          },
          Required: ['executionId'],
        },
      },
      {
        Name: 'list_automations',
        Description: 'List recent SSM Automation executions',
        InputSchema: {
          Type: 'object',
          Properties: {
            maxResults: {
              Type: 'integer',
              Description: 'Maximum number of results to return (default: 10, max: 50)',
            },
            documentName: {
              Type: 'string',
              Description: 'Filter by document name (default: AWSSupport-CollectEKSInstanceLogs)',
            },
          },
        },
      },
      {
        Name: 'list_collected_logs',
        Description: 'List collected EKS logs stored in S3 (includes extracted files from zip archives)',
        InputSchema: {
          Type: 'object',
          Properties: {
            instanceId: {
              Type: 'string',
              Description: 'Optional: Filter logs by instance ID',
            },
          },
        },
      },
      {
        Name: 'get_log_content',
        Description: 'Get the content of a specific log file from S3',
        InputSchema: {
          Type: 'object',
          Properties: {
            logKey: {
              Type: 'string',
              Description: 'The S3 key of the log file to retrieve (from list_collected_logs)',
            },
            maxBytes: {
              Type: 'integer',
              Description: 'Maximum bytes to retrieve (default: 100000, i.e., 100KB)',
            },
          },
          Required: ['logKey'],
        },
      },
      {
        Name: 'search_log_errors',
        Description: 'Search collected logs for error messages, warnings, and failures. Scans large log files (kubelet, containerd, dmesg, system logs) and returns only lines containing errors.',
        InputSchema: {
          Type: 'object',
          Properties: {
            instanceId: {
              Type: 'string',
              Description: 'The EC2 instance ID to search logs for (e.g., i-0123456789abcdef0)',
            },
            pattern: {
              Type: 'string',
              Description: 'Custom regex pattern to search for (default: error|fail|fatal|panic|crash|oom|killed|denied|refused|timeout|exception)',
            },
            logTypes: {
              Type: 'string',
              Description: 'Comma-separated log types to search: kubelet,containerd,dmesg,kernel,messages,system,networking,storage,ipamd,docker,pods,aws-node,coredns,config,security (default: all)',
            },
            maxResults: {
              Type: 'integer',
              Description: 'Maximum number of error lines to return per log file (default: 50)',
            },
          },
          Required: ['instanceId'],
        },
      },
    ];
  }

  /**
   * Returns the Unzip Lambda function code
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

def get_content_type(file_name):
    if file_name.endswith('.log') or file_name.endswith('.txt'):
        return 'text/plain'
    elif file_name.endswith('.json'):
        return 'application/json'
    elif file_name.endswith('.yaml') or file_name.endswith('.yml'):
        return 'text/yaml'
    return 'application/octet-stream'

def extract_zip(bucket, key, content):
    base_path = key[:-4]
    extract_prefix = f"{base_path}/extracted/"
    extracted_files = []
    with zipfile.ZipFile(io.BytesIO(content), 'r') as zip_ref:
        for file_info in zip_ref.infolist():
            if file_info.is_dir():
                continue
            file_name = file_info.filename
            file_content = zip_ref.read(file_name)
            extract_key = f"{extract_prefix}{file_name}"
            s3_client.put_object(Bucket=bucket, Key=extract_key, Body=file_content, ContentType=get_content_type(file_name))
            extracted_files.append(extract_key)
            print(f"Extracted: {extract_key}")
    return extracted_files

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
            file_obj = tar_ref.extractfile(member)
            if file_obj is None:
                continue
            file_content = file_obj.read()
            extract_key = f"{extract_prefix}{member.name}"
            s3_client.put_object(Bucket=bucket, Key=extract_key, Body=file_content, ContentType=get_content_type(member.name))
            extracted_files.append(extract_key)
            print(f"Extracted: {extract_key}")
    return extracted_files

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
                extracted_files = extract_zip(bucket, key, content)
            else:
                extracted_files = extract_targz(bucket, key, content)
            print(f"Successfully extracted {len(extracted_files)} files from {key}")
        except (zipfile.BadZipFile, tarfile.TarError) as e:
            print(f"Error: {key} is not a valid archive: {str(e)}")
        except Exception as e:
            print(f"Error processing {key}: {str(e)}")
            raise e
    return {'statusCode': 200, 'body': json.dumps({'message': 'Archive extraction complete'})}
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
        response = cognito.describe_user_pool_client(UserPoolId=user_pool_id, ClientId=client_id)
        client_secret = response['UserPoolClient'].get('ClientSecret', '')
        return {'statusCode': 200, 'body': json.dumps({'ClientSecret': client_secret})}
    except Exception as e:
        print(f"Error: {str(e)}")
        return {'statusCode': 500, 'body': json.dumps({'Error': str(e)})}
`;
  }

  /**
   * Returns the SSM Automation Lambda function code
   */
  private getSsmAutomationLambdaCode(): string {
    return `import json
import boto3
import os

ssm_client = boto3.client('ssm')
s3_client = boto3.client('s3')
LOGS_BUCKET = os.environ['LOGS_BUCKET_NAME']

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    delimiter = "___"
    original_tool_name = context.client_context.custom['bedrockAgentCoreToolName']
    tool_name = original_tool_name[original_tool_name.index(delimiter) + len(delimiter):]
    print(f"Extracted tool name: {tool_name}")
    if tool_name == 'run_eks_log_collection':
        return run_eks_log_collection(event)
    elif tool_name == 'get_automation_status':
        return get_automation_status(event)
    elif tool_name == 'list_automations':
        return list_automations(event)
    elif tool_name == 'list_collected_logs':
        return list_collected_logs(event)
    elif tool_name == 'get_log_content':
        return get_log_content(event)
    elif tool_name == 'search_log_errors':
        return search_log_errors(event)
    else:
        return {'statusCode': 400, 'body': json.dumps({'error': f'Unknown tool: {tool_name}'})}

def run_eks_log_collection(arguments):
    instance_id = arguments.get('instanceId')
    if not instance_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'instanceId is required'})}
    try:
        params = {'EKSInstanceId': [instance_id], 'LogDestination': [LOGS_BUCKET], 'AutomationAssumeRole': [os.environ.get('SSM_AUTOMATION_ROLE_ARN', '')]}
        response = ssm_client.start_automation_execution(DocumentName='AWSSupport-CollectEKSInstanceLogs', Parameters=params)
        execution_id = response['AutomationExecutionId']
        return {'statusCode': 200, 'body': json.dumps({'success': True, 'message': 'EKS log collection started', 'executionId': execution_id, 'instanceId': instance_id, 's3Bucket': LOGS_BUCKET})}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def get_automation_status(arguments):
    execution_id = arguments.get('executionId')
    if not execution_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'executionId is required'})}
    try:
        response = ssm_client.get_automation_execution(AutomationExecutionId=execution_id)
        execution = response['AutomationExecution']
        result = {'executionId': execution_id, 'status': execution['AutomationExecutionStatus'], 'documentName': execution.get('DocumentName', '')}
        if execution.get('ExecutionStartTime'):
            result['startTime'] = execution['ExecutionStartTime'].isoformat()
        if execution.get('ExecutionEndTime'):
            result['endTime'] = execution['ExecutionEndTime'].isoformat()
        if 'Outputs' in execution:
            result['outputs'] = execution['Outputs']
        if execution['AutomationExecutionStatus'] == 'Failed':
            result['failureMessage'] = execution.get('FailureMessage', 'Unknown failure')
        return {'statusCode': 200, 'body': json.dumps({'success': True, 'automation': result})}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def list_automations(arguments):
    max_results = arguments.get('maxResults', 10)
    document_name = arguments.get('documentName', 'AWSSupport-CollectEKSInstanceLogs')
    try:
        filters = [{'Key': 'DocumentNamePrefix', 'Values': [document_name]}] if document_name else []
        response = ssm_client.describe_automation_executions(Filters=filters, MaxResults=min(max_results, 50))
        executions = []
        for exec in response.get('AutomationExecutionMetadataList', []):
            item = {'executionId': exec['AutomationExecutionId'], 'documentName': exec.get('DocumentName', ''), 'status': exec['AutomationExecutionStatus']}
            if exec.get('ExecutionStartTime'):
                item['startTime'] = exec['ExecutionStartTime'].isoformat()
            executions.append(item)
        return {'statusCode': 200, 'body': json.dumps({'success': True, 'executions': executions, 'count': len(executions)})}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def list_collected_logs(arguments):
    instance_id = arguments.get('instanceId', '')
    try:
        # SSM document uploads files as eks_i-{instanceId}_{uuid}.tar.gz at bucket root
        # Extracted files are in eks_i-{instanceId}_{uuid}/extracted/
        prefix = f'eks_{instance_id}' if instance_id else 'eks_'
        response = s3_client.list_objects_v2(Bucket=LOGS_BUCKET, Prefix=prefix, MaxKeys=100)
        logs = [{'key': obj['Key'], 'size': obj['Size'], 'lastModified': obj['LastModified'].isoformat()} for obj in response.get('Contents', [])]
        return {'statusCode': 200, 'body': json.dumps({'success': True, 'logs': logs, 'count': len(logs), 'bucket': LOGS_BUCKET})}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

def get_log_content(arguments):
    log_key = arguments.get('logKey')
    max_bytes = arguments.get('maxBytes', 100000)
    if not log_key:
        return {'statusCode': 400, 'body': json.dumps({'error': 'logKey is required'})}
    try:
        head = s3_client.head_object(Bucket=LOGS_BUCKET, Key=log_key)
        file_size = head['ContentLength']
        truncated = file_size > max_bytes
        if truncated:
            response = s3_client.get_object(Bucket=LOGS_BUCKET, Key=log_key, Range=f'bytes=0-{max_bytes-1}')
        else:
            response = s3_client.get_object(Bucket=LOGS_BUCKET, Key=log_key)
        content = response['Body'].read()
        try:
            content_str = content.decode('utf-8')
        except:
            content_str = content.decode('latin-1')
        return {'statusCode': 200, 'body': json.dumps({'success': True, 'logKey': log_key, 'content': content_str, 'size': file_size, 'truncated': truncated})}
    except s3_client.exceptions.NoSuchKey:
        return {'statusCode': 404, 'body': json.dumps({'error': f'Log file not found: {log_key}'})}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}

import re

def search_log_errors(arguments):
    instance_id = arguments.get('instanceId')
    if not instance_id:
        return {'statusCode': 400, 'body': json.dumps({'error': 'instanceId is required'})}
    
    # Default error patterns for EKS/Kubernetes troubleshooting
    default_pattern = r'(?i)(error|fail|fatal|panic|crash|oom|killed|denied|refused|timeout|exception|unable|cannot|couldn\\'t|invalid|unauthorized|forbidden|not found|no space|disk pressure|memory pressure|evict|backoff|crashloop|imagepull|networkplugin|notready|unreachable|connection refused|tls handshake|certificate|expired|rejected|dropped|lost|missing|broken|corrupt)'
    custom_pattern = arguments.get('pattern', default_pattern)
    log_types_str = arguments.get('logTypes', '')
    max_results = min(arguments.get('maxResults', 50), 100)
    
    # Map log types to file patterns (based on EKS worker node log locations)
    log_type_patterns = {
        'kubelet': ['kubelet', 'kube-proxy'],
        'containerd': ['containerd'],
        'dmesg': ['dmesg'],
        'kernel': ['kernel', 'dmesg'],
        'messages': ['messages', 'syslog'],
        'system': ['messages', 'syslog', 'secure', 'audit', 'cron', 'cloud-init', 'user-data'],
        'networking': ['networking', 'iptables', 'conntrack', 'iproute', 'ifconfig', 'resolv'],
        'storage': ['storage', 'mount', 'lsblk', 'xfs', 'fstab', 'ebs-csi', 'efs-csi', 'fsx-csi', 's3-csi'],
        'ipamd': ['ipamd', 'aws-routed-eni', 'cni', 'plugin.log', 'egress-plugin', 'network-policy-agent'],
        'docker': ['docker', 'daemon.json'],
        'sandbox': ['sandbox'],
        'pods': ['pods/', 'containers/'],
        'aws-node': ['aws-node', 'cni-metrics-helper'],
        'coredns': ['coredns'],
        'config': ['kubelet-config', 'config.json', 'config.toml', 'kubeconfig', 'bootstrap'],
        'security': ['secure', 'audit'],
    }
    
    # Parse requested log types
    if log_types_str:
        requested_types = [t.strip().lower() for t in log_types_str.split(',')]
        file_patterns = []
        for t in requested_types:
            if t in log_type_patterns:
                file_patterns.extend(log_type_patterns[t])
    else:
        file_patterns = None  # Search all logs
    
    try:
        # List all extracted log files for this instance
        prefix = f'eks_{instance_id}'
        response = s3_client.list_objects_v2(Bucket=LOGS_BUCKET, Prefix=prefix, MaxKeys=500)
        
        results = {'instanceId': instance_id, 'pattern': custom_pattern, 'files_searched': 0, 'total_errors': 0, 'errors_by_file': []}
        
        for obj in response.get('Contents', []):
            key = obj['Key']
            # Only search extracted text files
            if '/extracted/' not in key:
                continue
            if not any(key.endswith(ext) for ext in ['.txt', '.log', '.conf', '.yaml', '.json', '']):
                continue
            # Skip binary/archive files
            if any(key.endswith(ext) for ext in ['.tar.gz', '.zip', '.gz', '.tar']):
                continue
            
            # Filter by log type if specified
            if file_patterns:
                if not any(p in key.lower() for p in file_patterns):
                    continue
            
            results['files_searched'] += 1
            
            try:
                # Read file content (limit to 5MB per file)
                file_response = s3_client.get_object(Bucket=LOGS_BUCKET, Key=key, Range='bytes=0-5242879')
                content = file_response['Body'].read()
                try:
                    content_str = content.decode('utf-8')
                except:
                    content_str = content.decode('latin-1', errors='ignore')
                
                # Search for error patterns
                error_lines = []
                for i, line in enumerate(content_str.split('\\n')):
                    if re.search(custom_pattern, line):
                        error_lines.append({'line_num': i + 1, 'content': line[:500]})  # Truncate long lines
                        if len(error_lines) >= max_results:
                            break
                
                if error_lines:
                    # Extract just the filename from the full path
                    filename = key.split('/extracted/')[-1] if '/extracted/' in key else key
                    results['errors_by_file'].append({
                        'file': filename,
                        'full_key': key,
                        'error_count': len(error_lines),
                        'errors': error_lines
                    })
                    results['total_errors'] += len(error_lines)
            except Exception as e:
                print(f"Error reading {key}: {str(e)}")
                continue
        
        # Sort by error count descending
        results['errors_by_file'].sort(key=lambda x: x['error_count'], reverse=True)
        
        return {'statusCode': 200, 'body': json.dumps({'success': True, **results})}
    except Exception as e:
        return {'statusCode': 500, 'body': json.dumps({'error': str(e)})}
`;
  }
}
