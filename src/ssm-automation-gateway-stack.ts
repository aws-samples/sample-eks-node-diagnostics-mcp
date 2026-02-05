import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { SsmAutomationGatewayConstruct } from './ssm-automation-gateway-construct';

export interface SsmAutomationGatewayStackProps extends cdk.StackProps {
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

export class SsmAutomationGatewayStack extends cdk.Stack {
  public readonly gateway: SsmAutomationGatewayConstruct;

  constructor(scope: Construct, id: string, props: SsmAutomationGatewayStackProps = {}) {
    super(scope, id, props);

    this.gateway = new SsmAutomationGatewayConstruct(this, 'SsmAutomationGateway', {
      gatewayName: props.gatewayName,
      cognitoUserPoolName: props.cognitoUserPoolName,
      resourceServerName: props.resourceServerName,
      logRetentionDays: props.logRetentionDays,
    });
  }
}
