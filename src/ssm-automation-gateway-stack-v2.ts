import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { SsmAutomationGatewayV2Construct, SsmAutomationGatewayV2Props } from './ssm-automation-gateway-construct-v2';

export interface SsmAutomationGatewayV2StackProps extends cdk.StackProps, SsmAutomationGatewayV2Props {}

/**
 * Production-grade EKS Node Log MCP Server Stack
 * 
 * Features:
 * - 10-tool world-class MCP toolset
 * - Async task pattern with idempotency
 * - Byte-range streaming for multi-GB files (NO TRUNCATION)
 * - Manifest validation and completeness verification
 * - Pre-indexed error findings (fast path)
 * - KMS encryption at rest
 * - Comprehensive audit logging
 */
export class EksNodeLogMcpStack extends cdk.Stack {
  public readonly gateway: SsmAutomationGatewayV2Construct;

  constructor(scope: Construct, id: string, props: SsmAutomationGatewayV2StackProps = {}) {
    super(scope, id, props);

    this.gateway = new SsmAutomationGatewayV2Construct(this, 'SsmAutomationGatewayV2', {
      gatewayName: props.gatewayName,
      cognitoUserPoolName: props.cognitoUserPoolName,
      resourceServerName: props.resourceServerName,
      logRetentionDays: props.logRetentionDays,
      enableEncryption: props.enableEncryption,
      enableS3DataEvents: props.enableS3DataEvents,
    });
  }
}
