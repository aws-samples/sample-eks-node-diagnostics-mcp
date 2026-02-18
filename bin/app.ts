#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { EksNodeLogMcpStack } from '../src/ssm-automation-gateway-stack-v2';

const app = new cdk.App();

new EksNodeLogMcpStack(app, 'EksNodeLogMcpStack', {
  description: 'EKS Node Log MCP Server - Collect and analyze diagnostic logs from EKS worker nodes',
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
  gatewayName: 'EksNodeLogMcpGW',
  enableEncryption: true,
  logRetentionDays: 1,
  ssmDefaultHostRoleArn: process.env.SSM_DEFAULT_HOST_ROLE_ARN,
  eksNodeRoleArns: process.env.EKS_NODE_ROLE_ARNS
    ? process.env.EKS_NODE_ROLE_ARNS.split(',').filter(Boolean)
    : undefined,
});
