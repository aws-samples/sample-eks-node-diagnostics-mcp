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
});
