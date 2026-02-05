#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { SsmAutomationGatewayStack } from '../src/ssm-automation-gateway-stack';

const app = new cdk.App();

new SsmAutomationGatewayStack(app, 'SsmAutomationGatewayStack', {
  description: 'SSM Automation Gateway - MCP Server for DevOps Agent to run SSM Automation Documents',
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  },
});
