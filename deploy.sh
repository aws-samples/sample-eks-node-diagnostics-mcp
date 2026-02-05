#!/bin/bash
set -e

# EKS Node Log MCP - Deploy and Configure Script
# This script deploys the CDK stack and outputs all values needed for DevOps Agent configuration

STACK_NAME="${1:-SsmAutomationGatewayStack}"
REGION="${AWS_REGION:-us-east-1}"

echo "=============================================="
echo "EKS Node Log MCP - Deployment Script"
echo "=============================================="
echo "Stack Name: $STACK_NAME"
echo "Region: $REGION"
echo ""

# Check prerequisites
command -v npm >/dev/null 2>&1 || { echo "Error: npm is required but not installed."; exit 1; }
command -v aws >/dev/null 2>&1 || { echo "Error: AWS CLI is required but not installed."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 is required but not installed."; exit 1; }

# Install dependencies
echo "Installing dependencies..."
npm install --silent

# Build TypeScript
echo "Building TypeScript..."
npm run build

# Bootstrap CDK (if needed)
echo "Bootstrapping CDK (if needed)..."
npx cdk bootstrap --quiet 2>/dev/null || true

# Deploy the stack
echo "Deploying CDK stack..."
npx cdk deploy "$STACK_NAME" --require-approval never --outputs-file cdk-outputs.json

echo ""
echo "=============================================="
echo "Deployment Complete! Retrieving configuration..."
echo "=============================================="

# Read from cdk-outputs.json using python3 for reliable JSON parsing
if [ ! -f cdk-outputs.json ]; then
  echo "Error: cdk-outputs.json not found"
  exit 1
fi

# Parse values from cdk-outputs.json
GATEWAY_URL=$(python3 -c "import json; d=json.load(open('cdk-outputs.json')); print([v for k,v in d.get('$STACK_NAME',{}).items() if 'GatewayUrl' in k][0])" 2>/dev/null || echo "NOT_FOUND")
CLIENT_ID=$(python3 -c "import json; d=json.load(open('cdk-outputs.json')); print([v for k,v in d.get('$STACK_NAME',{}).items() if 'CognitoClientId' in k][0])" 2>/dev/null || echo "NOT_FOUND")
USER_POOL_ID=$(python3 -c "import json; d=json.load(open('cdk-outputs.json')); print([v for k,v in d.get('$STACK_NAME',{}).items() if 'CognitoUserPoolId' in k][0])" 2>/dev/null || echo "NOT_FOUND")
TOKEN_URL=$(python3 -c "import json; d=json.load(open('cdk-outputs.json')); print([v for k,v in d.get('$STACK_NAME',{}).items() if 'OAuthExchangeUrl' in k][0])" 2>/dev/null || echo "NOT_FOUND")
OAUTH_SCOPE=$(python3 -c "import json; d=json.load(open('cdk-outputs.json')); print([v for k,v in d.get('$STACK_NAME',{}).items() if 'OAuthScope' in k][0])" 2>/dev/null || echo "NOT_FOUND")
LOGS_BUCKET=$(python3 -c "import json; d=json.load(open('cdk-outputs.json')); print([v for k,v in d.get('$STACK_NAME',{}).items() if 'LogsBucketName' in k][0])" 2>/dev/null || echo "NOT_FOUND")

# Get Cognito Client Secret
echo "Retrieving Cognito Client Secret..."
if [ "$USER_POOL_ID" != "NOT_FOUND" ] && [ "$CLIENT_ID" != "NOT_FOUND" ]; then
  CLIENT_SECRET=$(aws cognito-idp describe-user-pool-client \
    --user-pool-id "$USER_POOL_ID" \
    --client-id "$CLIENT_ID" \
    --region "$REGION" \
    --query "UserPoolClient.ClientSecret" \
    --output text 2>/dev/null || echo "NOT_FOUND")
else
  CLIENT_SECRET="NOT_FOUND"
fi

echo ""
echo "=============================================="
echo "DEVOPS AGENT MCP SERVER CONFIGURATION"
echo "=============================================="
echo ""
echo "Copy these values to configure the MCP Server in DevOps Agent Console:"
echo ""
echo "┌─────────────────────────────────────────────────────────────────────┐"
echo "│ MCP Server URL:                                                     │"
echo "│ $GATEWAY_URL"
echo "├─────────────────────────────────────────────────────────────────────┤"
echo "│ OAuth Client ID:                                                    │"
echo "│ $CLIENT_ID"
echo "├─────────────────────────────────────────────────────────────────────┤"
echo "│ OAuth Client Secret:                                                │"
echo "│ $CLIENT_SECRET"
echo "├─────────────────────────────────────────────────────────────────────┤"
echo "│ Token URL:                                                          │"
echo "│ $TOKEN_URL"
echo "├─────────────────────────────────────────────────────────────────────┤"
echo "│ Scope (use only ONE):                                               │"
echo "│ $OAUTH_SCOPE"
echo "└─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "Additional Info:"
echo "  Logs Bucket: $LOGS_BUCKET"
echo "  Region: $REGION"
echo ""

# Save configuration to file
CONFIG_FILE="mcp-config.txt"
cat > "$CONFIG_FILE" << EOF
# EKS Node Log MCP - DevOps Agent Configuration
# Generated: $(date)
# Stack: $STACK_NAME
# Region: $REGION

MCP_SERVER_URL=$GATEWAY_URL
OAUTH_CLIENT_ID=$CLIENT_ID
OAUTH_CLIENT_SECRET=$CLIENT_SECRET
TOKEN_URL=$TOKEN_URL
OAUTH_SCOPE=$OAUTH_SCOPE
LOGS_BUCKET=$LOGS_BUCKET
EOF

echo "Configuration saved to: $CONFIG_FILE"
echo ""
echo "=============================================="
echo "AVAILABLE MCP TOOLS"
echo "=============================================="
echo ""
echo "1. run_eks_log_collection"
echo "   - Collect logs from an EKS worker node"
echo "   - Parameter: instanceId (e.g., i-0123456789abcdef0)"
echo ""
echo "2. get_automation_status"
echo "   - Check status of log collection"
echo "   - Parameter: executionId"
echo ""
echo "3. list_automations"
echo "   - List recent log collection executions"
echo ""
echo "4. list_collected_logs"
echo "   - List logs stored in S3"
echo "   - Optional: instanceId to filter"
echo ""
echo "5. get_log_content"
echo "   - Read a specific log file"
echo "   - Parameter: logKey (from list_collected_logs)"
echo ""
echo "=============================================="
echo "EXAMPLE PROMPT FOR DEVOPS AGENT"
echo "=============================================="
echo ""
echo "\"Collect diagnostic logs from EKS worker node i-0123456789abcdef0\""
echo ""
