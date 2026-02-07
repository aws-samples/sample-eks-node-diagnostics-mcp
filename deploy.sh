#!/bin/bash
set -e

# EKS Node Log MCP - Deploy and Configure Script
# This script deploys the CDK stack and outputs all values needed for DevOps Agent configuration

STACK_NAME="${1:-EksNodeLogMcpStack}"
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
echo "TIER 1: CORE OPERATIONS"
echo "------------------------"
echo "1. start_log_collection"
echo "   - Start log collection with idempotency support"
echo "   - Parameters: instanceId (required), idempotencyToken (optional)"
echo ""
echo "2. get_collection_status"
echo "   - Get detailed status with progress tracking"
echo "   - Parameters: executionId (required), includeStepDetails (optional)"
echo ""
echo "3. validate_bundle_completeness"
echo "   - Verify all expected files were extracted"
echo "   - Parameters: executionId or instanceId"
echo ""
echo "4. get_error_summary"
echo "   - Get pre-indexed error findings (fast path)"
echo "   - Parameters: instanceId (required), severity (optional)"
echo ""
echo "5. read_log_chunk"
echo "   - Byte-range streaming for multi-GB files (NO TRUNCATION)"
echo "   - Parameters: logKey (required), startByte/endByte or startLine/lineCount"
echo ""
echo "TIER 2: ADVANCED ANALYSIS"
echo "-------------------------"
echo "6. search_logs_deep"
echo "   - Full-text regex search across all logs"
echo "   - Parameters: instanceId, query (required), logTypes, maxResults"
echo ""
echo "7. correlate_events"
echo "   - Cross-file timeline correlation"
echo "   - Parameters: instanceId (required), timeWindow, pivotEvent"
echo ""
echo "8. get_artifact_reference"
echo "   - Secure presigned URLs for large artifacts"
echo "   - Parameters: logKey (required), expirationMinutes"
echo ""
echo "9. generate_incident_summary"
echo "   - AI-ready structured incident summary"
echo "   - Parameters: instanceId (required), includeRecommendations"
echo ""
echo "10. list_collection_history"
echo "    - Audit trail of past collections"
echo "    - Parameters: instanceId, maxResults, status (all optional)"
echo ""
echo "=============================================="
echo "EXAMPLE PROMPT FOR DEVOPS AGENT"
echo "=============================================="
echo ""
echo "\"I'm investigating a node issue on i-0123456789abcdef0."
echo " Collect logs, find any critical errors, and give me a summary.\""
echo ""
