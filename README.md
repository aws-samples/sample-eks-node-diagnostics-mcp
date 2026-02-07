# EKS Node Log MCP

Production-grade MCP Server for AWS DevOps Agent to collect and analyze diagnostic logs from EKS worker nodes using SSM Automation.

## Overview

This solution enables DevOps Agent to collect diagnostic logs from EKS worker nodes through a secure MCP Gateway. It solves the challenge of running async SSM Automations and retrieving results without requiring direct S3 access for the agent.

### Key Features

- **Async Task Pattern**: Start log collection and poll for completion with idempotency support
- **Byte-Range Streaming**: Read multi-GB log files without truncation
- **Pre-Indexed Findings**: Fast error discovery without scanning raw files
- **Manifest Validation**: Verify bundle completeness before analysis
- **KMS Encryption**: Server-side encryption for all stored logs
- **Secure Artifact References**: Presigned URLs for large file downloads

---

## MCP Tools

### Tier 1: Core Operations

| Tool | Description |
|------|-------------|
| `start_log_collection` | Start log collection with idempotency token support |
| `get_collection_status` | Get detailed status with progress tracking and failure parsing |
| `validate_bundle_completeness` | Verify all expected files were extracted |
| `get_error_summary` | Get pre-indexed error findings (fast path) |
| `read_log_chunk` | Byte-range streaming for multi-GB files (NO TRUNCATION) |

### Tier 2: Advanced Analysis

| Tool | Description |
|------|-------------|
| `search_logs_deep` | Full-text regex search across all logs |
| `correlate_events` | Cross-file timeline correlation |
| `get_artifact_reference` | Secure presigned URLs for large artifacts |
| `generate_incident_summary` | AI-ready structured incident summary |
| `list_collection_history` | Audit trail of past collections |

---

## Agent Workflow

Recommended workflow for incident response:

```
1. start_log_collection(instanceId, idempotencyToken)
   ↓
2. get_collection_status(executionId) [poll until Success]
   ↓
3. validate_bundle_completeness(executionId)
   ↓
4. get_error_summary(instanceId) [fast path - pre-indexed]
   ↓
5. search_logs_deep(instanceId, query) [if deeper investigation needed]
   ↓
6. read_log_chunk(logKey, startByte, endByte) [for specific file context]
   ↓
7. generate_incident_summary(instanceId) [final report]
```

---

## Prerequisites

Before deploying, ensure you have the following installed:

### 1. Node.js (v18.x or later)

**macOS (using Homebrew):**
```bash
brew install node
```

**Linux (Ubuntu/Debian):**
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
```

**Verify installation:**
```bash
node --version  # Should be v18.x or later
npm --version   # Should be v9.x or later
```

### 2. AWS CLI v2

**macOS:**
```bash
brew install awscli
```

**Linux:**
```bash
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
```

**Verify installation:**
```bash
aws --version  # Should be aws-cli/2.x.x
```

### 3. AWS CDK CLI

```bash
npm install -g aws-cdk
```

**Verify installation:**
```bash
cdk --version  # Should be 2.x.x
```

### 4. Python 3 (for deploy script)

Most systems have Python 3 pre-installed. Verify with:
```bash
python3 --version
```

### 5. AWS Credentials

Configure AWS credentials with permissions to create:
- IAM Roles and Policies
- Lambda Functions
- S3 Buckets
- KMS Keys
- Cognito User Pools
- BedrockAgentCore Gateway

```bash
aws configure
# Or use AWS SSO:
aws sso login --profile your-profile
export AWS_PROFILE=your-profile
```

### 6. EKS Worker Node IAM Permissions (Required)

The `AWSSupport-CollectEKSInstanceLogs` SSM document runs on the EKS worker node and uploads logs directly to S3. The EKS worker node's IAM instance profile must have permissions to write to the logs bucket.

After deployment, add the following inline policy to your EKS node group IAM role:

```bash
# Get the S3 bucket name and KMS key ARN from CDK outputs
BUCKET_NAME=$(aws cloudformation describe-stacks --stack-name EksNodeLogMcpStack \
  --query 'Stacks[0].Outputs[?OutputKey==`LogsBucketName`].OutputValue' --output text)
KMS_KEY_ARN=$(aws cloudformation describe-stacks --stack-name EksNodeLogMcpStack \
  --query 'Stacks[0].Outputs[?OutputKey==`EncryptionKeyArn`].OutputValue' --output text)

# Add policy to your EKS node role (replace YOUR_EKS_NODE_ROLE_NAME)
aws iam put-role-policy \
  --role-name YOUR_EKS_NODE_ROLE_NAME \
  --policy-name EksNodeLogMcpS3Upload \
  --policy-document "{
    \"Version\": \"2012-10-17\",
    \"Statement\": [
      {
        \"Effect\": \"Allow\",
        \"Action\": [
          \"s3:PutObject\",
          \"s3:GetBucketPolicyStatus\",
          \"s3:GetBucketAcl\"
        ],
        \"Resource\": [
          \"arn:aws:s3:::${BUCKET_NAME}\",
          \"arn:aws:s3:::${BUCKET_NAME}/*\"
        ]
      },
      {
        \"Effect\": \"Allow\",
        \"Action\": [
          \"kms:GenerateDataKey\",
          \"kms:Encrypt\"
        ],
        \"Resource\": \"${KMS_KEY_ARN}\"
      }
    ]
  }"
```

**To find your EKS node role name:**
```bash
# List node groups for your cluster
aws eks list-nodegroups --cluster-name YOUR_CLUSTER_NAME

# Get the node role ARN
aws eks describe-nodegroup --cluster-name YOUR_CLUSTER_NAME \
  --nodegroup-name YOUR_NODEGROUP_NAME \
  --query 'nodegroup.nodeRole' --output text
```

> **Note**: Without these permissions, log collection will fail at the upload step with an S3 access denied error.

---

## Deployment

```bash
# Clone the repository
git clone https://github.com/aws-samples/eks-node-log-mcp.git
cd eks-node-log-mcp

# Make the script executable
chmod +x deploy.sh

# Deploy
./deploy.sh
```

The script will:
1. Install npm dependencies
2. Build TypeScript
3. Bootstrap CDK (if needed)
4. Deploy the CloudFormation stack
5. Retrieve all configuration values including Cognito Client Secret
6. Display formatted configuration for DevOps Agent
7. Save configuration to `mcp-config.txt`

---

## Configuration in DevOps Agent

After deployment, configure the MCP Server in DevOps Agent Console with the values from the deploy script output:

| Setting | Value |
|---------|-------|
| **MCP Server URL** | `https://<gateway-id>.gateway.bedrock-agentcore.<region>.amazonaws.com/mcp` |
| **OAuth Client ID** | Cognito Client ID from output |
| **OAuth Client Secret** | Cognito Client Secret from output |
| **Token URL** | `https://<stack-name>-<account>.auth.<region>.amazoncognito.com/oauth2/token` |
| **Scope** | `ssm-automation-gateway-id/gateway:read` |

> **Important**: DevOps Agent doesn't handle multiple OAuth scopes. Use only ONE scope: `gateway:read`

---

## Usage Examples

### Basic Log Collection

```
Collect logs from EKS worker node i-0123456789abcdef0
```

### Incident Investigation

```
I'm investigating a node issue on i-0123456789abcdef0. 
Collect logs, find any critical errors, and give me a summary.
```

### Deep Search

```
Search for OOM or memory pressure errors in the logs from i-0123456789abcdef0
```

### Read Specific Log Section

```
Read bytes 1000000-2000000 from the kubelet log file
```

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  DevOps Agent   │────▶│  MCP Gateway     │────▶│  Lambda         │
│  (MCP Client)   │     │  (AgentCore)     │     │  (Enhanced)     │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                        ┌─────────────────────────────────┼─────────────────────────────────┐
                        │                                 │                                 │
                        ▼                                 ▼                                 ▼
               ┌─────────────────┐             ┌─────────────────┐             ┌─────────────────┐
               │  SSM Automation │             │  S3 Bucket      │             │  Findings       │
               │  (Log Collect)  │────────────▶│  (KMS Encrypted)│◀────────────│  Indexer        │
               └─────────────────┘             └─────────────────┘             └─────────────────┘
                        │                                 │
                        ▼                                 ▼
               ┌─────────────────┐             ┌─────────────────┐
               │  EKS Worker     │             │  Unzip Lambda   │
               │  Node           │             │  (Auto-extract) │
               └─────────────────┘             └─────────────────┘
```

---

## CloudFormation Outputs

| Output | Description |
|--------|-------------|
| `GatewayId` | ID of the AgentCore Gateway |
| `GatewayUrl` | URL for MCP Server configuration |
| `CognitoUserPoolId` | Cognito User Pool ID |
| `CognitoClientId` | OAuth Client ID |
| `OAuthExchangeUrl` | OAuth Token URL |
| `OAuthScope` | OAuth Scope (use only ONE) |
| `LogsBucketName` | S3 bucket for collected logs |
| `SSMAutomationRoleArn` | IAM role for SSM Automation |
| `EncryptionKeyArn` | KMS key ARN |

---

## Security Features

- **KMS Encryption**: All logs encrypted at rest with customer-managed key
- **Block Public Access**: S3 bucket blocks all public access
- **Enforce SSL**: All S3 operations require HTTPS
- **Presigned URLs**: 15-minute expiration for artifact downloads
- **Idempotency**: Prevents duplicate executions with token mapping
- **Audit Logging**: CloudWatch logs for all Lambda invocations

---

## Cleanup

To delete all resources:

```bash
cdk destroy
```

---

## License

MIT-0
