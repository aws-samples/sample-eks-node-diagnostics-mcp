# EKS Node Log MCP

Production-grade MCP Server for AWS DevOps Agent to collect and analyze diagnostic logs from EKS worker nodes using SSM Automation.

## Overview

This solution enables DevOps Agent to collect diagnostic logs from EKS worker nodes through a secure MCP Gateway. It solves the challenge of running async SSM Automations and retrieving results without requiring direct S3 access for the agent.

### Key Features

- **Async Task Pattern**: Start log collection and poll for completion with idempotency support
- **Cross-Region Collection**: Collect logs from nodes in any AWS region from a single deployment
- **Byte-Range Streaming**: Read multi-GB log files without truncation using line-aligned byte ranges
- **Pre-Indexed Findings**: Fast error discovery with stable finding IDs (F-001 format) and 5-level severity
- **Anti-Hallucination Guardrails**: Finding-grounded summaries, citation enforcement, confidence levels, and gap reporting
- **Cluster-Level Intelligence**: Health overview, node comparison, smart batch collection with statistical sampling
- **Baseline Subtraction**: Suppress known pre-existing findings per cluster so only new issues surface
- **Network Diagnostics**: Structured parsing of iptables, CNI config, routes, DNS, ENI, and IPAMD logs
- **Manifest Validation**: Verify bundle completeness using manifest.json with file inventory
- **Pagination**: Page through large finding sets without truncation
- **KMS Encryption**: Server-side encryption for all stored logs
- **Secure Artifact References**: Presigned URLs for large file downloads

---

## MCP Tools

Tool names are kept short to stay under the 64-character limit when prefixed with the MCP server name (e.g., `byo-devopsagent-mcp-v2_collect`).

### Tier 1: Core Operations

| Tool | Description |
|------|-------------|
| `collect` | Start log collection with idempotency and cross-region support |
| `status` | Get detailed status with progress tracking and failure parsing |
| `validate` | Verify all expected files were extracted (uses manifest.json) |
| `errors` | Get pre-indexed findings by severity with finding IDs, pagination, and baseline subtraction |
| `read` | Line-aligned byte-range streaming for multi-GB files (NO TRUNCATION) |

### Tier 2: Advanced Analysis

| Tool | Description |
|------|-------------|
| `search` | Full-text regex search across all logs with finding IDs (S-NNN format) |
| `correlate` | Cross-file timeline correlation with temporal clusters, root cause chains, confidence, and gap reporting |
| `artifact` | Secure presigned URLs for large artifacts |
| `summarize` | Finding-grounded incident summary (requires finding_ids from errors tool) |
| `history` | Audit trail of past collections (supports cross-region) |

### Tier 3: Cluster-Level Intelligence

| Tool | Description |
|------|-------------|
| `cluster_health` | Cluster-wide health overview: node enumeration, SSM status, instance metadata |
| `compare_nodes` | Diff error findings between 2+ nodes to isolate unique vs common issues |
| `batch_collect` | Smart batch collection with statistical sampling for 1000+ node clusters |
| `batch_status` | Poll status of multiple collections at once |
| `network_diagnostics` | Structured networking analysis: iptables, CNI, routes, DNS, ENI, IPAMD |

---

## Agent Workflow

Recommended workflow for incident response:

```
1. collect(instanceId, region?)        → returns executionId + task envelope
   ↓
2. status(executionId)                 → poll until task.state = completed
   ↓
3. validate(executionId)               → file manifest with sizes
   ↓
4. errors(instanceId, clusterContext?) → pre-indexed findings with finding_ids (paginated)
   ↓
5. search(instanceId, query)           → deep investigation with regex
   ↓
6. correlate(instanceId)               → timeline + root cause chain + confidence
   ↓
7. read(logKey, startByte, endByte)    → specific file context (line-aligned)
   ↓
8. summarize(instanceId, finding_ids)  → grounded incident report
```

### Cluster-Level Workflow

```
1. cluster_health(clusterName)         → node inventory + unhealthy nodes
   ↓
2. batch_collect(clusterName, dryRun)  → preview sampling plan
   ↓
3. batch_collect(clusterName)          → collect from sampled nodes
   ↓
4. batch_status(batchId)               → poll until allComplete
   ↓
5. compare_nodes(instanceIds)          → diff findings across nodes
   ↓
6. network_diagnostics(instanceId)     → structured networking analysis
```

---

## Prerequisites

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

**Verify:**
```bash
node --version  # v18.x or later
npm --version   # v9.x or later
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

**Verify:**
```bash
aws --version  # aws-cli/2.x.x
```

### 3. AWS CDK CLI

```bash
npm install -g aws-cdk
```

**Verify:**
```bash
cdk --version  # 2.x.x
```

### 4. Python 3 (for deploy script)

Most systems have Python 3 pre-installed:
```bash
python3 --version
```

### 5. AWS Credentials

You need permissions to create IAM Roles, Lambda Functions, S3 Buckets, KMS Keys, Cognito User Pools, and BedrockAgentCore Gateways.

```bash
aws configure
# Or use AWS SSO:
aws sso login --profile your-profile
export AWS_PROFILE=your-profile
```

---

## Deployment

```bash
# Clone the repository
git clone https://github.com/aws-samples/eks-node-log-mcp.git
cd eks-node-log-mcp

# Make the script executable
chmod +x deploy.sh

# Deploy (defaults to us-east-1)
./deploy.sh

# Or deploy to a specific region
AWS_REGION=us-west-2 ./deploy.sh
```

The script will:
1. Install npm dependencies and build TypeScript
2. Bootstrap CDK (if needed)
3. Deploy the CloudFormation stack
4. Retrieve all configuration values including Cognito Client Secret
5. Save configuration to `mcp-config.txt`

### What Gets Deployed

The CDK stack creates all resources with the correct IAM permissions automatically:

| Resource | Purpose |
|----------|---------|
| S3 Bucket (KMS encrypted) | Stores collected log bundles |
| Lambda (SSM Automation) | Handles all MCP tool invocations |
| Lambda (Unzip) | Auto-extracts uploaded archives |
| Lambda (Findings Indexer) | Pre-indexes errors for fast retrieval |
| SSM Automation Role | Runs log collection on EC2 instances |
| Cognito User Pool | OAuth2 authentication for MCP Gateway |
| BedrockAgentCore Gateway | MCP protocol endpoint |
| KMS Key | Encrypts all data at rest |

The Lambda execution role is automatically granted cross-region permissions for `ec2:DescribeInstances`, `ssm:StartAutomationExecution`, `ssm:GetAutomationExecution`, and `ssm:DescribeDocument` across all regions. No manual IAM setup is needed for the Lambda itself.

---

## Post-Deployment: EKS Node IAM Setup (Required)

The `AWSSupport-CollectEKSInstanceLogs` SSM document runs directly on the EKS worker node and uploads logs to S3. The node's IAM instance profile needs two things:

1. **SSM Agent connectivity** (managed policy)
2. **S3 write access** to the logs bucket (inline policy)

### Same-Region Setup

For EKS clusters in the same region as the MCP stack:

```bash
# Get bucket name and KMS key from CDK outputs
BUCKET_NAME=$(aws cloudformation describe-stacks --stack-name EksNodeLogMcpStack \
  --query 'Stacks[0].Outputs[?contains(OutputKey,`LogsBucketName`)].OutputValue' --output text)
KMS_KEY_ARN=$(aws cloudformation describe-stacks --stack-name EksNodeLogMcpStack \
  --query 'Stacks[0].Outputs[?contains(OutputKey,`EncryptionKeyArn`)].OutputValue' --output text)

# Find your EKS node role
CLUSTER_NAME="your-cluster-name"
NODEGROUP=$(aws eks list-nodegroups --cluster-name $CLUSTER_NAME \
  --query 'nodegroups[0]' --output text)
NODE_ROLE_ARN=$(aws eks describe-nodegroup --cluster-name $CLUSTER_NAME \
  --nodegroup-name $NODEGROUP --query 'nodegroup.nodeRole' --output text)
NODE_ROLE_NAME=$(echo $NODE_ROLE_ARN | awk -F'/' '{print $NF}')

# 1. Ensure SSM Agent connectivity
aws iam attach-role-policy \
  --role-name $NODE_ROLE_NAME \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

# 2. Add S3 upload policy
aws iam put-role-policy \
  --role-name $NODE_ROLE_NAME \
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

### Cross-Region Setup

For EKS clusters in a different region than the MCP stack (e.g., stack in us-east-1, cluster in us-west-2):

```bash
# Get bucket and KMS key from the MCP stack (in your central region)
BUCKET_NAME=$(aws cloudformation describe-stacks --stack-name EksNodeLogMcpStack \
  --query 'Stacks[0].Outputs[?contains(OutputKey,`LogsBucketName`)].OutputValue' --output text)
KMS_KEY_ARN=$(aws cloudformation describe-stacks --stack-name EksNodeLogMcpStack \
  --query 'Stacks[0].Outputs[?contains(OutputKey,`EncryptionKeyArn`)].OutputValue' --output text)

# Target the remote region
REMOTE_REGION="us-west-2"
CLUSTER_NAME="your-cluster-name"

NODEGROUP=$(aws eks list-nodegroups --cluster-name $CLUSTER_NAME \
  --region $REMOTE_REGION --query 'nodegroups[0]' --output text)
NODE_ROLE_ARN=$(aws eks describe-nodegroup --cluster-name $CLUSTER_NAME \
  --nodegroup-name $NODEGROUP --region $REMOTE_REGION \
  --query 'nodegroup.nodeRole' --output text)
NODE_ROLE_NAME=$(echo $NODE_ROLE_ARN | awk -F'/' '{print $NF}')

# 1. Ensure SSM Agent connectivity
aws iam attach-role-policy \
  --role-name $NODE_ROLE_NAME \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore

# 2. Add S3 upload policy (scoped to the central bucket)
aws iam put-role-policy \
  --role-name $NODE_ROLE_NAME \
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

> **Important**: IAM is global — the same inline policy works regardless of which region the cluster is in. The key requirement is that the node role can write to the centralized S3 bucket and use the KMS key.

### Checklist Per Cluster

For every EKS cluster you want to collect logs from:

- [ ] Node role has `AmazonSSMManagedInstanceCore` managed policy attached
- [ ] Node role has `EksNodeLogMcpS3Upload` inline policy with S3 PutObject and KMS Encrypt permissions
- [ ] SSM Agent is running on the nodes (default on Amazon EKS AMIs)
- [ ] The `AWSSupport-CollectEKSInstanceLogs` SSM document exists in the target region

### SSM Document Regional Availability

The `AWSSupport-CollectEKSInstanceLogs` SSM document may not be available in all AWS regions. If you get a "document not found" error, the target region doesn't support this automation.

Commonly supported regions: us-east-1, us-east-2, us-west-2, eu-west-1, eu-central-1, ap-southeast-1, ap-northeast-1, ap-south-1.

---

## Cross-Region: How It Works

The MCP stack deploys to a single region but can collect logs from nodes in any supported region.

```
                    ┌─────────────────────────────────────────────┐
                    │           Central Region (us-east-1)        │
                    │                                             │
                    │  MCP Gateway → Lambda → S3 Bucket (KMS)    │
                    │                  │                          │
                    │                  │ SSM StartAutomation      │
                    └──────────────────┼──────────────────────────┘
                                       │
              ┌────────────────────────┼────────────────────────┐
              │                        │                        │
              ▼                        ▼                        ▼
     ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
     │   us-west-2     │    │   eu-west-1     │    │  ap-southeast-1 │
     │                 │    │                 │    │                 │
     │  EKS Node       │    │  EKS Node       │    │  EKS Node       │
     │  ↓ SSM Agent    │    │  ↓ SSM Agent    │    │  ↓ SSM Agent    │
     │  ↓ Upload to S3 │    │  ↓ Upload to S3 │    │  ↓ Upload to S3 │
     └─────────────────┘    └─────────────────┘    └─────────────────┘
```

1. `collect(instanceId, region?)` — Lambda calls SSM `StartAutomationExecution` in the target region
2. SSM runs the log collection document on the EC2 instance via SSM Agent
3. The instance uploads the log bundle directly to the central S3 bucket (cross-region S3 write)
4. Lambda stores region metadata in S3 so subsequent `status`/`validate` calls auto-route to the correct region
5. All analysis tools (`errors`, `search`, `read`, etc.) work against the central S3 bucket — no cross-region calls needed

### Region Resolution Priority

When calling `collect`:
1. Explicit `region` parameter (fastest — no lookup needed)
2. Auto-detection via `ec2:DescribeInstances` across regions (tries default region first, then 16 common regions with a 20s timeout)
3. Falls back to the Lambda's own region

> **Tip**: Always pass `region` explicitly if you know it. Auto-detection works but adds latency.

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

### Cluster Health Check
```
Give me a health check of my EKS cluster — how many nodes are up, any unhealthy ones?
```

### Incident Investigation
```
I'm seeing pod failures on my cluster. Check the cluster health, collect logs from the
unhealthiest node, and tell me what errors you find. Cite every finding ID.
```

### Baseline-Aware Scan
```
Scan errors on this node but filter out known baseline noise for my cluster.
```

### Cross-Region Collection
```
Collect logs from i-0abc123 which is running in us-west-2
```

### Smart Batch Triage
```
I suspect multiple nodes are having issues. Preview which unhealthy nodes you'd sample
and how they group by failure type. Don't collect yet, just show me the plan.
```

### Node Comparison
```
Compare these two nodes — what errors do they share vs what's unique to each?
```

### Network Deep Dive
```
This node is running out of pod IPs. Pull apart its networking — iptables, CNI config,
route tables, DNS, ENI attachments, and IPAMD status.
```

### Deep Search
```
Search for OOM or memory pressure errors in the logs from this node
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
│  (MCP Client)   │     │  (AgentCore)     │     │  (15 tools)     │
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                        ┌────────────┬────────────────────┼────────────────────┐
                        │            │                    │                    │
                        ▼            ▼                    ▼                    ▼
               ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
               │ SSM          │ │ S3 Bucket    │ │ Findings     │ │ Unzip        │
               │ Automation   │ │ (KMS + base- │ │ Indexer      │ │ Lambda       │
               │ (Collect)    │ │ lines/)      │ │ (v2 index)   │ │ (manifest)   │
               └──────┬───────┘ └──────────────┘ └──────────────┘ └──────────────┘
                      │
         ┌────────────┼────────────┐
         ▼            ▼            ▼
   ┌──────────┐ ┌──────────┐ ┌──────────┐
   │ EKS Node │ │ EKS Node │ │ EKS Node │
   │ (region) │ │ (region) │ │ (region) │
   └──────────┘ └──────────┘ └──────────┘
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

## Security

- **KMS Encryption**: All logs encrypted at rest with customer-managed key
- **Block Public Access**: S3 bucket blocks all public access
- **Enforce SSL**: All S3 operations require HTTPS
- **Anti-Hallucination**: Summaries are grounded in finding_ids — unresolved IDs are flagged
- **Confidence & Gaps**: Correlation and diagnostic tools report confidence level and data quality gaps
- **Baseline Subtraction**: Known cluster noise is annotated, not silently dropped — user retains full visibility
- **Presigned URLs**: 15-minute expiration for artifact downloads
- **Idempotency**: Prevents duplicate executions with token mapping
- **Audit Logging**: CloudWatch logs for all Lambda invocations
- **Scoped IAM**: Lambda role has least-privilege cross-region permissions provisioned by CDK

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `collect` returns "document not found" | SSM document not available in target region | Use a supported region or pass `region` explicitly |
| Log collection fails at upload step | Node role missing S3/KMS permissions | Add `EksNodeLogMcpS3Upload` inline policy (see setup above) |
| `status` returns wrong region | Region metadata not persisted | Pass `region` explicitly to `status` |
| Auto-detection times out | Instance in an uncommon region | Pass `region` explicitly to `collect` |
| Tool name exceeds 64 chars | MCP server name too long | Tool names are already shortened — check server name length |
| `errors` returns empty | Findings indexer hasn't run yet | Wait a few seconds after `validate` completes, or use `search` |

---

## Cleanup

```bash
cdk destroy
```

> **Note**: The S3 bucket has `removalPolicy: RETAIN` by default. Delete it manually after stack destruction if needed.

---

## License

MIT-0
