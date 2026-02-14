# EKS Node Log MCP

> **⚠️ Proof of Concept (POC):** This project is a proof of concept and should be tested in non-production environments first. Validate thoroughly in a staging or development account before using with production workloads.

> **Ready to deploy?** Jump straight to [Prerequisites](#prerequisites) and [Deployment](#deployment).

MCP Server for AWS DevOps Agent to collect and analyze diagnostic logs from EKS worker nodes using SSM Automation.

## The Problem

Around 40–50% of EKS production issues originate at the worker node level. When investigating these issues, teams typically send containerd and kubelet logs — but that is rarely enough. Effective root cause analysis also requires iptables rules, CNI configuration, route tables, DNS resolution state, ENI attachment status, conntrack tables, kernel ring buffer (dmesg), and IPAMD logs. These artifacts live on the node's OS and are not accessible through the Kubernetes API or CloudWatch.

This creates a gap: AI agents (DevOps Agent, or any MCP-compatible agent) can reason over logs, but they have no way to collect the full set of node-level evidence needed to diagnose networking failures, OOM kills, node NotReady events, or IP exhaustion issues.

## How This MCP Server Fills the Gap

This server gives any MCP-compatible agent the ability to:

- **Collect the full diagnostic bundle** from any EKS worker node via SSM Automation — not just kubelet/containerd, but all 20+ log sources including iptables, routes, CNI config, ENI metadata, IPAMD, dmesg, sysctl settings, and more
- **Pre-index errors** with severity classification and stable finding IDs so the agent doesn't have to parse raw logs
- **Stream multi-GB files** with byte-range reads — no truncation, no token limits
- **Correlate across log sources** to build temporal root cause chains (e.g., IPAMD IP exhaustion → CNI plugin failure → pod stuck in ContainerCreating)
- **Run live tcpdump captures** on nodes via SSM Run Command, with decoded packet summaries, protocol stats, and anomaly detection the agent can read directly
- **Compare nodes** to isolate what's unique to a failing node vs. common baseline noise
- **Batch collect** from 1000+ node clusters with smart statistical sampling

The result: an agent can go from "node is NotReady" to a grounded incident report with cited evidence in a single conversation, without a human needing to SSH into the node.

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

### Tier 4: Live Packet Capture

| Tool | Description |
|------|-------------|
| `tcpdump_capture` | Run tcpdump on a node via SSM Run Command (default 2 min). Supports capturing inside a pod/container network namespace — provide `podName` + `podNamespace` (auto-resolves PID via crictl/docker) or raw `containerPid`. Returns commandId for async polling. Uploads pcap + decoded summary + stats to S3 |
| `tcpdump_analyze` | Read decoded packet text, protocol stats (TCP/UDP/ICMP), top talkers, and anomaly detection (high RST, retransmissions, SYN floods) from a completed capture |

### Tier 5: SOP Management

| Tool | Description |
|------|-------------|
| `list_sops` | List all available runbooks with title, description, severity, and trigger patterns. Use to find the right SOP for a given symptom |
| `get_sop` | Retrieve the full SOP procedure by name (e.g., `D9-pod-to-pod-connectivity`). Returns the complete 3-phase investigation flow |

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

### Live Packet Capture Workflow

```
1. tcpdump_capture(instanceId, durationSeconds?, filter?, podName?, podNamespace?)
   → returns commandId + task envelope (async)
   ↓
2. tcpdump_capture(commandId, instanceId)
   → poll until status = completed
   ↓
3. tcpdump_analyze(instanceId, commandId)
   → decoded packets, protocol stats, top talkers, anomalies
```

### SOP-Guided Investigation

The agent can discover and follow structured runbooks for 36 known failure categories:

```
1. list_sops()                         → browse all 36 runbooks by category
   ↓
2. get_sop(sopName="D9-pod-to-pod-connectivity")
   → full 3-phase procedure with MCP tool calls
   ↓
3. Follow Phase 1 → Phase 2 → Phase 3 from the SOP
```

Every SOP follows a consistent 3-phase structure:
- **Phase 1 — Triage**: FIRST check pod/node state via EKS MCP tools, then collect logs and get pre-indexed findings
- **Phase 2 — Enrich**: Deep investigation with search, correlate, and domain-specific diagnostics
- **Phase 3 — Report**: Grounded incident summary with root cause, evidence, and remediation

---

## Runbook Library (36 SOPs)

All SOPs are stored in `sops/runbooks/` and automatically deployed to S3 via CDK BucketDeployment. The agent retrieves them at runtime using `list_sops` and `get_sop`.

| Category | SOPs | Coverage |
|----------|------|----------|
| **A — Node Lifecycle** | A1 (OOM/NotReady), A2 (Certificate Expired), A2 (Bootstrap Failure), A3 (Clock Skew), A4 (Join Failure) | Node registration, readiness, certificates |
| **B — Kubelet** | B1 (Config Errors), B2 (Eviction Manager), B3 (PLEG) | Kubelet crashes, eviction, container lifecycle |
| **C — Container Runtime** | C1 (Image Pull), C2 (Sandbox Creation), C3 (OverlayFS/Inode) | containerd, image pulls, filesystem |
| **D — Networking** | D1 (VPC CNI/IP), D2 (kube-proxy/iptables), D3 (Conntrack), D4 (MTU), D5 (DNS), D6 (ENA Throttling), D7 (Network Perf), D8 (Service Connectivity), D9 (Pod-to-Pod) | Full networking stack coverage |
| **E — Storage** | E1 (EBS CSI), E2 (EFS Mount) | Persistent volume attach/mount |
| **F — Scheduling** | F1 (CPU/Memory), F2 (Max Pods), F3 (Taints/Tolerations) | Pod scheduling failures |
| **G — Resource Pressure** | G1 (Disk Pressure), G2 (OOMKill), G3 (PID Pressure) | Node resource exhaustion |
| **H — IAM/Security** | H1 (Node Role), H2 (IRSA/Pod Identity), H3 (IMDS) | Permissions, credentials, metadata |
| **I — Upgrades** | I1 (Version Skew) | Control plane / node version mismatch |
| **J — Infrastructure** | J1 (ENA/Instance Limits), J2 (EBS Transient Attach), J3 (AZ Outage) | EC2, EBS, AZ-level failures |
| **Z — Catch-All** | Z1 (General Troubleshooting) | Systematic investigation for unknown issues |

### SOP Design Principles

- **FIRST check pod/node state**: Every SOP starts by checking pod and node status via EKS MCP tools (`list_k8s_resources`, `read_k8s_resource`, `get_k8s_events`) before collecting any node-level logs
- **MCP tools only**: SOPs reference only the 19 tools exposed by this MCP server — no kubectl, no AWS CLI, no SSH
- **3-phase structure**: Triage → Enrich → Report with MUST/SHOULD/MAY priority levels
- **Guardrails**: Escalation conditions and safety ratings (GREEN/YELLOW/RED) for every action
- **Grounded evidence**: All conclusions cite specific finding IDs from the `errors` and `search` tools

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
| S3 Bucket (SOPs) | Stores 36 runbooks, auto-deployed via CDK BucketDeployment |
| Lambda (SSM Automation) | Handles all 19 MCP tool invocations |
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

### "My pods keep getting evicted"
```
Pods on my production cluster keep getting evicted. Check cluster health, find which
nodes are under pressure, collect logs from the worst one, and tell me what's causing it.
```

### "Node went NotReady at 3am"
```
Node i-0abc123def in us-west-2 went NotReady around 3am last night. Collect its logs
and correlate what happened in the 5 minutes before it went down. I need the root cause chain.
```

### "We're leaking IPs"
```
Our pods are stuck in ContainerCreating and I think we're out of IPs. Pull the networking
diagnostics from node i-0abc123def — I need the IPAMD logs, ENI attachments, and iptables rules.
```

### "Is this error new or has it always been there?"
```
I'm seeing CNI plugin errors on this node. Scan the errors but use baseline subtraction
for cluster devopsagentcluster — I only want to see findings that are new, not the usual noise.
```

### "Multiple nodes crashing after a deploy"
```
After our last deploy, 3 nodes started flapping. Compare nodes i-0abc123, i-0def456,
and i-0ghi789 — what errors do they all share vs what's unique to each?
```

### "OOM but I don't know which container"
```
Something on node i-0abc123def is getting OOM killed. Search the kubelet and kernel logs
for OOM, memory pressure, or cgroup limit — show me the exact log lines with timestamps.
```

### "Triage a 200-node cluster"
```
We have a 200-node cluster and something is off. Do a dry run batch collection first —
show me which nodes you'd sample and why. Then collect from the unhealthy ones.
```

### "Read the raw kubelet log around the crash"
```
Finding F-003 mentions a kubelet restart. Read the raw kubelet log starting at byte
offset 2500000 — I want to see the 50 lines around that event.
```

### "Give me the incident summary for the ticket"
```
I've reviewed findings F-001 through F-008 from this node. Generate an incident summary
grounded in those finding IDs — I need it for the post-incident review.
```

### "Capture traffic to debug connection timeouts"
```
Pods on node i-0abc123def can't reach the API server. Run a 2-minute tcpdump filtered
on port 443, then analyze the capture — show me RST counts, retransmissions, and top IPs.
```

### "Is something dropping packets?"
```
Run tcpdump on i-0abc123def for 60 seconds with no filter. I want to see the full protocol
breakdown and any anomalies — especially RST rates and ICMP unreachables.
```

### "Capture DNS traffic from inside a CoreDNS pod"
```
DNS lookups are timing out intermittently. The CoreDNS pod coredns-5d78c9869d-abc12 is
running on node i-0abc123def in kube-system. Capture UDP port 53 traffic from inside
the pod's network namespace for 60 seconds, then analyze the capture.
```

### "Debug VPC CNI pod networking from the pod's perspective"
```
Pod my-app-7b9f4c-xyz in namespace production on node i-0abc123def can't reach the
database. Capture all traffic from inside the pod's namespace for 2 minutes — I want
to see if SYN packets are leaving and whether RSTs are coming back.
```

### "Check network between two pods"
```
Check network between pods test1 and test2 on node i-0abc123def. Capture packets on
both pods and tell me if there are any drops or issues.
```

### "I don't know what's wrong — just investigate"
```
Node i-0abc123def is acting weird but I'm not sure what category the issue falls into.
List the available SOPs, run a general triage, and follow whichever runbook matches.
```

---

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  DevOps Agent   │────▶│  MCP Gateway     │────▶│  Lambda         │
│  (MCP Client)   │     │  (AgentCore)     │     │  (19 tools)     │
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
| `SOPBucketName` | S3 bucket for runbook SOPs |
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

This project is licensed under the MIT No Attribution (MIT-0) License. See the [LICENSE](LICENSE) file for details.
