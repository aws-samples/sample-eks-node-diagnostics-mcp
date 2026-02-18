# EKS Node Diagnostics MCP

> **⚠️ Proof of Concept (POC):** This project is a proof of concept and should be tested in non-production environments first. Validate thoroughly in a staging or development account before using with production workloads.

MCP Server for AWS DevOps Agent to collect and analyze diagnostic logs from EKS worker nodes using SSM Automation. Covers 20+ log sources including kubelet, containerd, iptables, CNI config, route tables, dmesg, IPAMD, and more — artifacts that live on the node OS and aren't accessible through the Kubernetes API or CloudWatch.

> **Want to understand the internals?** See [Architecture & Design](docs/ARCHITECTURE.md) for a deep dive into how the components work, data flows, tool design, and security model.

---

## Prerequisites

### 1. Node.js (v18.x or later)

**macOS (Homebrew):**
```bash
brew install node
```

**Linux (Ubuntu/Debian):**
```bash
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs
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

### 3. AWS CDK CLI

```bash
npm install -g aws-cdk
```

### 4. Python 3

Most systems have it pre-installed:
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

### 6. crictl on Worker Nodes (for pod-level tcpdump)

Required only for `tcpdump_capture` with `podName`/`podNamespace`. EKS-optimized AMIs include it by default.

---

## Deployment

```bash
# Clone the repository
git clone https://github.com/aws-samples/sample-eks-node-diagnostics-mcp.git
cd sample-eks-node-diagnostics-mcp

# Make the script executable
chmod +x deploy.sh

# Deploy (defaults to us-east-1)
./deploy.sh

# Or deploy to a specific region
AWS_REGION=us-west-2 ./deploy.sh
```

### Interactive Deployment Flow

The deploy script walks you through three interactive prompts:

**Step 1 — Region selection:**
```
Which AWS regions should be scanned for EKS clusters?

  1) All enabled regions
  2) Current deploy region only (us-east-1)
  3) Enter a specific region

Select [1/2/3] (default: 1):
```

**Step 2 — Cluster selection:**
```
Found 4 EKS cluster(s):

  1) prod-cluster    (us-east-1)
  2) dev-cluster     (us-east-1)
  3) analytics        (us-west-2)
  4) eu-cluster       (eu-west-1)

  a) All clusters

Select clusters (comma-separated numbers, or 'a' for all) [default: a]:
```

**Step 3 — Node role selection:**
```
Found 3 unique node role(s):

  1) arn:aws:iam::123456789012:role/eks-prod-node-role
     └─ eks-prod-node-role  (prod-cluster / us-east-1)
  2) arn:aws:iam::123456789012:role/eks-dev-node-role
     └─ eks-dev-node-role  (dev-cluster / us-east-1)
  3) arn:aws:iam::123456789012:role/eks-eu-node-role
     └─ eks-eu-node-role  (eu-cluster / eu-west-1)

  a) All roles

Select node roles (comma-separated numbers, or 'a' for all) [default: a]:
```

**Fallback — Manual ARN entry:**

If no EKS clusters or node roles are found, the script prompts you to enter role ARNs manually:
```
WARNING: No EKS clusters found in the selected region(s).

Would you like to manually enter node role ARN(s)? [y/N]: y
Enter comma-separated role ARNs (e.g. arn:aws:iam::123456789012:role/MyNodeRole):
>
```

### Non-Interactive / CI Mode

Skip all prompts by providing role ARNs directly:

```bash
# Via environment variable
EKS_NODE_ROLE_ARNS="arn:aws:iam::123456789012:role/MyNodeRole" ./deploy.sh

# Or as a positional argument
./deploy.sh EksNodeLogMcpStack arn:aws:iam::123456789012:role/MyNodeRole

# Multiple roles (comma-separated)
EKS_NODE_ROLE_ARNS="arn:aws:iam::123456789012:role/Role1,arn:aws:iam::123456789012:role/Role2" ./deploy.sh
```

### What Gets Deployed

| Resource | Purpose |
|----------|---------|
| S3 Bucket (KMS encrypted) | Stores collected log bundles |
| S3 Bucket (SOPs) | Stores 36 runbooks, auto-deployed via CDK |
| Lambda (SSM Automation) | Handles all 19 MCP tool invocations |
| Lambda (Unzip) | Auto-extracts uploaded archives |
| Lambda (Findings Indexer) | Pre-indexes errors for fast retrieval |
| SSM Automation Role | Runs log collection on EC2 instances |
| Cognito User Pool | OAuth2 authentication for MCP Gateway |
| BedrockAgentCore Gateway | MCP protocol endpoint |
| KMS Key | Encrypts all data at rest |

---

## Post-Deployment: EKS Node IAM Setup

### What's Automatic

If you selected node roles during the interactive deploy flow (or passed them via `EKS_NODE_ROLE_ARNS`), the CDK stack automatically grants:

- S3 bucket policy: `s3:PutObject`, `s3:GetBucketPolicyStatus`, `s3:GetBucketAcl` on the logs bucket
- KMS key policy: `kms:GenerateDataKey`, `kms:Encrypt` on the encryption key

No manual S3 or KMS setup is needed for those roles.

If no node roles were provided during deployment, the stack falls back to an account-scoped policy (any principal in the account can upload). This is less restrictive but still functional.

### What You May Still Need

The only thing the CDK stack does not attach is the SSM Agent managed policy. EKS-optimized AMIs include SSM Agent by default, but the IAM role needs the policy:

```bash
# Only needed if not already attached
aws iam attach-role-policy \
  --role-name <YOUR-NODE-ROLE-NAME> \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
```

### Adding Node Roles After Deployment

If you add new EKS clusters later, re-run the deploy script — it will detect the new node roles and update the S3 bucket and KMS key policies automatically.

Alternatively, pass the new roles directly:

```bash
EKS_NODE_ROLE_ARNS="arn:aws:iam::123456789012:role/ExistingRole,arn:aws:iam::123456789012:role/NewRole" ./deploy.sh
```

### Checklist Per Cluster

- [ ] Node role was selected during deployment (or added via re-deploy)
- [ ] Node role has `AmazonSSMManagedInstanceCore` managed policy (for SSM Agent)
- [ ] SSM Agent is running on the nodes (default on EKS-optimized AMIs)
- [ ] `AWSSupport-CollectEKSInstanceLogs` SSM document exists in the target region

---

## Configuration in DevOps Agent

After deployment, the script outputs all values needed for the MCP Server configuration:

| Setting | Value |
|---------|-------|
| MCP Server URL | `https://<gateway-id>.gateway.bedrock-agentcore.<region>.amazonaws.com/mcp` |
| OAuth Client ID | Cognito Client ID from output |
| OAuth Client Secret | Cognito Client Secret from output |
| Token URL | `https://<stack-name>-<account>.auth.<region>.amazoncognito.com/oauth2/token` |
| Scope | `ssm-automation-gateway-id/gateway:read` |

Values are also saved to `mcp-config.txt` for reference.

---

## How It Works

The server gives MCP-compatible agents the ability to collect full diagnostic bundles from EKS worker nodes, pre-index errors with severity classification, stream multi-GB log files without truncation, correlate events across log sources, run live tcpdump captures, compare nodes, and follow structured runbooks — all through 19 MCP tools organized in 5 tiers.

For a detailed walkthrough of the architecture, data flows, tool design, cross-region mechanics, security model, and anti-hallucination design, see:

**[Architecture & Design →](docs/ARCHITECTURE.md)**

### MCP Tools (Quick Reference)

| Tier | Tools | Purpose |
|------|-------|---------|
| 1 — Core | `collect`, `status`, `validate`, `errors`, `read` | Log collection, findings, streaming |
| 2 — Analysis | `search`, `correlate`, `artifact`, `summarize`, `history` | Deep investigation, correlation, summaries |
| 3 — Cluster | `cluster_health`, `compare_nodes`, `batch_collect`, `batch_status`, `network_diagnostics` | Multi-node operations |
| 4 — Capture | `tcpdump_capture`, `tcpdump_analyze` | Live packet capture and analysis |
| 5 — SOPs | `list_sops`, `get_sop` | 36 structured runbooks |

### Agent Workflow

```
collect → status (poll) → validate → errors → search → correlate → read → summarize
```

### Runbook Library (36 SOPs)

| Category | Coverage |
|----------|----------|
| A — Node Lifecycle | OOM/NotReady, certificates, bootstrap, clock skew, join failures |
| B — Kubelet | Config errors, eviction, PLEG |
| C — Container Runtime | Image pull, sandbox creation, OverlayFS/inode |
| D — Networking | VPC CNI, kube-proxy, conntrack, MTU, DNS, ENA, pod-to-pod |
| E — Storage | EBS CSI, EFS mount |
| F — Scheduling | CPU/memory, max pods, taints/tolerations |
| G — Resource Pressure | Disk pressure, OOMKill, PID pressure |
| H — IAM/Security | Node role, IRSA/Pod Identity, IMDS |
| I — Upgrades | Version skew |
| J — Infrastructure | ENA/instance limits, EBS transient, AZ outage |
| Z — Catch-All | General troubleshooting |

---

## Usage Examples

### Basic Investigation
```
Node i-0abc123def in us-west-2 went NotReady around 3am. Collect its logs
and correlate what happened in the 5 minutes before it went down.
```

### Cluster-Wide Triage
```
We have a 200-node cluster and something is off. Do a dry run batch collection
first — show me which nodes you'd sample. Then collect from the unhealthy ones.
```

### Live Packet Capture
```
Pods on node i-0abc123def can't reach the API server. Run a 2-minute tcpdump
filtered on port 443, then analyze — show me RST counts and retransmissions.
```

### Pod-Level Capture
```
DNS lookups are timing out. CoreDNS pod coredns-5d78c9869d-abc12 is on node
i-0abc123def in kube-system. Capture UDP port 53 from inside the pod for 60s.
```

### SOP-Guided
```
I don't know what's wrong — just investigate. List the available SOPs, run a
general triage, and follow whichever runbook matches.
```

---

## CloudFormation Outputs

| Output | Description |
|--------|-------------|
| `GatewayId` | AgentCore Gateway ID |
| `GatewayUrl` | MCP Server URL |
| `CognitoUserPoolId` | Cognito User Pool ID |
| `CognitoClientId` | OAuth Client ID |
| `OAuthExchangeUrl` | OAuth Token URL |
| `OAuthScope` | OAuth Scope |
| `LogsBucketName` | S3 bucket for logs |
| `SOPBucketName` | S3 bucket for runbooks |
| `SSMAutomationRoleArn` | SSM Automation role ARN |
| `EncryptionKeyArn` | KMS key ARN |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `collect` returns "document not found" | SSM document not in target region | Use a supported region or pass `region` explicitly |
| Upload step fails | Node role missing S3/KMS permissions | Add `EksNodeLogMcpS3Upload` inline policy |
| `status` returns wrong region | Region metadata not persisted | Pass `region` explicitly |
| Auto-detection times out | Instance in uncommon region | Pass `region` explicitly |
| `errors` returns empty | Findings indexer hasn't run yet | Wait a few seconds after `validate`, or use `search` |

---

## Cleanup

```bash
cdk destroy
```

> The S3 bucket has `removalPolicy: RETAIN`. Delete it manually after stack destruction if needed.

---

## License

This project is licensed under the MIT No Attribution (MIT-0) License. See the [LICENSE](LICENSE) file.
