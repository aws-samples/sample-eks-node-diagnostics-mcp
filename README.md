# EKS Node Log MCP

MCP Server for AWS DevOps Agent to collect diagnostic logs from EKS worker nodes using SSM Automation.

## Overview

This solution enables DevOps Agent to collect diagnostic logs from EKS worker nodes through a secure MCP Gateway. It solves the challenge of running async SSM Automations and retrieving results without requiring direct S3 access for the agent.


## MCP Tools

| Tool | Description |
|------|-------------|
| `run_eks_log_collection` | Start log collection from an EKS worker node |
| `get_automation_status` | Check the status of an SSM Automation execution |
| `list_automations` | List recent SSM Automation executions |
| `list_collected_logs` | List collected logs in S3 (includes extracted files) |
| `get_log_content` | Read the content of a specific log file |

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
- Cognito User Pools
- BedrockAgentCore Gateway

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

# Deploy and get configuration
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

## Usage Example

Once configured, you can ask DevOps Agent:

```
Collect logs from EKS worker node i-0123456789abcdef0
```

The agent will:
1. Start the SSM Automation (`run_eks_log_collection`)
2. Poll for completion (`get_automation_status`)
3. List the collected logs (`list_collected_logs`)
4. Read and analyze the log content (`get_log_content`)

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

---

## Cleanup

To delete all resources:

```bash
cdk destroy
```


## License

MIT-0
