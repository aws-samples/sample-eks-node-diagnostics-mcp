---
title: "H1 — Node Role Missing Permissions"
description: "Diagnose ECR pull failures, CNI failures, or registration failures caused by missing IAM policies on node role"
status: active
severity: HIGH
triggers:
  - "AccessDenied"
  - "is not authorized to perform"
  - "UnauthorizedAccess"
owner: devops-agent
objective: "Identify missing IAM policies on the node role and restore permissions"
context: "EKS worker nodes require specific IAM policies: AmazonEKSWorkerNodePolicy, AmazonEKS_CNI_Policy, and AmazonEC2ContainerRegistryReadOnly. Missing any of these causes cascading failures in node registration, networking, or image pulls."
---

## Phase 1 — Triage

FIRST — Check node and pod state before collecting logs:
- Use `list_k8s_resources` with clusterName, kind=Node, apiVersion=v1 to list all nodes — check if the affected node is Ready or NotReady, and whether it even appears in the cluster (missing = registration failure)
- Use `read_k8s_resource` with clusterName, kind=Node, apiVersion=v1, name=<node-name> to get detailed node conditions — look for NetworkUnavailable (CNI permission failure) or NotReady (general permission issue)
- Use `list_k8s_resources` with clusterName, kind=Pod, apiVersion=v1, fieldSelector=spec.nodeName=<node-name> to list pods on the node — check for ImagePullBackOff (ECR permission failure) or CrashLoopBackOff (CNI/credential failures)
- Use `get_k8s_events` with clusterName, kind=Node, name=<node-name> to check for FailedCreatePodSandBox, ErrImagePull, or registration-related events

MUST:
- Use `collect` tool with instanceId of the affected node to gather node-level logs
- Use `status` tool with executionId to poll until collection completes
- Use `errors` tool with instanceId and severity=high to get pre-indexed IAM/permission findings
- Use `search` tool with instanceId and query=`AccessDenied|is not authorized to perform|UnauthorizedAccess|Forbidden` to find permission errors across all log types

SHOULD:
- Use `search` tool with query=`ecr.*AccessDenied|pull.*denied|authorization failed` to check for ECR-specific permission failures
- Use `search` tool with query=`aws-node|ipamd|eni.*error` in CNI logs to check for VPC CNI permission failures

MAY:
- Use `cluster_health` tool with clusterName to check if multiple nodes have the same permission issue
- Use `search` tool with query=`cloud-init|bootstrap|userdata` to check node bootstrap for early permission failures

## Phase 2 — Enrich

MUST:
- Use `correlate` tool with instanceId and pivotEvent=`AccessDenied` to build timeline of permission failures
- Map the denied API action from findings to the required IAM policy:
  - ECR pull failures → AmazonEC2ContainerRegistryReadOnly
  - CNI failures → AmazonEKS_CNI_Policy
  - Registration failures → AmazonEKSWorkerNodePolicy
  - SSM failures → AmazonSSMManagedInstanceCore
- Use `search` tool with query=`instance profile|iam role|assume role` to check if instance profile is attached

SHOULD:
- Use `search` tool with query=`sts.*AssumeRole|credential|token` to check if the node can obtain credentials at all
- Use `errors` tool with severity=all to check if permission errors are intermittent or persistent

MAY:
- Use `search` tool with query=`SCP|service control policy|Organizations` to check for org-level restrictions
- Use EKS MCP `get_cloudwatch_logs` with clusterName, resource_type="cluster", log_type="control-plane", filter_pattern="access" to check for recent access entry changes or aws-auth ConfigMap mutations that may have removed the node role mapping
- Use EKS MCP `get_cloudwatch_logs` with clusterName, resource_type="cluster", log_type="control-plane", filter_pattern="certificatesigningrequests" to check for node CSR approval/denial events

## Phase 3 — Report

MUST:
- Use `summarize` tool with instanceId and finding_ids from permission-related findings to generate incident summary
- State root cause: specific missing IAM policy with the denied API action from findings
- Recommend adding the policy to the node role
- Operator action — not available via MCP tools: attach IAM policy to node role, verify instance profile

SHOULD:
- Include the specific AccessDenied error message from findings

MAY:
- Recommend managed node groups for automatic IAM configuration

## Guardrails

escalation_conditions:
  - "IAM policy changes require approval process"
  - "SCP blocking required permissions — found via search"
  - "Instance profile not attached to instance"

safety_ratings:
  - "Log collection (collect), search, errors, correlate, cluster_health: GREEN (read-only)"
  - "Attach IAM policy to node role: YELLOW — operator action, not available via MCP tools"
  - "Modify SCP: RED — operator action, requires security team approval"

## Common Issues

- symptoms: "errors tool returns findings with ECR image pull AccessDenied"
  diagnosis: "Node role missing AmazonEC2ContainerRegistryReadOnly. Use search with query=ecr.*AccessDenied to confirm."
  resolution: "Operator action: attach AmazonEC2ContainerRegistryReadOnly to node IAM role"

- symptoms: "search for aws-node returns VPC CNI AccessDenied errors"
  diagnosis: "Node role missing AmazonEKS_CNI_Policy. Use network_diagnostics to check CNI health."
  resolution: "Operator action: attach AmazonEKS_CNI_Policy to node IAM role (or use IRSA for CNI)"

- symptoms: "errors tool returns findings with node registration Unauthorized"
  diagnosis: "Node role missing AmazonEKSWorkerNodePolicy. Use search with query=bootstrap to check registration logs."
  resolution: "Operator action: attach AmazonEKSWorkerNodePolicy to node IAM role"

## Examples

```
# Step 1: Collect logs
collect(instanceId="i-0abc123def456")
# Step 2: Poll status
status(executionId="<id-from-step-1>")
# Step 3: Get permission findings
errors(instanceId="i-0abc123def456", severity="high")
# Step 4: Search for AccessDenied evidence
search(instanceId="i-0abc123def456", query="AccessDenied|is not authorized to perform|UnauthorizedAccess")
# Step 5: Correlate permission failure timeline
correlate(instanceId="i-0abc123def456", pivotEvent="AccessDenied", timeWindow=120)
# Step 6: Check cluster-wide impact
cluster_health(clusterName="my-cluster")
# Step 7: Generate summary
summarize(instanceId="i-0abc123def456", finding_ids=["F-001","F-002"])
```

## Output Format

```yaml
root_cause: "Missing IAM policy — <policy_name>"
evidence:
  - type: iam_finding
    content: "<AccessDenied finding from errors tool with denied action>"
  - type: correlation
    content: "<timeline from correlate showing permission failure pattern>"
severity: HIGH
mitigation:
  immediate: "Operator: attach <policy_name> to node IAM role"
  long_term: "Use managed node groups for automatic IAM setup"
```
