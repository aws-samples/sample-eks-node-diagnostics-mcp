---
title: "H2 — IRSA / Pod Identity Confusion"
description: "Diagnose AWS API AccessDenied errors caused by IRSA or Pod Identity misconfiguration"
status: active
severity: HIGH
triggers:
  - "AccessDenied.*AssumeRoleWithWebIdentity"
  - "ExpiredTokenException"
  - "InvalidIdentityToken"
  - "No OpenIDConnect provider found"
owner: devops-agent
objective: "Identify the IRSA or Pod Identity misconfiguration and restore AWS API access from pods"
context: "Pods use IRSA (IAM Roles for Service Accounts) or EKS Pod Identity to assume IAM roles for AWS API access. Misconfigurations in ServiceAccount annotations, OIDC provider, trust policies, or Pod Identity associations cause AccessDenied errors."
---

## Phase 1 — Triage

FIRST — Check pod state before collecting logs:
- Use `list_k8s_resources` with clusterName, kind=Pod, apiVersion=v1, namespace=<namespace> to list pods in the affected namespace — check for pods in CrashLoopBackOff or Error state due to credential failures
- Use `read_k8s_resource` with clusterName, kind=Pod, apiVersion=v1, namespace=<namespace>, name=<pod-name> to get detailed pod spec — check serviceAccountName, projected volume mounts for token, and container status/restart count
- Use `read_k8s_resource` with clusterName, kind=ServiceAccount, apiVersion=v1, namespace=<namespace>, name=<sa-name> to check ServiceAccount annotations for eks.amazonaws.com/role-arn
- Use `get_k8s_events` with clusterName, kind=Pod, namespace=<namespace>, name=<pod-name> to check for credential-related warning events

MUST:
- Use `collect` tool with instanceId of the node running the affected pod to gather node-level logs
- Use `status` tool with executionId to poll until collection completes
- Use `errors` tool with instanceId and severity=high to get pre-indexed IRSA/credential findings
- Use `search` tool with instanceId and query=`AccessDenied.*AssumeRoleWithWebIdentity|ExpiredTokenException|InvalidIdentityToken|No OpenIDConnect provider` to find IRSA errors

SHOULD:
- Use `search` tool with query=`eks.amazonaws.com/role-arn|service-account|projected.*token` to check ServiceAccount configuration evidence in kubelet logs
- Use `search` tool with query=`AWS_ROLE_ARN|AWS_WEB_IDENTITY_TOKEN_FILE|EKS_POD_IDENTITY` to check pod environment variable injection

MAY:
- Use `cluster_health` tool with clusterName to check if OIDC provider is configured for the cluster
- Use `search` tool with query=`pod-identity-agent|pod identity association` to check Pod Identity agent status

## Phase 2 — Enrich

MUST:
- Use `correlate` tool with instanceId and pivotEvent=`AccessDenied` to build timeline of credential failures
- Review findings from `errors` tool to classify the failure:
  - If "AssumeRoleWithWebIdentity" denied: SA annotation missing or trust policy mismatch
  - If "No OpenIDConnect provider found": OIDC provider not created for cluster
  - If "InvalidIdentityToken": trust policy condition has wrong namespace/SA
  - If "ExpiredTokenException": token expiration or projected volume mount issue
- Use `search` tool with query=`sts.*AssumeRole|oidc|web-identity` to find the specific API call that failed

SHOULD:
- Use `search` tool with query=`audience|sts.amazonaws.com` to check token audience configuration
- Use `search` tool with query=`pod-identity|EKS_POD_IDENTITY_AGENT` to determine if Pod Identity is in use vs IRSA

MAY:
- Use `search` tool with query=`token.*expir|token.*refresh` to check for intermittent token expiration failures
- Use EKS MCP `get_cloudwatch_logs` with clusterName, resource_type="cluster", log_type="control-plane", filter_pattern="ServiceAccount" to check for recent ServiceAccount mutations (annotation changes, deletions) that may have broken IRSA bindings
- Use EKS MCP `get_cloudwatch_logs` with clusterName, resource_type="cluster", log_type="control-plane", filter_pattern="podidentityassociation" to check for Pod Identity association create/update/delete events

## Phase 3 — Report

MUST:
- Use `summarize` tool with instanceId and finding_ids from IRSA/credential findings to generate incident summary
- State root cause: specific IRSA/Pod Identity misconfiguration with evidence from findings
- Recommend targeted fix based on root cause classification
- Operator action — not available via MCP tools: annotate ServiceAccount, create OIDC provider, update IAM trust policy, create Pod Identity association

SHOULD:
- Include the specific error message from findings
- Include SA annotation and trust policy details from search results

MAY:
- Recommend migrating from IRSA to Pod Identity for simpler management

## Guardrails

escalation_conditions:
  - "OIDC provider creation requires cluster admin access"
  - "IAM role trust policy changes require security team approval"
  - "Multiple services affected by the same IRSA misconfiguration — check via cluster_health"

safety_ratings:
  - "Log collection (collect), search, errors, correlate, cluster_health: GREEN (read-only)"
  - "Annotate ServiceAccount: YELLOW — operator action, not available via MCP tools"
  - "Create OIDC provider: YELLOW — operator action, not available via MCP tools"
  - "Modify IAM trust policy: RED — operator action, requires security team approval"

## Common Issues

- symptoms: "errors tool returns findings with AccessDenied AssumeRoleWithWebIdentity"
  diagnosis: "ServiceAccount not annotated with IAM role ARN. Use search with query=eks.amazonaws.com/role-arn to confirm."
  resolution: "Operator action: kubectl annotate sa <sa> -n <ns> eks.amazonaws.com/role-arn=<role-arn>"

- symptoms: "search returns No OpenIDConnect provider found"
  diagnosis: "OIDC provider not created for the cluster. Use cluster_health to check cluster configuration."
  resolution: "Operator action: eksctl utils associate-iam-oidc-provider --cluster <name> --approve"

- symptoms: "search returns InvalidIdentityToken"
  diagnosis: "Trust policy condition has wrong namespace or service account name."
  resolution: "Operator action: update IAM role trust policy to include correct OIDC issuer and conditions"

- symptoms: "errors tool returns findings with ExpiredTokenException"
  diagnosis: "Projected service account token expired or not mounted. Use search with query=token.*expir to check."
  resolution: "Operator action: check token expiration settings, verify projected volume mount in pod spec"

## Examples

```
# Step 1: Collect logs from node running affected pod
collect(instanceId="i-0abc123def456")
# Step 2: Poll status
status(executionId="<id-from-step-1>")
# Step 3: Get IRSA/credential findings
errors(instanceId="i-0abc123def456", severity="high")
# Step 4: Search for IRSA errors
search(instanceId="i-0abc123def456", query="AccessDenied.*AssumeRoleWithWebIdentity|InvalidIdentityToken|ExpiredTokenException")
# Step 5: Check SA configuration evidence
search(instanceId="i-0abc123def456", query="eks.amazonaws.com/role-arn|AWS_ROLE_ARN|AWS_WEB_IDENTITY_TOKEN_FILE")
# Step 6: Correlate credential failure timeline
correlate(instanceId="i-0abc123def456", pivotEvent="AccessDenied", timeWindow=120)
# Step 7: Generate summary
summarize(instanceId="i-0abc123def456", finding_ids=["F-001","F-002"])
```

## Output Format

```yaml
root_cause: "<irsa_annotation|oidc_provider|trust_policy|pod_identity> — <detail>"
evidence:
  - type: credential_finding
    content: "<AccessDenied finding from errors tool>"
  - type: sa_config
    content: "<ServiceAccount configuration from search results>"
severity: HIGH
mitigation:
  immediate: "Operator: <specific fix based on root cause>"
  long_term: "Migrate to Pod Identity, use Terraform/CDK for SA-Role bindings"
```