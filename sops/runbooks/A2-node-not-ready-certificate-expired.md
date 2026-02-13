---
title: "A2-cert — Node NotReady Due to Expired Certificate"
description: "Diagnose node NotReady caused by expired kubelet serving or client certificate"
status: active
severity: HIGH
triggers:
  - "x509: certificate has expired"
  - "certificate.*expired"
  - "TLS handshake error"
owner: devops-agent
objective: "Confirm certificate expiry as root cause and restore node TLS communication"
context: "Kubelet uses client certificates to authenticate with the API server. If certificates expire and auto-rotation fails, the node loses communication and transitions to NotReady."
---

## Phase 1 — Triage

MUST:
- Use `collect` tool with instanceId to gather logs from the affected node
- Use `status` tool with executionId to poll until collection completes
- Use `errors` tool with instanceId to get pre-indexed findings — look for x509 or certificate errors
- Use `search` tool with instanceId and query=`x509.*expired|certificate has expired|TLS handshake error` to find certificate failure evidence

SHOULD:
- Use `search` tool with query=`rotateCertificates|certificate rotation` to check if rotation is enabled in kubelet config
- Use `search` tool with query=`kubelet-client-current.pem|kubelet.pem` to find certificate file references

MAY:
- Use `cluster_health` tool with clusterName to check if multiple nodes have the same issue

## Phase 2 — Enrich

MUST:
- Use `correlate` tool with instanceId and pivotEvent=`x509` to build timeline around certificate failure
- Confirm certificate expiry by reviewing findings from `errors` tool for x509 messages with dates
- Use `search` tool with query=`rotateCertificates` to verify if kubelet certificate rotation is enabled

SHOULD:
- Use `search` tool with query=`clock|time|chrony|ntp` to check if clock skew is causing false expiry (see A3-clock-skew SOP)
- Use `search` tool with query=`CSR|CertificateSigningRequest` to check for pending CSR approval issues

MAY:
- Use `compare_nodes` tool to compare certificate-related findings between affected and healthy nodes

## Phase 3 — Report

MUST:
- Use `summarize` tool with instanceId and finding_ids from certificate-related findings
- State root cause: certificate expired with expiry date evidence from findings
- Recommend fix: operator should restart kubelet to trigger certificate rotation, or manually approve CSR
- List blast radius

SHOULD:
- Include certificate expiry evidence from search results
- Verify rotateCertificates setting from search results

MAY:
- Recommend monitoring certificate expiry dates

## Guardrails

escalation_conditions:
  - "Certificate rotation enabled but CSR not auto-approved"
  - "Multiple nodes with expired certificates simultaneously"
  - "Kubelet restart does not trigger new CSR"

safety_ratings:
  - "Log collection (collect), search, errors, correlate: GREEN (read-only)"
  - "Restart kubelet: YELLOW — operator action, not available via MCP tools"
  - "Approve CSR: YELLOW — operator action, not available via MCP tools"

## Common Issues

- symptoms: "errors tool returns findings with x509: certificate has expired"
  diagnosis: "Kubelet client certificate expired and rotation did not occur"
  resolution: "Operator action: restart kubelet to trigger CSR. If CSR pending, approve via kubectl certificate approve"

- symptoms: "search for rotateCertificates returns false or no matches"
  diagnosis: "Certificate rotation not enabled in kubelet config"
  resolution: "Operator action: set rotateCertificates: true in kubelet config and restart kubelet"

## Examples

```
# Step 1: Collect logs
collect(instanceId="i-0abc123def456")
# Step 2: Get certificate-related findings
errors(instanceId="i-0abc123def456", severity="critical")
# Step 3: Search for certificate errors
search(instanceId="i-0abc123def456", query="x509.*expired|certificate has expired")
# Step 4: Check rotation config
search(instanceId="i-0abc123def456", query="rotateCertificates")
```

## Output Format

```yaml
root_cause: "Kubelet certificate expired"
evidence:
  - type: finding
    content: "<x509 error finding with expiry date>"
  - type: config_search
    content: "<rotateCertificates setting>"
severity: HIGH
mitigation:
  immediate: "Operator: restart kubelet to trigger certificate rotation"
  long_term: "Ensure rotateCertificates: true in kubelet config"
```
