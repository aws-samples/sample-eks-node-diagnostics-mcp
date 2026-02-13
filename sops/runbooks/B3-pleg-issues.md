---
title: "B3 — PLEG (Pod Lifecycle Event Generator) Issues"
description: "Diagnose node NotReady caused by PLEG health check failures"
status: active
severity: HIGH
triggers:
  - "PLEG is not healthy"
  - "pleg was last seen active.*ago"
  - "GenericPLEG.*relisting"
owner: devops-agent
objective: "Identify why PLEG is unhealthy and restore node stability"
context: "PLEG monitors pod lifecycle events by periodically relisting all containers. When containerd is slow or overloaded, PLEG relisting takes too long and kubelet reports the node as NotReady."
---

## Phase 1 — Triage

MUST:
- Use `collect` tool with instanceId to gather logs from the affected node
- Use `status` tool with executionId to poll until collection completes
- Use `errors` tool with instanceId to get pre-indexed findings — look for PLEG health check failures
- Use `search` tool with instanceId and query=`PLEG is not healthy|PLEG.*relisting|pleg was last seen` to find PLEG failure evidence

SHOULD:
- Use `search` tool with query=`containerd.*slow|containerd.*timeout|containerd.*error` and logTypes=`containerd` to check containerd health
- Use `storage_diagnostics` tool with instanceId to check if slow disk I/O is causing containerd slowness

MAY:
- Use `cluster_health` tool with clusterName to check if multiple nodes show PLEG issues
- Use `search` tool with query=`crictl|container.*count` to estimate container density on the node

## Phase 2 — Enrich

MUST:
- Use `correlate` tool with instanceId and pivotEvent=`PLEG` to correlate PLEG unhealthy events with containerd latency
- Use `search` tool with query=`containerd` and logTypes=`containerd` to find slow operations or errors in containerd logs
- Use `errors` tool with severity=all to get full picture of node health issues

SHOULD:
- Use `storage_diagnostics` tool with instanceId and sections=kubelet to check if disk I/O latency is elevated
- Use `search` tool with query=`container.*create|container.*start|container.*stop` to assess pod churn rate

MAY:
- Use `compare_nodes` tool to compare PLEG-related findings between affected and healthy nodes

## Phase 3 — Report

MUST:
- Use `summarize` tool with instanceId and finding_ids from PLEG-related findings
- State root cause: PLEG unhealthy due to containerd overload, disk I/O, or high pod density
- Recommend mitigation based on root cause (operator action)
- Confirm node should return to Ready after remediation

SHOULD:
- Include PLEG timing evidence from search results
- Include containerd latency evidence from findings

MAY:
- Recommend spreading workloads across more nodes

## Guardrails

escalation_conditions:
  - "PLEG unhealthy persists after containerd restart"
  - "Multiple nodes showing PLEG issues simultaneously"
  - "Disk I/O latency consistently >100ms (from storage_diagnostics)"

safety_ratings:
  - "Log collection (collect), search, errors, correlate, storage_diagnostics: GREEN (read-only)"
  - "Restart containerd: YELLOW — operator action, not available via MCP tools"
  - "Drain node: YELLOW — operator action, not available via MCP tools"

## Common Issues

- symptoms: "errors tool returns PLEG unhealthy findings, search shows containerd slow to respond"
  diagnosis: "Containerd overloaded by high pod density or slow disk"
  resolution: "Operator action: reduce pod count on node, check disk I/O, consider larger instance type with faster storage"

- symptoms: "PLEG unhealthy findings correlate with high pod churn in correlate timeline"
  diagnosis: "Rapid pod creation/deletion overwhelming container runtime"
  resolution: "Operator action: reduce deployment rollout speed, spread across more nodes"

## Examples

```
# Step 1: Collect logs
collect(instanceId="i-0abc123def456")
# Step 2: Get PLEG findings
errors(instanceId="i-0abc123def456")
# Step 3: Search for PLEG evidence
search(instanceId="i-0abc123def456", query="PLEG is not healthy|PLEG.*relisting")
# Step 4: Check containerd
search(instanceId="i-0abc123def456", query="containerd.*slow|containerd.*timeout", logTypes="containerd")
# Step 5: Correlate
correlate(instanceId="i-0abc123def456", pivotEvent="PLEG", timeWindow=120)
```

## Output Format

```yaml
root_cause: "PLEG unhealthy — <containerd_overload|disk_io|high_pod_density>"
evidence:
  - type: finding
    content: "<PLEG health check failure finding>"
  - type: containerd_search
    content: "<containerd latency evidence>"
severity: HIGH
mitigation:
  immediate: "Operator: reduce pod churn, check containerd health"
  long_term: "Increase node resources, spread workloads"
```
