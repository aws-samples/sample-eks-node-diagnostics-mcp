---
title: "B1 — Kubelet Configuration Errors"
description: "Diagnose kubelet startup failures due to misconfiguration (cgroup driver mismatch, invalid config, wrong max-pods/dns-cluster-ip)"
status: active
severity: HIGH
triggers:
  - "misconfiguration: kubelet cgroup driver"
  - "failed to run Kubelet"
  - "invalid configuration"
  - "Failed to create cgroup"
owner: devops-agent
objective: "Identify the specific kubelet misconfiguration and restore kubelet to running state"
context: "Kubelet fails to start or crashes on startup due to configuration errors. Common causes include cgroup driver mismatch between kubelet and containerd, invalid config JSON, or wrong DNS/max-pods settings."
---

## Phase 1 — Triage

MUST:
- Use `collect` tool with instanceId to gather logs from the affected node
- Use `status` tool with executionId to poll until collection completes
- Use `errors` tool with instanceId to get pre-indexed findings — look for kubelet config errors
- Use `search` tool with instanceId and query=`failed to run Kubelet|invalid configuration|cgroup driver|Failed to create cgroup` to find config failure evidence

SHOULD:
- Use `search` tool with query=`kubelet.*config|config.json` and logTypes=`kubelet` to find kubelet configuration content in collected logs
- Use `search` tool with query=`SystemdCgroup|cgroupDriver` to check cgroup driver settings

MAY:
- Use `compare_nodes` tool with instanceIds of broken + healthy node to diff kubelet config findings
- Use `search` tool with query=`cloud-init|bootstrap` to check for bootstrap-time config errors

## Phase 2 — Enrich

MUST:
- Use `search` tool with query=`cgroup driver` to detect cgroup driver mismatch — both kubelet and containerd must use systemd
- Use `search` tool with query=`invalid configuration|parse error|json.*error` to detect config file parse errors
- Use `search` tool with query=`dns-cluster-ip|clusterDNS` to verify DNS IP matches service CIDR

SHOULD:
- Use `search` tool with query=`max-pods|maxPods` to check max-pods setting against instance type ENI limits
- Use `correlate` tool with instanceId to build timeline of kubelet startup attempts and failures

MAY:
- Use `compare_nodes` tool to compare config between broken and healthy nodes in the same node group

## Phase 3 — Report

MUST:
- Use `summarize` tool with instanceId and finding_ids from config-related findings
- State root cause: specific configuration error with evidence from findings
- Recommend fix: exact config change needed (operator action)
- Confirm kubelet should start successfully after fix

SHOULD:
- Include the offending config line from search results
- Provide corrected config snippet

MAY:
- Recommend managed node groups to avoid manual kubelet config

## Guardrails

escalation_conditions:
  - "Kubelet fails to start after config correction"
  - "Config file is managed by automation and cannot be manually edited"
  - "Multiple nodes in the node group have the same misconfiguration"

safety_ratings:
  - "Log collection (collect), search, errors, correlate: GREEN (read-only)"
  - "Edit kubelet config: YELLOW — operator action, not available via MCP tools"
  - "Restart kubelet: YELLOW — operator action, not available via MCP tools"

## Common Issues

- symptoms: "search for cgroup driver returns mismatch between kubelet and containerd"
  diagnosis: "Kubelet and containerd using different cgroup drivers"
  resolution: "Operator action: ensure both use systemd. Set SystemdCgroup=true in containerd config and cgroupDriver: systemd in kubelet config."

- symptoms: "search for dns-cluster-ip shows wrong value"
  diagnosis: "dns-cluster-ip does not match service CIDR"
  resolution: "Operator action: set --dns-cluster-ip to match kube-dns ClusterIP (usually 10.100.0.10 or 172.20.0.10)"

## Examples

```
# Step 1: Collect logs
collect(instanceId="i-0abc123def456")
# Step 2: Get config-related findings
errors(instanceId="i-0abc123def456")
# Step 3: Search for specific config errors
search(instanceId="i-0abc123def456", query="cgroup driver|invalid configuration|failed to run Kubelet")
# Step 4: Check cgroup settings
search(instanceId="i-0abc123def456", query="SystemdCgroup|cgroupDriver")
```

## Output Format

```yaml
root_cause: "<cgroup_mismatch|invalid_config|wrong_dns_ip> — <detail>"
evidence:
  - type: finding
    content: "<kubelet error finding>"
  - type: config_search
    content: "<offending config value from search>"
severity: HIGH
mitigation:
  immediate: "Operator: fix config and restart kubelet"
  long_term: "Use managed node groups for automatic kubelet configuration"
```
