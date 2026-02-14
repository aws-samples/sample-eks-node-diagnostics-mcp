---
title: "D5 — DNS Failures from Pods"
description: "Diagnose DNS resolution failures affecting pod workloads"
status: active
severity: HIGH
triggers:
  - "UnknownHostException"
  - "Could not resolve host"
  - "SERVFAIL"
  - "linklocal_allowance_exceeded"
owner: devops-agent
objective: "Identify the DNS failure root cause and restore name resolution"
context: "Pod DNS failures can stem from CoreDNS overload, VPC DNS throttling (1024 PPS per ENI), ENA linklocal allowance exceeded, incorrect resolv.conf, ndots:5 amplification, or network policies blocking UDP 53."
---

## Phase 1 — Triage

MUST:
- **FIRST**: Check pod and node state before any log collection:
  - List pods in the affected namespace: `kubectl get pods -n <namespace> -o wide` (via EKS MCP `list_k8s_resources`)
  - Verify the affected pod is Running and Ready — DNS failures in a non-running pod are a symptom, not the cause
  - Check CoreDNS pods: `kubectl get pods -n kube-system -l k8s-app=kube-dns` (via EKS MCP `list_k8s_resources`) — if CoreDNS pods are not Running, that is the root cause
  - Check node conditions: `kubectl get nodes` (via EKS MCP `list_k8s_resources` kind=Node) — NotReady nodes cannot reach CoreDNS
- Use `collect` tool with instanceId to gather logs from the affected node
- Use `status` tool with executionId to poll until collection completes
- Use `errors` tool with instanceId to get pre-indexed findings — look for DNS errors
- Use `network_diagnostics` tool with instanceId and sections=dns to get DNS configuration from collected logs

SHOULD:
- Use `search` tool with instanceId and query=`UnknownHostException|Could not resolve|SERVFAIL|linklocal_allowance_exceeded` to find DNS failure evidence
- Use `search` tool with query=`resolv.conf|nameserver|ndots` to check DNS configuration

MAY:
- Use `search` tool with query=`ethtool.*linklocal|linklocal_allowance` to check ENA linklocal counters
- Use `cluster_health` tool with clusterName to check if DNS failures are cluster-wide

## Phase 2 — Enrich

MUST:
- Review `network_diagnostics` dns section for resolv.conf configuration and DNS issues
- Use `search` tool with query=`linklocal_allowance_exceeded` — if found, PPS throttling to VPC DNS (recommend NodeLocal DNSCache)
- Use `search` tool with query=`nameserver` in resolv.conf — if not kube-dns ClusterIP, bootstrap misconfiguration
- Use `search` tool with query=`CoreDNS|coredns.*error|coredns.*CrashLoop` to check CoreDNS health

SHOULD:
- Use `correlate` tool with instanceId and pivotEvent=`DNS|resolve` to correlate DNS failures with other events
- Use `search` tool with query=`ndots` to check ndots setting (ndots:5 causes 4x query amplification)

MAY:
- Use `network_diagnostics` with sections=iptables to check for rules blocking UDP 53
- Use EKS MCP `get_cloudwatch_logs` with clusterName, resource_type="cluster", log_type="control-plane", filter_pattern="coredns" to check for recent CoreDNS ConfigMap changes (Corefile edits, plugin changes) that may have broken DNS
- Use EKS MCP `get_cloudwatch_logs` with clusterName, resource_type="cluster", log_type="control-plane", filter_pattern="NetworkPolicy" to check for NetworkPolicy changes that may be blocking UDP 53 to CoreDNS pods

## Phase 3 — Report

MUST:
- Use `summarize` tool with instanceId and finding_ids from DNS-related findings
- State root cause: specific DNS failure mechanism with evidence
- Recommend targeted fix (operator action)
- Confirm DNS resolution should be restored after fix

SHOULD:
- Include linklocal counter values or CoreDNS error evidence from search results
- Recommend NodeLocal DNSCache if PPS throttling detected

MAY:
- Recommend reducing ndots in pod spec for external-heavy workloads

## Guardrails

escalation_conditions:
  - "CoreDNS pods CrashLooping and cannot be restarted"
  - "VPC DNS throttling affecting all nodes"
  - "DNS failures causing cascading application failures"

safety_ratings:
  - "Log collection (collect), search, errors, network_diagnostics: GREEN (read-only)"
  - "Deploy NodeLocal DNSCache, modify CoreDNS: YELLOW — operator action, not available via MCP tools"

## Common Issues

- symptoms: "search returns linklocal_allowance_exceeded > 0"
  diagnosis: "PPS throttling to VPC DNS (169.254.169.253)"
  resolution: "Operator action: deploy NodeLocal DNSCache to reduce VPC DNS queries"

- symptoms: "network_diagnostics dns section shows wrong nameserver IP in resolv.conf"
  diagnosis: "Bootstrap misconfiguration — dns-cluster-ip wrong"
  resolution: "Operator action: fix --dns-cluster-ip in kubelet config to match kube-dns ClusterIP"

- symptoms: "search returns CoreDNS CrashLooping"
  diagnosis: "CoreDNS resource exhaustion or configuration error"
  resolution: "Operator action: scale CoreDNS replicas, increase memory limits, check Corefile"

## Examples

```
# Step 1: Collect logs
collect(instanceId="i-0abc123def456")
# Step 2: Get DNS diagnostics
network_diagnostics(instanceId="i-0abc123def456", sections="dns")
# Step 3: Get DNS-related findings
errors(instanceId="i-0abc123def456")
# Step 4: Search for DNS failures
search(instanceId="i-0abc123def456", query="linklocal_allowance_exceeded|Could not resolve|SERVFAIL")
```

## Output Format

```yaml
root_cause: "<pps_throttling|coredns_overload|config_error|network_policy> — <detail>"
evidence:
  - type: network_diagnostics
    content: "<DNS configuration from dns section>"
  - type: finding
    content: "<DNS error finding>"
severity: HIGH
mitigation:
  immediate: "Operator: <specific fix>"
  long_term: "Deploy NodeLocal DNSCache, reduce ndots, monitor DNS metrics"
```
