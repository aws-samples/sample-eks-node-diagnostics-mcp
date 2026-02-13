---
title: "J2 — EBS Transient Attach/Detach Failures"
description: "Diagnose pods stuck due to EBS volume attach timeouts, stale attachments, or multi-attach errors"
status: active
severity: HIGH
triggers:
  - "AttachVolume.*timed out"
  - "Multi-Attach error"
  - "volume is already.*attached"
  - "FailedAttachVolume"
  - "WaitForAttach.*timeout"
owner: devops-agent
objective: "Identify the EBS attach failure reason and restore volume access"
context: "EBS volumes can get stuck in attaching state, remain attached to terminated nodes, or fail due to AZ mismatch. Multi-attach errors occur when a volume is still attached to a previous node."
---

## Phase 1 — Triage

MUST:
- Use `collect` tool with instanceId of the affected node to gather node-level logs
- Use `status` tool with executionId to poll until collection completes
- Use `errors` tool with instanceId and severity=high to get pre-indexed EBS attach/detach findings
- Use `search` tool with instanceId and query=`AttachVolume.*timed out|Multi-Attach error|volume is already.*attached|FailedAttachVolume|WaitForAttach.*timeout` to find EBS attach failure evidence
- Use `storage_diagnostics` tool with instanceId and sections=ebs_csi,pv_pvc to check EBS CSI driver status and PV/PVC state

SHOULD:
- Use `search` tool with query=`ebs-csi|csi-driver|csi-node` to check CSI driver pod health
- Use `search` tool with query=`VolumeAttachment|volume attachment|attach.*vol-` to find volume attachment details

MAY:
- Use `cluster_health` tool with clusterName to check if EBS CSI driver is healthy cluster-wide
- Use `search` tool with query=`throttl|API.*rate|TooManyRequests` to check for AWS API throttling on attach/detach calls

## Phase 2 — Enrich

MUST:
- Use `correlate` tool with instanceId and pivotEvent=`AttachVolume` to build timeline of attach failures
- Review findings from `errors` tool and `storage_diagnostics` to classify the failure:
  - If volume "in-use" but attached to different node: stale attachment from previous pod
  - If volume AZ != node AZ: AZ mismatch — volume cannot cross AZs
  - If max volumes per instance reached: instance volume limit hit
  - If ebs-csi-node pod not running: CSI driver issue
- Use `search` tool with query=`vol-.*state|volume.*status|in-use|available|attaching` to find volume state details

SHOULD:
- Use `search` tool with query=`terminated|terminating|previous pod|graceful` to check if previous pod fully terminated
- Use `search` tool with query=`WaitForFirstConsumer|volumeBindingMode|StorageClass` to check StorageClass configuration

MAY:
- Use `compare_nodes` tool to check if EBS attach issues affect specific nodes or are cluster-wide

## Phase 3 — Report

MUST:
- Use `summarize` tool with instanceId and finding_ids from EBS-related findings to generate incident summary
- State root cause: specific attach failure with volume and node details from findings and storage_diagnostics
- Recommend fix based on root cause classification
- Operator action — not available via MCP tools: force detach volume (with data corruption warning), reschedule pod, fix CSI driver

SHOULD:
- Include volume ID, state, and attachment details from findings
- Warn about data corruption risk for force detach operations

MAY:
- Recommend WaitForFirstConsumer binding mode for topology-aware provisioning

## Guardrails

escalation_conditions:
  - "Force detach needed on actively-written volume (data corruption risk)"
  - "Volume stuck in attaching state for >10 minutes — check via storage_diagnostics"
  - "CSI driver pods not running on any node — check via cluster_health"

safety_ratings:
  - "Log collection (collect), search, errors, storage_diagnostics, correlate: GREEN (read-only)"
  - "Force detach volume: RED — operator action, data corruption risk, requires approval"
  - "Reschedule pod to correct AZ: YELLOW — operator action, not available via MCP tools"
  - "Restart CSI driver pods: YELLOW — operator action, not available via MCP tools"

## Common Issues

- symptoms: "errors tool returns findings with AttachVolume timed out, storage_diagnostics shows volume attached to different node"
  diagnosis: "Stale attachment from previous pod that did not fully terminate. Use search with query=terminated to check."
  resolution: "Operator action: wait for GC, or force detach — aws ec2 detach-volume --volume-id <vol-id> --force (data corruption risk)"

- symptoms: "search returns volume AZ does not match node AZ"
  diagnosis: "EBS volumes cannot cross AZs. Use storage_diagnostics to confirm AZ mismatch."
  resolution: "Operator action: reschedule pod to correct AZ or create new volume in target AZ"

- symptoms: "errors tool returns FailedAttachVolume with max volumes reached"
  diagnosis: "Instance volume attachment limit hit. Use storage_diagnostics to confirm volume count."
  resolution: "Operator action: move pods to nodes with available volume slots"

- symptoms: "storage_diagnostics shows ebs-csi-node pod not running"
  diagnosis: "CSI driver issue — ebs-csi-node DaemonSet pod not healthy."
  resolution: "Operator action: restart ebs-csi-node pod, check CSI driver DaemonSet status"

## Examples

```
# Step 1: Collect logs
collect(instanceId="i-0abc123def456")
# Step 2: Poll status
status(executionId="<id-from-step-1>")
# Step 3: Get EBS attach findings
errors(instanceId="i-0abc123def456", severity="high")
# Step 4: Check EBS CSI and PV/PVC status
storage_diagnostics(instanceId="i-0abc123def456", sections="ebs_csi,pv_pvc")
# Step 5: Search for attach failure evidence
search(instanceId="i-0abc123def456", query="AttachVolume.*timed out|Multi-Attach error|FailedAttachVolume")
# Step 6: Correlate attach failure timeline
correlate(instanceId="i-0abc123def456", pivotEvent="AttachVolume", timeWindow=120)
# Step 7: Generate summary
summarize(instanceId="i-0abc123def456", finding_ids=["F-001","F-002"])
```

## Output Format

```yaml
root_cause: "<stale_attach|az_mismatch|volume_limit|csi_driver> — <detail>"
evidence:
  - type: storage_diagnostics
    content: "<EBS volume state and attachment from storage_diagnostics>"
  - type: attach_finding
    content: "<attach failure finding from errors tool>"
severity: HIGH
mitigation:
  immediate: "Operator: <specific fix based on root cause>"
  long_term: "Use WaitForFirstConsumer, topology-aware provisioning"
```