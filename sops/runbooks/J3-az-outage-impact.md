---
title: "J3 — Availability Zone Outage Impact"
description: "Diagnose and respond to multiple node failures caused by AZ-level infrastructure issues"
status: active
severity: CRITICAL
triggers:
  - "NodeNotReady.*multiple nodes.*same AZ"
  - "aws health.*operational issue"
  - "VolumeAttachmentTimeout.*multiple"
owner: devops-agent
objective: "Confirm AZ-level impact, ensure workloads reschedule to healthy AZs, and minimize service disruption"
context: "When an AWS Availability Zone experiences degradation, multiple nodes in that AZ become NotReady simultaneously. Pods enter Unknown/Terminating state, and EBS volumes in the affected AZ become unavailable."
---

## Phase 1 — Triage

MUST:
- Check node AZ distribution: `kubectl get nodes -L topology.kubernetes.io/zone`
- Identify NotReady nodes: `kubectl get nodes`
- Check AWS Health Dashboard for AZ events
- Check pod distribution: `kubectl get pods -A -o wide`

SHOULD:
- Check EBS volume status in affected AZ: `aws ec2 describe-volume-status`
- Check AWS Health events: `aws health describe-events --filter eventTypeCategories=issue`

MAY:
- Check if PodDisruptionBudgets are blocking rescheduling

## Phase 2 — Enrich

MUST:
- Confirm multiple NotReady nodes are all in the same AZ
- Check AWS Health Dashboard for AZ-level operational issues
- Verify pods are rescheduling to other AZs
- Check if StatefulSets with AZ-pinned volumes are stuck

SHOULD:
- Check PDB configuration for affected workloads
- Verify topology spread constraints are configured

MAY:
- Check if EBS volumes in affected AZ are showing errors

## Phase 3 — Report

MUST:
- State root cause: AZ-level degradation with affected AZ and node count
- Confirm workloads rescheduled to healthy AZs
- List any stuck workloads (StatefulSets, PDB-blocked)
- Recommend long-term multi-AZ resilience improvements

SHOULD:
- Include node distribution by AZ
- Include AWS Health event details

MAY:
- Recommend topology spread constraints
- Recommend multi-AZ EBS replication for critical data

## Guardrails

escalation_conditions:
  - "Single-AZ cluster with no redundancy"
  - "PDB blocking all pod rescheduling"
  - "StatefulSets with AZ-pinned volumes stuck indefinitely"
  - "AWS Health Dashboard shows no event but AZ nodes are down"

## Common Issues

- symptoms: "Multiple nodes NotReady, all in same AZ"
  diagnosis: "AZ-level infrastructure degradation"
  resolution: "Cordon affected nodes. Verify pods rescheduling to healthy AZs. Check AWS Health Dashboard."

- symptoms: "PDB blocking eviction of pods from affected AZ"
  diagnosis: "PDB too restrictive for AZ failure scenario"
  resolution: "Temporarily relax PDB if service is degraded. Set maxUnavailable >= 33% for AZ tolerance."

- symptoms: "StatefulSets stuck, EBS volumes in affected AZ"
  diagnosis: "EBS volumes cannot move across AZs"
  resolution: "Wait for AZ recovery, or restore from snapshot in healthy AZ (data loss risk)"

## Output Format

```yaml
root_cause: "AZ outage — <az-id> affecting <N> nodes"
evidence:
  - type: nodes
    content: "<NotReady nodes and their AZ>"
  - type: aws_health
    content: "<health event details>"
blast_radius: "<N> nodes, <M> pods affected"
severity: CRITICAL
mitigation:
  immediate: "Cordon affected nodes, verify pod rescheduling"
  long_term: "Deploy across 3+ AZs, configure topology spread constraints"
```
