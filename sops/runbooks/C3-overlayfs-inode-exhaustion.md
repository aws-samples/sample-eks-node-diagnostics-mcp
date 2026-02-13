# SOP: C3 — OverlayFS / Inode Exhaustion

## Failure Mode ID: `C3` | Severity: HIGH | Blast Radius: node

## Symptoms
`no space left on device` errors despite df showing available space; DiskPressure condition.

## Required Evidence
| Artifact | Source |
|----------|--------|
| `storage/inodes.txt` (df --inodes) | SSM RunCommand |
| `storage/mounts.txt` | SSM RunCommand |
| `storage/pod_local_storage.txt` | SSM RunCommand |

## Detection Patterns
```
Pattern: no space left on device
IUse% at 100% in inodes.txt
```

## Decision Logic
- If disk space available but inodes exhausted → too many small files (container layers or log rotation failures)

## Mitigations
- **Immediate**: Clean up stopped containers: `crictl rm $(crictl ps -a -q --state exited)`
- **Long-term**: Increase root volume, configure image GC thresholds

## References
- https://kubernetes.io/docs/concepts/scheduling-eviction/node-pressure-eviction/
