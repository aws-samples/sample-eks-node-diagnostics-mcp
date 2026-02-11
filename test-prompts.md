# MCP Tool Test Prompts

Natural DevOps questions — each one exercises a specific MCP tool.
Copy-paste into the DevOps agent one at a time.

Cluster: arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster

## Node Reference
| Node | Instance ID | Fault Type |
|------|------------|------------|
| 1 | i-0f2c36ed3c6441131 | OOM kills + memory pressure |
| 2 | i-07b1807d7f5b67fd2 | Volume mount failures |
| 3 | i-066b6285d77f63954 | CNI/IPAMD IP exhaustion |
| 4 | i-0cdd62ca87b93aa86 | Image pull failures |
| 5 | i-021c69a6c01051590 | DNS + network timeouts |
| 6 | i-0441d2643ac9718f8 | Probe failures + crashloop |

---

## 1. Cluster overview (→ cluster_health)

```
We're seeing random pod failures across arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster. Can you give me a health check of the whole cluster — how many nodes are up, any unhealthy ones, SSM connectivity, and which AZs are affected?
```

## 2. Smart batch triage (→ batch_collect dryRun)

```
I suspect multiple nodes in arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster are having issues. Before collecting logs from everything, can you preview which unhealthy nodes you'd sample and how they group by failure type? Don't actually collect yet, just show me the plan.
```

## 3. Collect logs from a node (→ collect + status)

```
Node i-0cdd62ca87b93aa86 in arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster is showing ImagePullBackOff on several pods. Grab the node logs and let me know when the collection finishes.
```

## 4. Check multiple collections (→ batch_status)

```
I kicked off log collections on arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster earlier. Can you check if these are all done: 8e4ccb28-6b1a-4a85-8ab7-296b1b19323f, 69ad552f-11c8-44a8-8e60-cad23810f31e, 8e230d3e-cc84-422d-8011-970a0b73bc35? Which ones succeeded?
```

## 5. Verify bundle completeness (→ validate)

```
I collected logs from i-0441d2643ac9718f8 on arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster but I'm not sure the bundle is complete. Can you check if all the expected files are there — kubelet, containerd, dmesg, networking configs, ipamd?
```

## 6. What's wrong with this node? (→ errors)

```
Node i-0f2c36ed3c6441131 on arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster seems to be killing pods. What errors are in its logs? Show me the critical and warning findings.
```

## 7. Show me the actual log lines (→ read)

```
I see crash loop errors on i-0441d2643ac9718f8 in arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster. Can you show me the kubelet log around lines 480-520 where the restarts are happening? I want to see the raw log entries.
```

## 8. Find DNS failures (→ search)

```
Node i-021c69a6c01051590 on arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster has pods that can't resolve DNS. Search its logs for anything matching NXDOMAIN, SERVFAIL, or DNS timeout patterns. What's going on?
```

## 9. Timeline of the OOM incident (→ correlate)

```
i-0f2c36ed3c6441131 on arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster is hitting OOM kills. Can you build me a timeline of what happened in the 2 minutes around the OOM events? I want to see which components were involved and the sequence of failures.
```

## 10. Download the raw log (→ artifact)

```
I need to download the full kubelet log from i-066b6285d77f63954 on arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster for offline analysis. Can you get me a download link?
```

## 11. Full incident report (→ summarize)

```
Node i-07b1807d7f5b67fd2 on arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster has pods stuck in ContainerCreating with mount errors. Give me a full incident summary — what's broken, what's affected, and what should I do to fix it.
```

## 12. Why is this node different? (→ compare_nodes)

```
On arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster, i-0441d2643ac9718f8 is crashlooping but i-0f2c36ed3c6441131 has OOM issues. Can you diff these two nodes — what errors do they share vs what's unique to each? Are their configs the same?
```

## 13. Networking deep dive (→ network_diagnostics)

```
i-066b6285d77f63954 on arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster is running out of pod IPs and we're seeing CNI errors. Can you pull apart its networking — iptables rules, CNI config, route tables, DNS setup, ENI attachments, and IPAMD status?
```

## 14. What collections have we done? (→ history)

```
Show me all the log collections we've run on arn:aws:eks:us-west-2:466162272783:cluster/devopsagentcluster so far. Which nodes, when, and did they all succeed? I want to know if I need to re-collect anything.
```
