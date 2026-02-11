# Gap Analysis: Research Requirements vs Current Code + Implementation Plan

## Methodology

Three-way comparison:
- **Research** = authoritative requirements from 2024-2025 deep research (100+ sources)
- **Code** = current codebase (`ssm-automation-enhanced.py`, CDK construct, Findings Indexer)
- **Plan** = `IMPLEMENTATION_PLAN.md` (Phases 0-5)

Classification:
- **MUST** = research marks as non-negotiable or critical for hallucination reduction
- **SHOULD** = research marks as strongly recommended for accuracy/security
- **COULD** = research marks as nice-to-have or future enhancement

Status:
- ✅ **COVERED** = exists in code or fully addressed in plan
- ⚠️ **PARTIAL** = partially addressed (code or plan covers some but not all)
- ❌ **GAP** = not in current code AND not in implementation plan

---

## Section 1: Architecture (Research Section 1)

| # | Requirement | Code | Plan | Status |
|---|------------|------|------|--------|
| 1.1 | AgentCore Gateway + Lambda tool targets | ✅ CDK construct deploys Gateway + Lambda | N/A (exists) | ✅ COVERED |
| 1.2 | SSM Automation for log collection | ✅ `start_log_collection()` triggers SSM | N/A (exists) | ✅ COVERED |
| 1.3 | S3 for artifact storage | ✅ Logs bucket with KMS encryption | N/A (exists) | ✅ COVERED |
| 1.4 | Pre-indexing at collection time | ✅ Findings Indexer Lambda triggered by Unzip | N/A (exists) | ✅ COVERED |

**No gaps in architecture.**

---

## Section 2: Anti-Hallucination Patterns (Research Section 2 — 7 Patterns)

| # | Requirement | Code | Plan | Status | Priority |
|---|------------|------|------|--------|----------|
| 2.1 | `finding_id` in F-NNN format on all findings | ❌ No finding_id in current code | ✅ Phase 0.1 | ✅ COVERED | MUST |
| 2.2 | `outputSchema` on all tool definitions | ❌ No outputSchema in CDK construct | ✅ Phase 0.2 | ✅ COVERED | MUST |
| 2.3 | Citation forcing in tool descriptions | ❌ Descriptions don't mention citation | ✅ Phase 0.3 | ✅ COVERED | MUST |
| 2.4 | Retrieval-before-interpretation enforcement | ❌ `summarize` does own retrieval | ✅ Phase 4.1-4.2 | ✅ COVERED | MUST |
| 2.5 | Confidence scoring on interpretation tools | ❌ No confidence/gaps in responses | ✅ Phase 4.3 | ✅ COVERED | MUST |
| 2.6 | Tool-before-answer workflow | ❌ No enforcement | ✅ Phase 4 (summarize requires finding_ids) | ✅ COVERED | MUST |
| 2.7 | `response_format` parameter (concise/detailed) on retrieval tools | ❌ Not in code | ❌ Not in plan | ❌ **GAP** | SHOULD |

### GAP 2.7: `response_format` parameter

**Research requirement:** Retrieval tools should accept a `response_format` parameter with values `concise` (finding_id + severity + one-line excerpt) or `detailed` (full evidence object). This reduces token consumption when the agent only needs a summary scan before drilling into specific findings.

**What to implement:**
- File: `src/ssm-automation-gateway-construct-v2.ts` — add `response_format` to `errors`, `search`, `correlate` InputSchema
- File: `src/lambda/ssm-automation-enhanced.py` — in `get_error_summary()`, `search_logs_deep()`, `correlate_events()`:
  ```python
  response_format = arguments.get('response_format', 'detailed')
  if response_format == 'concise':
      findings = [{
          'finding_id': f['finding_id'],
          'severity': f['severity'],
          'pattern': f['pattern'],
          'count': f.get('count', 1),
      } for f in findings]
  # else: return full evidence objects (current behavior)
  ```
- Estimated effort: 0.5 day
- Risk: Low — additive, backward compatible (default=detailed)

---

## Section 3: Log-Scale Challenges (Research Section 3)

| # | Requirement | Code | Plan | Status | Priority |
|---|------------|------|------|--------|----------|
| 3.1 | 3-tier retrieval (index → search → chunk) | ⚠️ Tiers exist but not formalized | ✅ Phase 3 formalizes tiers | ✅ COVERED | MUST |
| 3.2 | S3 byte-range GET with line alignment | ⚠️ Byte-range exists, no line alignment | ✅ Phase 3.3 adds line alignment | ✅ COVERED | MUST |
| 3.3 | S3 Select for structured logs | ❌ Not in code | ✅ Phase 3.2 adds S3 Select | ✅ COVERED | SHOULD |
| 3.4 | Remove 10MB file skip in search | ❌ Code skips files >10MB silently | ✅ Phase 3.2 replaces with chunked scan | ✅ COVERED | MUST |
| 3.5 | manifest.json with checksums | ❌ No manifest.json generated | ✅ Phase 2.1 generates manifest | ✅ COVERED | MUST |
| 3.6 | Pagination (`page_size`, `page_token`) on `get_findings` | ❌ Returns max 100, no pagination | ❌ Not in plan | ❌ **GAP** | SHOULD |
| 3.7 | Line-aware chunking (content trimmed to complete lines) | ❌ Current `read` can split mid-line | ✅ Phase 3.3 | ✅ COVERED | MUST |

### GAP 3.6: Pagination on `get_findings` (errors tool)

**Research requirement:** For nodes with hundreds of findings, `get_findings` should support `page_size` (default 50) and `page_token` for cursor-based pagination. Current code hard-caps at 100 findings with no pagination.

**What to implement:**
- File: `src/ssm-automation-gateway-construct-v2.ts` — add to `errors` InputSchema:
  ```typescript
  pageSize: { Type: 'integer', Description: 'Results per page (default: 50, max: 200)' },
  pageToken: { Type: 'string', Description: 'Cursor from previous response for next page' },
  ```
- File: `src/lambda/ssm-automation-enhanced.py` — in `get_error_summary()`:
  ```python
  page_size = min(arguments.get('pageSize', 50), 200)
  page_token = arguments.get('pageToken')
  start_idx = decode_page_token(page_token) if page_token else 0
  
  page = findings[start_idx:start_idx + page_size]
  next_token = encode_page_token(start_idx + page_size) if start_idx + page_size < len(findings) else None
  
  response['findings'] = page
  response['pagination'] = {
      'page_size': page_size,
      'total_findings': len(findings),
      'next_page_token': next_token,
      'has_more': next_token is not None,
  }
  ```
- Estimated effort: 0.5 day
- Risk: Low — additive, default behavior unchanged

---

## Section 4: Gold-Standard Toolset (Research Section 4)

Research defines 7 specific tools. Mapping to current tools:

| Research Tool | Current Tool | Plan Tool | Status | Notes |
|--------------|-------------|-----------|--------|-------|
| `start_collection_job` | `collect` | `collect` + Tasks | ✅ COVERED | Plan adds Task state machine |
| `validate_manifest` | `validate` | `validate` + manifest.json | ✅ COVERED | Plan adds checksum verification |
| `get_findings` | `errors` | `errors` + finding_id + coverage | ✅ COVERED | Plan adds F-NNN IDs, evidence, coverage |
| `search_logs` | `search` | `search` + S3 Select + coverage | ✅ COVERED | Plan adds large file support |
| `fetch_log_chunk` | `read` | `read` + line alignment | ✅ COVERED | Plan adds line-aligned chunking |
| `correlate_timeline` | `correlate` | `correlate` + confidence | ⚠️ PARTIAL | See gaps below |
| `generate_incident_report` | `summarize` | `summarize` + finding_ids required | ⚠️ PARTIAL | See gaps below |

### Research schema fields NOT in plan:

| # | Field | Research Location | Code | Plan | Status | Priority |
|---|-------|------------------|------|------|--------|----------|
| 4.1 | `node_filter` param on `get_findings` | Research Section 4 | ❌ | ❌ | ❌ **GAP** | COULD |
| 4.2 | `affected_nodes` array on findings | Research Section 4 | ❌ | ❌ | ❌ **GAP** | COULD |
| 4.3 | `first_seen`/`last_seen` timestamps on findings | Research Section 4 | ❌ | ❌ | ❌ **GAP** | SHOULD |
| 4.4 | `clusters` (temporal event clusters) in correlate output | Research Section 4 | ❌ | ❌ | ❌ **GAP** | SHOULD |
| 4.5 | `potential_root_cause_chain` in correlate output | Research Section 4 | ❌ | ❌ | ❌ **GAP** | SHOULD |
| 4.6 | Severity enum: 5 levels (CRITICAL/HIGH/MEDIUM/LOW/INFO) | Research Section 4 | ❌ 3 levels | ❌ Plan keeps 3 | ❌ **GAP** | MUST |

### GAP 4.1: `node_filter` on `get_findings`

**Research requirement:** Multi-node clusters need filtering findings by node role, nodegroup, or AZ. Current `errors` tool only accepts `instanceId` (single node).

**Assessment:** COULD implement. Current architecture is single-node-per-call. Multi-node filtering is better served by `compare_nodes` which already exists. Low priority — the existing tool set covers this use case differently.

### GAP 4.2: `affected_nodes` array on findings

**Research requirement:** Each finding should list all nodes where it was observed. Current findings are per-instance.

**Assessment:** COULD implement. Would require cross-instance correlation at query time. `compare_nodes` already does this. Low priority.

### GAP 4.3: `first_seen`/`last_seen` timestamps on findings

**Research requirement:** Deduplicated findings should track the time range of occurrences, not just the first match.

**What to implement:**
- File: `src/ssm-automation-gateway-construct-v2.ts` → `getFindingsIndexerCode()` — in `deduplicate_findings()`:
  ```python
  if dedup_key not in seen:
      seen[dedup_key] = {
          **finding,
          'count': 1,
          'lines': [finding.get('line')],
          'first_seen': extract_timestamp(finding.get('sample', '')),
          'last_seen': extract_timestamp(finding.get('sample', '')),
      }
  else:
      seen[dedup_key]['count'] += 1
      ts = extract_timestamp(finding.get('sample', ''))
      if ts:
          if not seen[dedup_key].get('first_seen') or ts < seen[dedup_key]['first_seen']:
              seen[dedup_key]['first_seen'] = ts
          if not seen[dedup_key].get('last_seen') or ts > seen[dedup_key]['last_seen']:
              seen[dedup_key]['last_seen'] = ts
  ```
- Also update `src/lambda/ssm-automation-enhanced.py` → `scan_and_index_errors()` with same logic
- Estimated effort: 0.5 day
- Risk: Low — additive fields

### GAP 4.4: Temporal event clusters in `correlate_timeline` output

**Research requirement:** `correlate_timeline` should return structured `clusters` — groups of temporally related events with a `cluster_id`, `time_range`, `events[]`, and `dominant_severity`.

**What to implement:**
- File: `src/lambda/ssm-automation-enhanced.py` → `correlate_events()` — after building timeline, group events into clusters:
  ```python
  def cluster_timeline_events(timeline, window_seconds=30):
      clusters = []
      current_cluster = None
      for event in sorted(timeline, key=lambda e: e.get('timestamp', '')):
          ts = parse_timestamp(event.get('timestamp'))
          if current_cluster is None or (ts - current_cluster['end_time']).total_seconds() > window_seconds:
              if current_cluster:
                  clusters.append(current_cluster)
              current_cluster = {
                  'cluster_id': f'C-{len(clusters)+1:03d}',
                  'start_time': ts,
                  'end_time': ts,
                  'events': [event],
                  'dominant_severity': event.get('severity', 'info'),
              }
          else:
              current_cluster['events'].append(event)
              current_cluster['end_time'] = ts
              # Upgrade severity
              if severity_rank(event.get('severity')) < severity_rank(current_cluster['dominant_severity']):
                  current_cluster['dominant_severity'] = event['severity']
      if current_cluster:
          clusters.append(current_cluster)
      return clusters
  ```
- Estimated effort: 1 day
- Risk: Low — additive field in correlate response

### GAP 4.5: `potential_root_cause_chain` in correlate output

**Research requirement:** Correlate should attempt to build a causal chain: event A → event B → event C, with confidence.

**What to implement:**
- File: `src/lambda/ssm-automation-enhanced.py` → `find_correlations()` — extend to produce ordered chains:
  ```python
  # After clustering, identify chains where one event type commonly precedes another
  # e.g., "IP exhaustion" → "CNI not ready" → "pod scheduling failure"
  KNOWN_CAUSAL_CHAINS = {
      'IP exhaustion': ['CNI not ready', 'pod scheduling failure'],
      'OOM killer invoked': ['container OOMKilled', 'pod evicted'],
      'disk pressure': ['pod evicted', 'image pull failure'],
      'certificate error': ['API server unreachable', 'node NotReady'],
  }
  
  root_cause_chain = []
  for cluster in clusters:
      patterns = [e.get('pattern', '') for e in cluster['events']]
      for root, chain in KNOWN_CAUSAL_CHAINS.items():
          if any(root in p for p in patterns):
              matched_chain = [root] + [c for c in chain if any(c in p for p in patterns)]
              if len(matched_chain) > 1:
                  root_cause_chain.append({
                      'chain': matched_chain,
                      'confidence': 'high' if len(matched_chain) == len(chain) + 1 else 'medium',
                      'cluster_id': cluster['cluster_id'],
                  })
  ```
- Estimated effort: 1 day
- Risk: Medium — causal inference can produce false positives. Mitigate with confidence levels and known-chain approach.

### GAP 4.6: Severity enum mismatch (3 levels vs 5 levels)

**Research requirement:** 5 severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`.
**Current code:** 3 levels: `critical`, `warning`, `info`.
**Plan:** Keeps 3 levels.

**What to implement:**
- File: `src/lambda/ssm-automation-enhanced.py` — update `Severity` enum:
  ```python
  class Severity(Enum):
      CRITICAL = 'critical'
      HIGH = 'high'
      MEDIUM = 'medium'  # Maps from current 'warning'
      LOW = 'low'
      INFO = 'info'
  ```
- File: `src/ssm-automation-gateway-construct-v2.ts` → Findings Indexer — update `ERROR_PATTERNS` to split `warning` into `high` and `medium`:
  - `high`: OOMKilled, CrashLoopBackOff, ImagePullBackOff, FailedScheduling, connection refused
  - `medium`: probe failures, restart backoff, insufficient resources, DNS issues
- File: All outputSchema `severity` enums → update to 5 values
- Migration: Add backward-compat mapping `warning` → `medium` for old indices
- Estimated effort: 1 day
- Risk: Medium — breaking change for existing findings_index.json. Mitigate with version field check and mapping layer.

---

## Section 5: Accuracy & Evaluation (Research Section 5)

| # | Requirement | Code | Plan | Status | Priority |
|---|------------|------|------|--------|----------|
| 5.1 | Test harness architecture | ❌ | ⚠️ Phase 5.2 has debug envelope only | ❌ **GAP** | SHOULD |
| 5.2 | 9 specific metrics (Finding Precision, Recall, Hallucination Rate, etc.) | ❌ | ❌ Not defined | ❌ **GAP** | SHOULD |
| 5.3 | Regression suite with golden test cases | ❌ | ⚠️ Phase 5.2 mentions input/output hash pairs | ⚠️ PARTIAL | SHOULD |
| 5.4 | LLM-as-judge hallucination detection | ❌ | ❌ | ❌ **GAP** | COULD |
| 5.5 | Multi-signal confirmation for CRITICAL findings | ❌ | ❌ | ❌ **GAP** | SHOULD |
| 5.6 | Baseline subtraction (per-cluster error baselines) | ❌ | ❌ | ❌ **GAP** | SHOULD |
| 5.7 | Negative pattern lists for false positive reduction | ⚠️ Findings Indexer has SKIP_FILE_PATTERNS | ❌ Plan doesn't extend | ⚠️ PARTIAL | SHOULD |
| 5.8 | False positive prevention (context-aware pattern matching) | ⚠️ Some context in Indexer | ❌ | ⚠️ PARTIAL | SHOULD |

### GAP 5.1: Test Harness Architecture

**Research requirement:** A structured evaluation framework with:
- Synthetic log bundles with known-injected errors
- Ground truth labels for each injected error
- Automated comparison of tool output vs ground truth
- CI-integrated regression runs

**What to implement:**
- Create `tests/evaluation/` directory with:
  - `test_bundles/` — synthetic S3 bundles with known errors (OOM, CNI failure, cert expiry, etc.)
  - `ground_truth/` — JSON files mapping bundle → expected findings with finding_ids
  - `eval_runner.py` — invokes each tool against test bundles, compares output to ground truth
  - `metrics.py` — computes precision, recall, F1, hallucination rate
- File: `eval_runner.py` skeleton:
  ```python
  def evaluate_tool(tool_name, test_input, ground_truth):
      response = invoke_tool(tool_name, test_input)
      predicted = extract_findings(response)
      expected = ground_truth['findings']
      
      tp = len(set(predicted) & set(expected))
      fp = len(set(predicted) - set(expected))
      fn = len(set(expected) - set(predicted))
      
      precision = tp / max(tp + fp, 1)
      recall = tp / max(tp + fn, 1)
      f1 = 2 * precision * recall / max(precision + recall, 0.001)
      
      return {'precision': precision, 'recall': recall, 'f1': f1, 'fp': fp, 'fn': fn}
  ```
- Estimated effort: 3-5 days (including synthetic bundle creation)
- Risk: Low — test infrastructure, no production impact

### GAP 5.2: 9 Specific Evaluation Metrics

**Research defines these metrics:**

| Metric | Definition | Current | Plan |
|--------|-----------|---------|------|
| Finding Precision | correct findings / total findings returned | ❌ | ❌ |
| Finding Recall | correct findings / total actual errors in bundle | ❌ | ❌ |
| Hallucination Rate | fabricated findings / total findings returned | ❌ | ❌ |
| Citation Accuracy | findings with valid evidence / total findings | ❌ | ❌ |
| Coverage Completeness | files scanned / total files | ❌ | ✅ (coverage_report) |
| Severity Accuracy | correctly classified severity / total findings | ❌ | ❌ |
| Latency p50/p95/p99 | per-tool response time | ❌ | ✅ (OTEL Phase 5) |
| Time-to-First-Finding | latency from tool call to first finding | ❌ | ✅ (OTEL Phase 5) |
| Schema Compliance | responses passing JSON schema validation | ❌ | ✅ (AC-1) |

**What to implement:** Define these in `tests/evaluation/metrics.py` and compute them in the eval runner (see GAP 5.1). The plan's Phase 5 OTEL covers latency metrics. The remaining 6 metrics need the test harness.

- Estimated effort: 1 day (on top of GAP 5.1)

### GAP 5.4: LLM-as-Judge Hallucination Detection

**Research requirement:** Use a second LLM call to verify that agent-generated reports only contain claims supported by tool output. Feed the LLM the tool responses and the agent's report, ask it to flag unsupported claims.

**Assessment:** COULD implement. This is an evaluation-time technique, not a runtime tool change. Would be part of the test harness, not the MCP server itself. Defer to post-MVP.

### GAP 5.5: Multi-Signal Confirmation for CRITICAL Findings

**Research requirement:** CRITICAL findings should be confirmed by at least 2 independent signals (e.g., OOM in both kernel dmesg AND kubelet logs) before being classified as CRITICAL.

**What to implement:**
- File: `src/ssm-automation-gateway-construct-v2.ts` → `getFindingsIndexerCode()` — in `deduplicate_findings()`:
  ```python
  # After dedup, check if critical findings appear in multiple files
  for finding in result:
      if finding['severity'] == 'critical':
          # Count distinct source files with same pattern
          same_pattern = [f for f in result if f['pattern'] == finding['pattern']]
          distinct_files = len(set(f['file'] for f in same_pattern))
          finding['confirmation'] = {
              'signals': distinct_files,
              'confirmed': distinct_files >= 2,
              'sources': list(set(f['file'] for f in same_pattern))[:5],
          }
          if distinct_files < 2:
              finding['severity_note'] = 'Single-source critical finding. Verify with additional log sources.'
  ```
- Estimated effort: 0.5 day
- Risk: Low — additive metadata, doesn't change severity classification

### GAP 5.6: Baseline Subtraction

**Research requirement:** Maintain per-cluster error baselines so that "normal" errors (e.g., periodic DNS timeouts that always happen) are flagged as `baseline` rather than `new`. This prevents alert fatigue and false positives.

**What to implement:**
- New DynamoDB item type: `BASELINE#{cluster}#{pattern}` with `count`, `last_seen`, `is_baseline: true`
- File: `src/lambda/ssm-automation-enhanced.py` — in `get_error_summary()`:
  ```python
  # After loading findings, check against baseline
  if cluster_name:
      baselines = load_baselines(cluster_name)
      for finding in findings:
          baseline = baselines.get(finding['pattern'])
          if baseline and baseline['count'] > 10:
              finding['is_baseline'] = True
              finding['baseline_note'] = f'This pattern has been seen {baseline["count"]} times across this cluster. Likely normal.'
  ```
- Estimated effort: 2 days (DynamoDB schema + baseline learning + query integration)
- Risk: Medium — requires baseline data collection over time. Initial deployment has no baselines.

### GAP 5.7: Extended Negative Pattern Lists

**Current state:** Findings Indexer has `SKIP_FILE_PATTERNS` (files to skip) and `SCANNABLE_FILE_PATTERNS` (files to scan). But no negative patterns for content (e.g., "ignore OOM in test namespaces").

**Research requirement:** Content-level negative patterns to reduce false positives:
- Ignore errors in `kube-system` namespace pods that are expected (e.g., kube-proxy restarts during upgrades)
- Ignore DNS NXDOMAIN for known non-existent domains in health checks
- Ignore OOM in stress-test pods

**What to implement:**
- File: `src/ssm-automation-gateway-construct-v2.ts` → `getFindingsIndexerCode()` — add `FALSE_POSITIVE_SUPPRESSIONS`:
  ```python
  FALSE_POSITIVE_SUPPRESSIONS = [
      # Pattern, context regex that makes it a false positive, reason
      ('NXDOMAIN', r'health[-.]?check|readiness|liveness', 'Health check DNS lookup — expected'),
      ('OOMKilled', r'stress[-.]?test|load[-.]?test|chaos', 'Stress test pod — expected OOM'),
      ('connection refused', r'127\.0\.0\.1:10256.*healthz', 'kube-proxy local healthz — transient during startup'),
  ]
  ```
- Estimated effort: 0.5 day
- Risk: Low — reduces false positives, may suppress real errors if patterns are too broad. Mitigate by logging suppressions.

---

## Section 6: AWS Security (Research Section 6)

| # | Requirement | Code | Plan | Status | Priority |
|---|------------|------|------|--------|----------|
| 6.1 | IAM least privilege | ✅ CDK construct scopes permissions | N/A (exists) | ✅ COVERED | MUST |
| 6.2 | KMS encryption at rest | ✅ S3 bucket uses KMS key | N/A (exists) | ✅ COVERED | MUST |
| 6.3 | KMS encryption context (`job_id` in KMS calls) | ❌ No encryption context | ❌ Not in plan | ❌ **GAP** | SHOULD |
| 6.4 | PII/PHI redaction via Amazon Comprehend | ❌ Not in code | ❌ Not in plan | ❌ **GAP** | SHOULD |
| 6.5 | S3 VPC endpoint policy (data exfiltration prevention) | ❌ No VPC endpoint policy | ❌ Not in plan | ❌ **GAP** | SHOULD |
| 6.6 | S3 Object Lock for compliance retention | ❌ | ❌ | ❌ **GAP** | COULD |
| 6.7 | Presigned URL expiration ≤15 min | ✅ Default 15 min in `get_artifact_reference()` | N/A (exists) | ✅ COVERED | MUST |

### GAP 6.3: KMS Encryption Context

**Research requirement:** When writing to S3, include encryption context with `job_id` so that CloudTrail logs show which job wrote which object. Enables audit trail for compliance.

**What to implement:**
- File: `src/lambda/ssm-automation-enhanced.py` — in all `s3_client.put_object()` calls:
  ```python
  s3_client.put_object(
      Bucket=LOGS_BUCKET,
      Key=key,
      Body=body,
      ServerSideEncryption='aws:kms',
      SSEKMSKeyId=KMS_KEY_ID,
      SSEKMSEncryptionContext={
          'job_id': execution_id or instance_id,
          'tool': tool_name,
          'timestamp': datetime.utcnow().isoformat(),
      }
  )
  ```
- File: `src/ssm-automation-gateway-construct-v2.ts` — ensure KMS key policy allows `kms:EncryptionContextKeys` condition
- Estimated effort: 1 day
- Risk: Low — additive. Requires KMS key policy update to allow encryption context.

### GAP 6.4: PII/PHI Redaction via Amazon Comprehend

**Research requirement:** Log excerpts returned to the agent may contain PII (IP addresses, hostnames, usernames, tokens). Use Amazon Comprehend `DetectPiiEntities` to redact before returning.

**What to implement:**
- File: `src/lambda/ssm-automation-enhanced.py` — add redaction helper:
  ```python
  comprehend = boto3.client('comprehend')
  
  def redact_pii(text: str, redact_types: List[str] = None) -> str:
      """Redact PII from text using Amazon Comprehend."""
      if not os.environ.get('ENABLE_PII_REDACTION'):
          return text
      if len(text) > 5000:  # Comprehend limit
          text = text[:5000]
      try:
          response = comprehend.detect_pii_entities(Text=text, LanguageCode='en')
          # Redact from end to start to preserve offsets
          for entity in sorted(response['Entities'], key=lambda e: e['BeginOffset'], reverse=True):
              if redact_types is None or entity['Type'] in redact_types:
                  text = text[:entity['BeginOffset']] + f'[{entity["Type"]}]' + text[entity['EndOffset']:]
          return text
      except Exception:
          return text  # Fail open — don't block on redaction failure
  ```
- Apply to `evidence.excerpt` in all finding responses
- File: `src/ssm-automation-gateway-construct-v2.ts` — add Comprehend permissions to Lambda role:
  ```typescript
  ssmLambda.addToRolePolicy(new iam.PolicyStatement({
      actions: ['comprehend:DetectPiiEntities'],
      resources: ['*'],
  }));
  ```
- Add `ENABLE_PII_REDACTION` environment variable (default: false)
- Estimated effort: 1-2 days
- Risk: Medium — Comprehend adds latency (~100-200ms per call). Feature-flag it. Also adds cost (~$0.0001 per 100 chars).

### GAP 6.5: S3 VPC Endpoint Policy

**Research requirement:** If Lambda runs in a VPC, the S3 VPC endpoint should have a policy restricting access to only the logs bucket. Prevents data exfiltration to other S3 buckets.

**What to implement:**
- File: `src/ssm-automation-gateway-construct-v2.ts` — if VPC is configured:
  ```typescript
  const s3Endpoint = vpc.addGatewayEndpoint('S3Endpoint', {
      service: ec2.GatewayVpcEndpointAwsService.S3,
  });
  s3Endpoint.addToPolicy(new iam.PolicyStatement({
      principals: [new iam.AnyPrincipal()],
      actions: ['s3:GetObject', 's3:PutObject', 's3:ListBucket'],
      resources: [logsBucket.bucketArn, `${logsBucket.bucketArn}/*`],
  }));
  ```
- Estimated effort: 0.5 day
- Risk: Low — only applies if Lambda is VPC-attached. Currently Lambda is not in a VPC, so this is a future hardening item.

### GAP 6.6: S3 Object Lock

**Research requirement:** For compliance environments, enable S3 Object Lock in governance mode to prevent accidental deletion of log bundles during retention period.

**Assessment:** COULD implement. Only needed for regulated environments (HIPAA, SOC2). Add as optional CDK construct parameter.

---

## Section 7: Observability (Research Section 7)

| # | Requirement | Code | Plan | Status | Priority |
|---|------------|------|------|--------|----------|
| 7.1 | OpenTelemetry tracing on all tool Lambdas | ❌ | ✅ Phase 5.1 (ADOT layer) | ✅ COVERED | SHOULD |
| 7.2 | Per-tool latency p50/p95/p99 | ❌ | ✅ Phase 5.1 metrics table | ✅ COVERED | SHOULD |
| 7.3 | Success/error rate counters | ❌ | ✅ Phase 5.1 | ✅ COVERED | SHOULD |
| 7.4 | Bytes scanned / files scanned counters | ❌ | ✅ Phase 5.1 | ✅ COVERED | SHOULD |
| 7.5 | Time-to-first-finding histogram | ❌ | ✅ Phase 5.1 | ✅ COVERED | SHOULD |
| 7.6 | 3-layer observability (tool → Lambda → SSM) | ❌ | ⚠️ Phase 5 covers Lambda layer only | ⚠️ PARTIAL | SHOULD |
| 7.7 | Debug envelope for evaluation | ❌ | ✅ Phase 5.2 | ✅ COVERED | SHOULD |

### GAP 7.6: 3-Layer Observability (partial)

**Research requirement:** Tracing should span 3 layers:
1. Tool invocation (AgentCore Gateway → Lambda)
2. Lambda execution (internal tool logic)
3. Downstream calls (SSM, S3, DynamoDB)

**Plan covers:** Layer 2 (Lambda tracing via ADOT). Layers 1 and 3 are partially covered by AWS X-Ray auto-instrumentation in ADOT, but the plan doesn't explicitly configure:
- Gateway-level trace propagation (Layer 1)
- SSM Automation step-level tracing (Layer 3 — SSM doesn't natively support OTEL)

**What to implement:**
- Layer 1: AgentCore Gateway should propagate `traceparent` header. Verify Gateway config supports this.
- Layer 3: For SSM, add custom spans around `ssm.start_automation_execution()` and `ssm.describe_automation_executions()` calls:
  ```python
  with tracer.start_as_current_span('ssm.start_automation') as span:
      span.set_attribute('ssm.document', document_name)
      span.set_attribute('ssm.instance_id', instance_id)
      response = ssm_client.start_automation_execution(...)
  ```
- Estimated effort: 0.5 day (on top of Phase 5.1)
- Risk: Low — additive tracing

---

## Section 8: Best Practice Checklist (Research Section 8)

Research provides a MUST/SHOULD/COULD checklist. Cross-referencing:

### MUST items

| Item | Status | Notes |
|------|--------|-------|
| finding_id on all findings | ✅ Plan Phase 0 | |
| outputSchema on all tools | ✅ Plan Phase 0 | |
| coverage_report on retrieval tools | ✅ Plan Phase 0 | |
| Retrieval-before-report enforcement | ✅ Plan Phase 4 | |
| No silent truncation | ✅ Plan Phase 0 (truncated field) | |
| MCP Tasks for long-running ops | ✅ Plan Phase 1 | |
| manifest.json with checksums | ✅ Plan Phase 2 | |
| Line-aligned byte-range reads | ✅ Plan Phase 3 | |
| Idempotency keys | ✅ Exists + Plan Phase 1 (DynamoDB) | |
| 5-level severity enum | ❌ **GAP** (see 4.6) | Plan keeps 3 levels |

### SHOULD items

| Item | Status | Notes |
|------|--------|-------|
| `response_format` (concise/detailed) | ❌ **GAP** (see 2.7) | |
| Pagination on get_findings | ❌ **GAP** (see 3.6) | |
| `first_seen`/`last_seen` on findings | ❌ **GAP** (see 4.3) | |
| Temporal event clusters in correlate | ❌ **GAP** (see 4.4) | |
| Root cause chain in correlate | ❌ **GAP** (see 4.5) | |
| Multi-signal confirmation for CRITICAL | ❌ **GAP** (see 5.5) | |
| Baseline subtraction | ❌ **GAP** (see 5.6) | |
| Extended false positive suppression | ⚠️ PARTIAL (see 5.7) | |
| KMS encryption context | ❌ **GAP** (see 6.3) | |
| PII/PHI redaction | ❌ **GAP** (see 6.4) | |
| S3 VPC endpoint policy | ❌ **GAP** (see 6.5) | |
| Test harness with ground truth | ❌ **GAP** (see 5.1) | |
| 9 evaluation metrics | ❌ **GAP** (see 5.2) | |
| 3-layer observability | ⚠️ PARTIAL (see 7.6) | |

### COULD items

| Item | Status | Notes |
|------|--------|-------|
| `node_filter` on get_findings | ❌ GAP (see 4.1) | Low priority — compare_nodes covers this |
| `affected_nodes` array | ❌ GAP (see 4.2) | Low priority |
| Progressive tool discovery (`list_tools_by_workflow`) | ❌ GAP | Not needed — 15 tools is manageable |
| Code Mode (`execute_analysis_code`) | ❌ GAP | Security risk — defer indefinitely |
| S3 Object Lock | ❌ GAP (see 6.6) | Only for compliance environments |
| LLM-as-judge hallucination detection | ❌ GAP (see 5.4) | Eval-time only, not runtime |

---

## Summary: All Gaps Ranked by Priority

### MUST Implement (1 gap)

| Gap | Effort | Files to Change | Risk |
|-----|--------|----------------|------|
| **4.6** Severity enum: 5 levels instead of 3 | 1 day | `ssm-automation-enhanced.py` (Severity enum, ERROR_PATTERNS), CDK Findings Indexer, all outputSchema enums | Medium — breaking change for existing indices |

### SHOULD Implement (13 gaps)

| Gap | Effort | Files to Change | Risk |
|-----|--------|----------------|------|
| **2.7** `response_format` param (concise/detailed) | 0.5 day | CDK InputSchema (3 tools), Lambda (3 functions) | Low |
| **3.6** Pagination on `get_findings` | 0.5 day | CDK InputSchema, Lambda `get_error_summary()` | Low |
| **4.3** `first_seen`/`last_seen` on findings | 0.5 day | CDK Findings Indexer, Lambda `scan_and_index_errors()` | Low |
| **4.4** Temporal event clusters in correlate | 1 day | Lambda `correlate_events()` | Low |
| **4.5** Root cause chain in correlate | 1 day | Lambda `find_correlations()` | Medium |
| **5.1** Test harness architecture | 3-5 days | New `tests/evaluation/` directory | Low |
| **5.2** 9 evaluation metrics | 1 day | New `tests/evaluation/metrics.py` | Low |
| **5.5** Multi-signal confirmation for CRITICAL | 0.5 day | CDK Findings Indexer `deduplicate_findings()` | Low |
| **5.6** Baseline subtraction | 2 days | DynamoDB schema, Lambda `get_error_summary()` | Medium |
| **5.7** Extended false positive suppression | 0.5 day | CDK Findings Indexer | Low |
| **6.3** KMS encryption context | 1 day | Lambda (all S3 put_object calls), CDK KMS policy | Low |
| **6.4** PII/PHI redaction | 1-2 days | Lambda (new helper + apply to excerpts), CDK IAM | Medium |
| **6.5** S3 VPC endpoint policy | 0.5 day | CDK construct (VPC endpoint) | Low |

### COULD Implement (5 gaps — defer)

| Gap | Effort | Recommendation |
|-----|--------|---------------|
| **4.1** `node_filter` on get_findings | 1 day | Defer — `compare_nodes` covers this |
| **4.2** `affected_nodes` array | 1 day | Defer — requires cross-instance correlation |
| **5.4** LLM-as-judge | 2-3 days | Defer — eval-time only |
| **6.6** S3 Object Lock | 0.5 day | Defer — compliance environments only |
| **7.6** 3-layer observability (full) | 0.5 day | Partially covered by ADOT auto-instrumentation |

---

## Recommended Implementation Order

Integrate these gaps into the existing phase plan:

### Phase 0 (add ~1 day)
- **4.6** Severity enum expansion (MUST — do this first since it affects all finding schemas)
- **2.7** `response_format` parameter (SHOULD — trivial, do alongside schema work)

### Phase 2 (add ~1 day)
- **4.3** `first_seen`/`last_seen` on findings (SHOULD — part of Findings Indexer v2 upgrade)
- **5.5** Multi-signal confirmation for CRITICAL (SHOULD — part of Findings Indexer upgrade)
- **5.7** Extended false positive suppression (SHOULD — part of Findings Indexer upgrade)

### Phase 3 (add ~0.5 day)
- **3.6** Pagination on `get_findings` (SHOULD — part of retrieval hardening)

### Phase 4 (add ~2 days)
- **4.4** Temporal event clusters in correlate (SHOULD — part of interpretation improvements)
- **4.5** Root cause chain in correlate (SHOULD — part of interpretation improvements)

### Phase 5 (add ~2 days)
- **6.3** KMS encryption context (SHOULD — security hardening)
- **6.4** PII/PHI redaction (SHOULD — security hardening, feature-flagged)
- **6.5** S3 VPC endpoint policy (SHOULD — security hardening)

### Phase 6 (new — Evaluation Framework, ~5 days)
- **5.1** Test harness architecture
- **5.2** 9 evaluation metrics
- **5.6** Baseline subtraction (requires data collection period)

### Total additional effort: ~12-14 days on top of existing plan (~15-19 days)
### Revised total: ~27-33 days for complete research compliance

---

## File Change Index

Quick reference for which files need changes for each gap:

| File | Gaps |
|------|------|
| `src/lambda/ssm-automation-enhanced.py` | 2.7, 3.6, 4.3, 4.4, 4.5, 4.6, 5.6, 6.3, 6.4 |
| `src/ssm-automation-gateway-construct-v2.ts` (tool schemas) | 2.7, 3.6, 4.6, 6.4, 6.5 |
| `src/ssm-automation-gateway-construct-v2.ts` (Findings Indexer) | 4.3, 4.6, 5.5, 5.7 |
| `src/ssm-automation-gateway-construct-v2.ts` (CDK infra) | 6.3, 6.5 |
| `tests/evaluation/` (new) | 5.1, 5.2 |
