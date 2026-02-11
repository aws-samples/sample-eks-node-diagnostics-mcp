# Anti-Hallucination Implementation Plan

## Current State Assessment

The existing MCP server (`eks-node-log-mcp`) already has solid foundations:
- Idempotency tokens on `collect` with DynamoDB-backed dedup (S3 metadata)
- Pre-indexed findings via `findings_index.json` (Findings Indexer Lambda)
- Byte-range streaming in `read` (S3 Range GET)
- Manifest validation in `validate`
- 15 tools across 3 tiers

**Gaps identified against requirements:**
1. No `finding_id` (F-001 format) on findings — agent can't cite specific evidence
2. No `outputSchema` on any tool — agent gets no structural contract
3. `summarize` does its own retrieval instead of requiring pre-retrieved `finding_ids`
4. No `coverage_report` on retrieval tools (files scanned vs total)
5. No MCP Tasks integration — `collect` returns immediately but has no formal task state machine
6. `findings_index.json` lacks `evidence.byte_offset` / `evidence.line_range` for deep retrieval
7. No `manifest.json` with checksums — `validate` infers completeness heuristically
8. Tool descriptions don't instruct agent to cite `finding_id` + `evidence.excerpt`
9. No OpenTelemetry tracing
10. `search` skips files >10MB — silent gap in coverage
11. Severity enum uses 3 levels (`critical`/`warning`/`info`) — research requires 5 (`critical`/`high`/`medium`/`low`/`info`) *(GAP 4.6)*
12. No `response_format` parameter (concise/detailed) on retrieval tools — wastes tokens *(GAP 2.7)*
13. No pagination on `get_findings` — hard-caps at 100 findings *(GAP 3.6)*
14. No `first_seen`/`last_seen` timestamps on deduplicated findings *(GAP 4.3)*
15. No temporal event clusters in `correlate` output *(GAP 4.4)*
16. No `potential_root_cause_chain` in `correlate` output *(GAP 4.5)*
17. No multi-signal confirmation for CRITICAL findings *(GAP 5.5)*
18. No false positive suppression patterns for content-level filtering *(GAP 5.7)*
19. No KMS encryption context on S3 writes *(GAP 6.3)*
20. No PII/PHI redaction on evidence excerpts *(GAP 6.4)*
21. No S3 VPC endpoint policy for data exfiltration prevention *(GAP 6.5)*
22. No test harness with ground truth bundles *(GAP 5.1)*
23. No formal evaluation metrics (precision, recall, hallucination rate) *(GAP 5.2)*
24. No baseline subtraction for per-cluster error baselines *(GAP 5.6)*

---

## Phase 0: Quick Refactors (Schemas, IDs, Descriptions, Severity Enum)

**Timeline:** 2-3 days *(+1 day for GAP 4.6 severity expansion + GAP 2.7 response_format)*
**Risk:** Low-Medium — severity enum change is additive but requires backward-compat mapping
**Rollback:** Revert Lambda code; old responses are a subset of new ones. Severity mapping layer handles old indices.

### 0.1 Add `finding_id` to all findings

**File:** `src/lambda/ssm-automation-enhanced.py`

**Change:** In `scan_and_index_errors()` and the Findings Indexer Lambda, assign sequential
`finding_id` values in format `F-001`, `F-002`, etc. (per instance, reset per indexing run).

```python
# In deduplicate_findings() or after sort:
for idx, finding in enumerate(deduplicated, start=1):
    finding['finding_id'] = f"F-{idx:03d}"
```

**Also add `evidence` wrapper to each finding:**
```python
finding['evidence'] = {
    'source_file': finding['file'],
    'full_key': finding['fullKey'],
    'excerpt': finding['sample'][:500],
    'line_range': {'start': finding.get('line', 0), 'end': finding.get('line', 0)},
    'timestamp': extract_timestamp(finding.get('sample', '')),
}
```

**Impact:** Every downstream tool (`errors`, `correlate`, `summarize`) now returns citable findings.

### 0.2 Add `outputSchema` to tool definitions

**File:** `src/ssm-automation-gateway-construct-v2.ts` → `getToolSchemaDefinitions()`

Add `OutputSchema` to each tool definition. Example for `errors`:

```jsonc
OutputSchema: {
  Type: 'object',
  Properties: {
    instanceId: { Type: 'string' },
    findings: {
      Type: 'array',
      Items: {
        Type: 'object',
        Properties: {
          finding_id: { Type: 'string', Pattern: '^F-\\d{3,}$' },
          severity: { Type: 'string', Enum: ['critical', 'high', 'medium', 'low', 'info'] },
          pattern: { Type: 'string' },
          count: { Type: 'integer' },
          evidence: {
            Type: 'object',
            Properties: {
              source_file: { Type: 'string' },
              full_key: { Type: 'string' },
              excerpt: { Type: 'string', MaxLength: 500 },
              line_range: {
                Type: 'object',
                Properties: {
                  start: { Type: 'integer' },
                  end: { Type: 'integer' }
                }
              },
              timestamp: { Type: 'string' }
            },
            Required: ['source_file', 'excerpt']
          }
        },
        Required: ['finding_id', 'severity', 'evidence']
      }
    },
    coverage_report: {
      Type: 'object',
      Properties: {
        files_scanned: { Type: 'integer' },
        total_files: { Type: 'integer' },
        coverage_pct: { Type: 'number' },
        skipped_files: {
          Type: 'array',
          Items: {
            Type: 'object',
            Properties: {
              file: { Type: 'string' },
              reason: { Type: 'string', Enum: ['too_large', 'binary', 'config_file', 'not_log'] }
            }
          }
        }
      }
    },
    truncated: { Type: 'boolean' }
  }
}
```

### 0.3 Update tool descriptions with citation requirements

**File:** `src/ssm-automation-gateway-construct-v2.ts`

Append to every retrieval tool description:
```
"Each finding includes a finding_id (e.g., F-001) and evidence object. When reporting to the user, you MUST cite finding_id and quote evidence.excerpt verbatim."
```

Append to `summarize` description:
```
"IMPORTANT: You MUST call errors() or search() FIRST to retrieve findings. This tool requires finding_ids from prior retrieval. Do NOT call this tool without first retrieving evidence."
```

### 0.4 Add `coverage_report` to all retrieval tool responses

**File:** `src/lambda/ssm-automation-enhanced.py`

Add to `get_error_summary()`, `search_logs_deep()`, `correlate_events()`:

```python
# After scanning, compute coverage
total_files = len(all_extracted_files)
files_scanned = len(files_to_search)
skipped = [{'file': f['key'], 'reason': reason} for f, reason in skipped_with_reasons]

response['coverage_report'] = {
    'files_scanned': files_scanned,
    'total_files': total_files,
    'coverage_pct': round(files_scanned / max(total_files, 1) * 100, 1),
    'skipped_files': skipped[:20],  # Cap to avoid bloat
}
```

**Impact:** Agent can report "Scanned 42/47 files (89.4%)" — no silent gaps.

### 0.5 Expand severity enum from 3 to 5 levels *(GAP 4.6 — MUST)*

**Research requirement:** 5 severity levels: `critical`, `high`, `medium`, `low`, `info`.
**Current:** 3 levels: `critical`, `warning`, `info`.

**File:** `src/lambda/ssm-automation-enhanced.py` — update severity classification:

```python
class Severity(Enum):
    CRITICAL = 'critical'
    HIGH = 'high'
    MEDIUM = 'medium'   # Maps from current 'warning' (high-impact subset)
    LOW = 'low'
    INFO = 'info'

# Backward-compat mapping for old findings_index.json (v1)
SEVERITY_V1_TO_V2 = {
    'critical': 'critical',
    'warning': 'medium',   # Default mapping; Indexer v2 will classify properly
    'info': 'info',
}
```

**File:** `src/ssm-automation-gateway-construct-v2.ts` → `getFindingsIndexerCode()` — split `ERROR_PATTERNS`:

```python
# HIGH: immediate node/pod impact, single-signal
HIGH_PATTERNS = [
    ('OOMKilled', 'Container exceeded memory limit'),
    ('CrashLoopBackOff', 'Container crash loop'),
    ('ImagePullBackOff', 'Image pull failure'),
    ('FailedScheduling', 'Pod scheduling failure'),
    ('connection refused', 'Service connection refused'),
]

# MEDIUM: degraded but not immediately failing
MEDIUM_PATTERNS = [
    ('probe failed', 'Health probe failure'),
    ('restart backoff', 'Container restart backoff'),
    ('Insufficient', 'Insufficient resources'),
    ('NXDOMAIN', 'DNS resolution failure'),
    ('i/o timeout', 'Network I/O timeout'),
]

# LOW: informational warnings
LOW_PATTERNS = [
    ('eviction manager', 'Eviction manager threshold'),
    ('slow operation', 'Slow etcd/API operation'),
    ('TLS handshake', 'TLS handshake issue'),
]
```

**File:** All `outputSchema` severity enums throughout Section 2 → update to:
```
Enum: ['critical', 'high', 'medium', 'low', 'info']
```

**Migration:** When reading `findings_index.json` without `version` field (v1), apply `SEVERITY_V1_TO_V2` mapping.

### 0.6 Add `response_format` parameter to retrieval tools *(GAP 2.7 — SHOULD)*

**Research requirement:** Retrieval tools accept `response_format` with values `concise` (finding_id + severity + one-line pattern) or `detailed` (full evidence object). Reduces token consumption for summary scans.

**File:** `src/ssm-automation-gateway-construct-v2.ts` — add to `errors`, `search`, `correlate` InputSchema:
```typescript
response_format: {
  Type: 'string',
  Enum: ['concise', 'detailed'],
  Description: 'concise = finding_id + severity + pattern only. detailed = full evidence (default).',
}
```

**File:** `src/lambda/ssm-automation-enhanced.py` — in `get_error_summary()`, `search_logs_deep()`, `correlate_events()`:
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

**Impact:** Agent can do a quick scan with `response_format=concise`, then drill into specific findings with `response_format=detailed`. Saves ~70% tokens on initial scan.

---

## Phase 1: MCP Tasks for Long-Running Collection

**Timeline:** 3-5 days
**Risk:** Medium — changes Gateway config and `collect` response contract
**Rollback:** Remove `execution.taskSupport` from tool definition; Lambda still works

### 1.1 Mark `collect` and `batch_collect` as Task-capable

**File:** `src/ssm-automation-gateway-construct-v2.ts`

Add to `collect` and `batch_collect` tool definitions:
```typescript
Execution: {
  TaskSupport: 'required',
},
```

### 1.2 Return Task state machine from `collect`

**File:** `src/lambda/ssm-automation-enhanced.py` → `start_log_collection()`

Change response to return MCP Task envelope:

```python
def start_log_collection(arguments: Dict) -> Dict:
    # ... existing SSM start logic ...

    return success_response({
        'task': {
            'taskId': execution_id,
            'state': 'working',          # working | completed | failed | cancelled
            'message': f'Log collection started for {instance_id}',
            'ttl': 600,                  # 10 min max
            'suggestedPollInterval': 15, # seconds
        },
        'executionId': execution_id,
        'instanceId': instance_id,
        'region': target_region,
        'idempotencyKey': idempotency_token,
    })
```

### 1.3 `status` returns Task state transitions

**File:** `src/lambda/ssm-automation-enhanced.py` → `get_collection_status()`

Map SSM states to MCP Task states:
```python
SSM_TO_TASK_STATE = {
    'Pending': 'working',
    'InProgress': 'working',
    'Waiting': 'working',
    'Success': 'completed',
    'TimedOut': 'failed',
    'Cancelling': 'cancelled',
    'Cancelled': 'cancelled',
    'Failed': 'failed',
}
```

Return:
```python
return success_response({
    'task': {
        'taskId': execution_id,
        'state': SSM_TO_TASK_STATE.get(ssm_status, 'working'),
        'message': f'{ssm_status}: {progress}% complete',
        'ttl': 600 if ssm_status in ('Pending', 'InProgress') else 0,
        'suggestedPollInterval': 15 if ssm_status in ('Pending', 'InProgress') else 0,
    },
    # ... existing fields ...
})
```

### 1.4 Idempotency key → taskId mapping in DynamoDB

**Current state:** Idempotency uses S3 metadata (`s3://bucket/idempotency/instance/token`).
**Change:** Migrate to DynamoDB for atomic reads and TTL.

**File:** `src/ssm-automation-gateway-construct-v2.ts` — add DynamoDB table:
```typescript
const idempotencyTable = new dynamodb.Table(this, 'IdempotencyTable', {
  partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },  // instance#token
  sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },       // 'IDEMPOTENCY'
  timeToLiveAttribute: 'ttl',
  billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  removalPolicy: cdk.RemovalPolicy.DESTROY,
});
```

**Schema:**
```
pk: "i-0abc123#tok-uuid-here"
sk: "IDEMPOTENCY"
executionId: "exec-uuid"
taskState: "working"
region: "us-west-2"
createdAt: "2025-01-15T..."
ttl: 1737000000  (epoch + 24h)
```

**File:** `src/lambda/ssm-automation-enhanced.py` — replace `find_execution_by_idempotency_token()`
and `store_idempotency_mapping()` with DynamoDB `get_item` / `put_item` using `ConditionExpression`
for safe upsert.

**Impact:** Atomic dedup, no S3 eventual-consistency race. TTL auto-cleans old entries.

---

## Phase 2: Manifest + Coverage + Pre-Index Pipeline

**Timeline:** 4-5 days *(+1 day for GAP 4.3 first_seen/last_seen, GAP 5.5 multi-signal, GAP 5.7 false positive suppression)*
**Risk:** Medium — changes Findings Indexer Lambda output format
**Rollback:** Old `findings_index.json` format still readable; add version field

### 2.1 Generate `manifest.json` during unzip

**File:** `src/ssm-automation-gateway-construct-v2.ts` → `getUnzipLambdaCode()`

After extracting all files, write `manifest.json`:

```python
import hashlib

manifest = {
    'version': '2.0',
    'instanceId': instance_id,
    'createdAt': datetime.utcnow().isoformat(),
    'source_archive': archive_key,
    'expected_files': [],
}

for extracted_file in extracted_files:
    # Compute MD5 during extraction
    md5 = hashlib.md5(content).hexdigest()
    manifest['expected_files'].append({
        'key': extracted_file['key'],
        'relative_path': extracted_file['key'].split('/extracted/')[-1],
        'size_bytes': extracted_file['size'],
        'md5': md5,
        'status': 'extracted',  # extracted | failed | skipped
        'file_type': categorize_file(extracted_file['key']),  # log | config | binary | unknown
    })

manifest['total_files'] = len(manifest['expected_files'])
manifest['total_size_bytes'] = sum(f['size_bytes'] for f in manifest['expected_files'])

# Write manifest
s3.put_object(
    Bucket=bucket,
    Key=f'{prefix}/manifest.json',
    Body=json.dumps(manifest),
    ContentType='application/json'
)
```

### 2.2 Upgrade `findings_index.json` schema (v2)

**File:** `src/ssm-automation-gateway-construct-v2.ts` → `getFindingsIndexerCode()`

New schema:
```json
{
  "version": "2.0",
  "instanceId": "i-0abc123",
  "indexedAt": "2025-01-15T10:30:00Z",
  "manifest_ref": "eks_i-0abc123/manifest.json",
  "coverage": {
    "files_scanned": 42,
    "total_files": 47,
    "coverage_pct": 89.4,
    "skipped_files": [
      {"file": "containerd-images.txt", "reason": "config_file"},
      {"file": "large-coredump.bin", "reason": "binary"}
    ]
  },
  "findings": [
    {
      "finding_id": "F-001",
      "severity": "critical",
      "pattern": "OOM killer invoked",
      "count": 3,
      "evidence": {
        "source_file": "var_log/messages",
        "full_key": "eks_i-0abc123/extracted/var_log/messages",
        "excerpt": "Jan 15 10:25:03 ip-10-0-1-5 kernel: [12345.678] Out of memory: Kill process 4567 (java) score 900",
        "line_range": {"start": 1523, "end": 1523},
        "byte_offset": {"start": 98304, "end": 98450},
        "timestamp": "2025-01-15T10:25:03Z"
      },
      "additional_occurrences": [
        {"line": 1530, "timestamp": "2025-01-15T10:25:05Z"},
        {"line": 1542, "timestamp": "2025-01-15T10:25:08Z"}
      ]
    }
  ],
  "summary": {
    "critical": 5,
    "high": 8,
    "medium": 4,
    "low": 2,
    "info": 3
  }
}
```

**Key additions:**
- `finding_id` (F-NNN format)
- `evidence.byte_offset` for Tier 3 deep retrieval
- `evidence.line_range` for line-based reads
- `coverage` block
- `version` field for backward compat

### 2.3 Strengthen `validate` to use `manifest.json`

**File:** `src/lambda/ssm-automation-enhanced.py` → `validate_bundle_completeness()`

```python
def validate_bundle_completeness(arguments):
    # Try to read manifest.json first (new path)
    manifest_key = f'{prefix}/manifest.json'
    manifest_result = safe_s3_read(manifest_key)

    if manifest_result['success']:
        manifest = json.loads(manifest_result['content'])
        # Verify each file exists and checksum matches
        verified = 0
        missing = []
        corrupted = []
        for expected in manifest['expected_files']:
            head = safe_s3_head(expected['key'])
            if not head['success']:
                missing.append(expected['relative_path'])
            elif head['size'] != expected['size_bytes']:
                corrupted.append({
                    'file': expected['relative_path'],
                    'expected_size': expected['size_bytes'],
                    'actual_size': head['size']
                })
            else:
                verified += 1

        return success_response({
            'manifest_version': manifest['version'],
            'complete': len(missing) == 0 and len(corrupted) == 0,
            'verified_files': verified,
            'total_expected': manifest['total_files'],
            'missing_files': missing,
            'corrupted_files': corrupted,
            'total_size_bytes': manifest['total_size_bytes'],
            'coverage_report': {
                'files_scanned': verified,
                'total_files': manifest['total_files'],
                'coverage_pct': round(verified / max(manifest['total_files'], 1) * 100, 1),
                'missing_files': missing,
            },
            'truncated': False,
        })

    # Fall back to existing heuristic validation (backward compat)
    # ... existing code ...
```

### 2.4 Add `first_seen`/`last_seen` timestamps to deduplicated findings *(GAP 4.3 — SHOULD)*

**Research requirement:** Deduplicated findings should track the full time range of occurrences, not just the first match.

**File:** `src/ssm-automation-gateway-construct-v2.ts` → `getFindingsIndexerCode()` — in `deduplicate_findings()`:

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

**Also update:** `src/lambda/ssm-automation-enhanced.py` → `scan_and_index_errors()` with same logic.

**Impact:** Agent can report "OOM killer active from 10:25:03 to 10:25:08 (3 occurrences)" instead of just showing the first hit.

### 2.5 Multi-signal confirmation for CRITICAL findings *(GAP 5.5 — SHOULD)*

**Research requirement:** CRITICAL findings should be confirmed by ≥2 independent log sources before being classified as CRITICAL. Single-source critical findings get a `severity_note`.

**File:** `src/ssm-automation-gateway-construct-v2.ts` → `getFindingsIndexerCode()` — after `deduplicate_findings()`:

```python
# After dedup, check if critical findings appear in multiple files
for finding in result:
    if finding['severity'] == 'critical':
        same_pattern = [f for f in result if f['pattern'] == finding['pattern']]
        distinct_files = len(set(f['file'] for f in same_pattern))
        finding['confirmation'] = {
            'signals': distinct_files,
            'confirmed': distinct_files >= 2,
            'sources': list(set(f['file'] for f in same_pattern))[:5],
        }
        if distinct_files < 2:
            finding['severity_note'] = (
                'Single-source critical finding. '
                'Verify with additional log sources.'
            )
```

**Impact:** Agent can distinguish between confirmed critical issues (kernel OOM in dmesg + kubelet OOMKilled) and single-source alerts that need manual verification.

### 2.6 Extended false positive suppression patterns *(GAP 5.7 — SHOULD)*

**Current state:** Findings Indexer has `SKIP_FILE_PATTERNS` and `SCANNABLE_FILE_PATTERNS` for file-level filtering. No content-level suppression.

**Research requirement:** Content-level negative patterns to reduce false positives.

**File:** `src/ssm-automation-gateway-construct-v2.ts` → `getFindingsIndexerCode()` — add `FALSE_POSITIVE_SUPPRESSIONS`:

```python
FALSE_POSITIVE_SUPPRESSIONS = [
    # (error_pattern, context_regex_that_makes_it_FP, reason)
    ('NXDOMAIN', r'health[-.]?check|readiness|liveness', 'Health check DNS lookup — expected'),
    ('OOMKilled', r'stress[-.]?test|load[-.]?test|chaos', 'Stress test pod — expected OOM'),
    ('connection refused', r'127\.0\.0\.1:10256.*healthz', 'kube-proxy local healthz — transient during startup'),
    ('TLS handshake error', r'kube-probe|health[-.]?check', 'Probe TLS handshake — expected'),
]

def is_false_positive(pattern: str, context: str) -> Optional[str]:
    """Returns suppression reason if this is a known false positive, else None."""
    for error_pat, fp_regex, reason in FALSE_POSITIVE_SUPPRESSIONS:
        if error_pat.lower() in pattern.lower():
            if re.search(fp_regex, context, re.IGNORECASE):
                return reason
    return None
```

Apply in the indexer scan loop:
```python
fp_reason = is_false_positive(finding['pattern'], finding.get('sample', ''))
if fp_reason:
    finding['suppressed'] = True
    finding['suppression_reason'] = fp_reason
    suppressed_count += 1
    continue  # Skip from main findings list
```

**Impact:** Reduces false positive noise. Suppressed findings are logged but not returned in the main findings list.

---

## Phase 3: Multi-Tier Retrieval Hardening

**Timeline:** 4-5.5 days *(+0.5 day for GAP 3.6 pagination on get_findings)*
**Risk:** Medium — changes `search` and `read` behavior for large files
**Rollback:** Feature-flag `ENABLE_S3_SELECT` env var; default off

### 3.1 Tier 1: `errors` (get_findings) — already exists, enhance

**Current:** Reads `findings_index.json` → returns findings.
**Change:** Add `coverage_report` and `finding_id` (done in Phase 0).
No structural change needed — this tier is already fast-path.

### 3.1b Add pagination to `errors` (get_findings) *(GAP 3.6 — SHOULD)*

**Research requirement:** For nodes with hundreds of findings, `get_findings` should support cursor-based pagination. Current code hard-caps at 100 findings.

**File:** `src/ssm-automation-gateway-construct-v2.ts` — add to `errors` InputSchema:
```typescript
pageSize: { Type: 'integer', Description: 'Results per page (default: 50, max: 200)' },
pageToken: { Type: 'string', Description: 'Cursor from previous response for next page' },
```

**File:** `src/lambda/ssm-automation-enhanced.py` — in `get_error_summary()`:
```python
import base64, json as _json

def encode_page_token(offset: int) -> str:
    return base64.b64encode(_json.dumps({'o': offset}).encode()).decode()

def decode_page_token(token: str) -> int:
    try:
        return _json.loads(base64.b64decode(token))['o']
    except Exception:
        return 0

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

**Impact:** Agent can page through large finding sets without hitting Lambda response size limits.

### 3.2 Tier 2: `search` — S3 Select for structured logs, Lambda streaming for text

**File:** `src/lambda/ssm-automation-enhanced.py` → `search_logs_deep()`

For JSON-structured logs (e.g., containerd JSON logs), use S3 Select:

```python
def search_with_s3_select(key: str, query: str, max_results: int) -> List[Dict]:
    """Use S3 Select for JSON-line logs (much faster for large files)."""
    try:
        # S3 Select supports SQL-like queries on JSON/CSV
        expression = f"SELECT * FROM s3object s WHERE s._source LIKE '%{query}%'"
        resp = s3_client.select_object_content(
            Bucket=LOGS_BUCKET,
            Key=key,
            ExpressionType='SQL',
            Expression=expression,
            InputSerialization={'JSON': {'Type': 'LINES'}},
            OutputSerialization={'JSON': {}},
        )
        results = []
        for event in resp['Payload']:
            if 'Records' in event:
                payload = event['Records']['Payload'].decode('utf-8')
                for line in payload.strip().split('\n'):
                    if line:
                        results.append(json.loads(line))
                        if len(results) >= max_results:
                            return results
        return results
    except Exception:
        return None  # Fall back to Lambda streaming
```

**Remove the 10MB file skip** — instead, for files >10MB:
1. Try S3 Select if JSON-structured
2. Fall back to byte-range scanning (read in 1MB chunks, scan each)
3. Track `bytes_scanned` in coverage report

```python
# Replace the 10MB skip with chunked scanning
if obj['size'] > 10485760:  # >10MB
    if is_json_log(key):
        matches = search_with_s3_select(key, query, max_results)
    else:
        matches = search_large_file_chunked(key, pattern, max_results, obj['size'])
    # Track in coverage
    bytes_scanned += obj['size']
```

### 3.3 Tier 3: `read` (fetch_log_chunk) — line-aligned byte-range

**File:** `src/lambda/ssm-automation-enhanced.py` → `read_log_chunk()`

**Current issue:** Byte-range reads can split mid-line.
**Fix:** After reading a byte range, trim to line boundaries:

```python
def read_log_chunk_line_aligned(arguments: Dict) -> Dict:
    # ... existing byte-range read ...

    # Line-align: trim partial first line and partial last line
    content_bytes = read_result['content'].encode('utf-8')

    # If not starting at byte 0, skip to first newline
    actual_start = start_byte
    if start_byte > 0:
        first_nl = content_bytes.find(b'\n')
        if first_nl >= 0:
            content_bytes = content_bytes[first_nl + 1:]
            actual_start = start_byte + first_nl + 1

    # Trim after last complete newline
    last_nl = content_bytes.rfind(b'\n')
    if last_nl >= 0:
        content_bytes = content_bytes[:last_nl + 1]
        actual_end = actual_start + last_nl + 1
    else:
        actual_end = actual_start + len(content_bytes)

    content_str = content_bytes.decode('utf-8', errors='replace')
    line_count = content_str.count('\n')

    return success_response({
        'logKey': log_key,
        'content': content_str,
        'startByte': actual_start,
        'endByte': actual_end,
        'lineCount': line_count,
        'chunkSize': len(content_str),
        'totalSize': total_size,
        'totalSizeHuman': format_bytes(total_size),
        'hasMore': actual_end < total_size,
        'nextChunkStart': actual_end if actual_end < total_size else None,
        'truncated': False,
        'lineAligned': True,
    })
```

---

## Phase 4: Report Generation Constraints

**Timeline:** 4-5 days *(+2 days for GAP 4.4 temporal clusters + GAP 4.5 root cause chain)*
**Risk:** Low-Medium — tightens `summarize` input contract; causal inference can produce false positives
**Rollback:** Make `finding_ids` optional with deprecation warning; disable root cause chain via env var

### 4.1 Require `finding_ids` input on `summarize`

**File:** `src/ssm-automation-gateway-construct-v2.ts` — update `summarize` tool:

```typescript
{
  Name: 'summarize',
  Description: 'Generate structured incident report from PREVIOUSLY RETRIEVED findings. '
    + 'REQUIRES finding_ids from errors() or search(). '
    + 'MUST call errors() or search() FIRST. '
    + 'When reporting to the user, MUST cite finding_id and quote evidence.excerpt. '
    + 'Returns confidence level and coverage gaps.',
  InputSchema: {
    Type: 'object',
    Properties: {
      instanceId: {
        Type: 'string',
        Description: 'EC2 instance ID',
      },
      finding_ids: {
        Type: 'array',
        Description: 'Array of finding_ids from errors() or search() (e.g., ["F-001", "F-003"]). REQUIRED.',
        Items: { Type: 'string' },
      },
      clusterContext: {
        Type: 'string',
        Description: 'Optional cluster name for context enrichment',
      },
      includeRecommendations: {
        Type: 'boolean',
        Description: 'Include remediation steps (default: true)',
      },
    },
    Required: ['instanceId', 'finding_ids'],
  },
}
```

### 4.2 Lambda enforces finding_ids

**File:** `src/lambda/ssm-automation-enhanced.py` → `generate_incident_summary()`

```python
def generate_incident_summary(arguments: Dict) -> Dict:
    instance_id = arguments.get('instanceId')
    finding_ids = arguments.get('finding_ids', [])

    if not instance_id:
        return error_response(400, 'instanceId is required')

    if not finding_ids:
        return error_response(400,
            'finding_ids is required. Call errors() or search() first to retrieve findings, '
            'then pass the finding_ids here. This tool does NOT perform its own retrieval.')

    # Load findings index
    prefix = f'eks_{instance_id}'
    index_key = find_findings_index(prefix)
    if not index_key:
        return error_response(404, f'No findings index for {instance_id}. Run errors() first.')

    index_data = json.loads(safe_s3_read(index_key)['content'])
    all_findings = {f['finding_id']: f for f in index_data.get('findings', [])}

    # Resolve requested findings
    resolved = []
    missing = []
    for fid in finding_ids:
        if fid in all_findings:
            resolved.append(all_findings[fid])
        else:
            missing.append(fid)

    if missing:
        return error_response(400,
            f'Unknown finding_ids: {missing}. '
            f'Available: {list(all_findings.keys())[:20]}')

    # Build report from ONLY the cited findings (no independent retrieval)
    critical = [f for f in resolved if f['severity'] == 'critical']
    high = [f for f in resolved if f['severity'] == 'high']
    warnings = [f for f in resolved if f['severity'] in ('medium', 'low')]

    report = {
        'instanceId': instance_id,
        'generatedAt': datetime.utcnow().isoformat(),
        'finding_ids_requested': finding_ids,
        'finding_ids_resolved': len(resolved),
        'findings': [
            {
                'finding_id': f['finding_id'],
                'severity': f['severity'],
                'pattern': f['pattern'],
                'evidence': f['evidence'],
                'count': f.get('count', 1),
            }
            for f in resolved
        ],
        'affected_components': list(set(
            categorize_log_source(f['evidence']['source_file']) for f in resolved
        )),
        'recommendations': generate_recommendations(critical, high, warnings)
            if arguments.get('includeRecommendations', True) else [],
        'confidence': {
            'level': 'high' if len(critical) > 0 or len(high) > 0 else 'medium',
            'basis': f'{len(resolved)} findings analyzed',
            'gaps': [],
        },
        'coverage_report': index_data.get('coverage', {}),
        'truncated': False,
        'caveat': 'Report based on log pattern matching. Verify with kubectl and pod-level inspection.',
    }

    # Identify gaps
    coverage = index_data.get('coverage', {})
    if coverage.get('coverage_pct', 100) < 90:
        report['confidence']['gaps'].append(
            f"Only {coverage['coverage_pct']}% of files scanned. "
            f"Missing: {coverage.get('skipped_files', [])[:5]}"
        )
        report['confidence']['level'] = 'medium'

    return success_response(report)
```

### 4.3 Add `confidence` and `gaps` to all interpretation responses

Every tool that returns conclusions (not raw data) must include:
```python
'confidence': {
    'level': 'high' | 'medium' | 'low',
    'basis': 'description of what was analyzed',
    'gaps': ['list of known limitations'],
}
```

Apply to: `summarize`, `correlate`, `network_diagnostics`, `compare_nodes`, `cluster_health`.

### 4.4 Add temporal event clusters to `correlate` output *(GAP 4.4 — SHOULD)*

**Research requirement:** `correlate_timeline` should return structured `clusters` — groups of temporally related events with a `cluster_id`, `time_range`, `events[]`, and `dominant_severity`.

**File:** `src/lambda/ssm-automation-enhanced.py` → `correlate_events()` — after building timeline:

```python
def cluster_timeline_events(timeline, window_seconds=30):
    """Group temporally adjacent events into clusters."""
    clusters = []
    current_cluster = None
    for event in sorted(timeline, key=lambda e: e.get('timestamp', '')):
        ts = parse_timestamp(event.get('timestamp'))
        if ts is None:
            continue
        if current_cluster is None or (ts - current_cluster['end_time']).total_seconds() > window_seconds:
            if current_cluster:
                current_cluster['event_count'] = len(current_cluster['events'])
                clusters.append(current_cluster)
            current_cluster = {
                'cluster_id': f'C-{len(clusters)+1:03d}',
                'start_time': ts.isoformat(),
                'end_time': ts,
                'events': [event],
                'dominant_severity': event.get('severity', 'info'),
            }
        else:
            current_cluster['events'].append(event)
            current_cluster['end_time'] = ts
            if severity_rank(event.get('severity')) < severity_rank(current_cluster['dominant_severity']):
                current_cluster['dominant_severity'] = event['severity']
    if current_cluster:
        current_cluster['end_time'] = current_cluster['end_time'].isoformat()
        current_cluster['event_count'] = len(current_cluster['events'])
        clusters.append(current_cluster)
    return clusters

SEVERITY_RANK = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
def severity_rank(s): return SEVERITY_RANK.get(s, 4)
```

Add to `correlate` response:
```python
response['clusters'] = cluster_timeline_events(timeline, window_seconds=time_window)
```

**Impact:** Agent can report "3 event clusters detected: C-001 (10:25:03-10:25:08, 5 events, critical), C-002 (10:26:00-10:26:15, 3 events, medium)".

### 4.5 Add `potential_root_cause_chain` to `correlate` output *(GAP 4.5 — SHOULD)*

**Research requirement:** Correlate should attempt to build causal chains: event A → event B → event C, with confidence.

**File:** `src/lambda/ssm-automation-enhanced.py` → after `cluster_timeline_events()`:

```python
KNOWN_CAUSAL_CHAINS = {
    'IP exhaustion': ['CNI not ready', 'pod scheduling failure'],
    'OOM killer invoked': ['container OOMKilled', 'pod evicted'],
    'disk pressure': ['pod evicted', 'image pull failure'],
    'certificate error': ['API server unreachable', 'node NotReady'],
    'kubelet not ready': ['node NotReady', 'pod scheduling failure'],
    'ENI attachment': ['IP exhaustion', 'pod scheduling failure'],
}

def build_root_cause_chains(clusters):
    """Identify known causal chains within event clusters."""
    chains = []
    for cluster in clusters:
        patterns = [e.get('pattern', '') for e in cluster.get('events', [])]
        for root, expected_chain in KNOWN_CAUSAL_CHAINS.items():
            if any(root.lower() in p.lower() for p in patterns):
                matched = [root] + [c for c in expected_chain if any(c.lower() in p.lower() for p in patterns)]
                if len(matched) > 1:
                    chains.append({
                        'chain': matched,
                        'confidence': 'high' if len(matched) == len(expected_chain) + 1 else 'medium',
                        'cluster_id': cluster['cluster_id'],
                    })
    return chains
```

Add to `correlate` response:
```python
response['potential_root_cause_chains'] = build_root_cause_chains(response.get('clusters', []))
```

**Risk mitigation:** Causal inference uses only known-chain patterns (not ML). Confidence levels clearly distinguish full-chain matches from partial. Agent is instructed to present chains as "potential" not "confirmed".

---

## Phase 5: Observability + Security Hardening

**Timeline:** 5-6 days *(+2 days for GAP 6.3 KMS context, GAP 6.4 PII redaction, GAP 6.5 VPC endpoint)*
**Risk:** Low — additive; no behavioral changes. PII redaction feature-flagged.
**Rollback:** Remove tracing middleware; Lambda still works. Disable PII redaction via env var.

### 5.1 OpenTelemetry tracing

**File:** `src/lambda/ssm-automation-enhanced.py`

Add Lambda layer for AWS Distro for OpenTelemetry (ADOT):

```python
# At top of lambda_handler:
from aws_lambda_powertools import Tracer
tracer = Tracer()

@tracer.capture_method
def get_error_summary(arguments):
    tracer.put_annotation('tool', 'errors')
    tracer.put_annotation('instance_id', arguments.get('instanceId', ''))
    # ... existing code ...
    tracer.put_metadata('files_scanned', coverage['files_scanned'])
    tracer.put_metadata('findings_count', len(findings))
```

**File:** `src/ssm-automation-gateway-construct-v2.ts` — add ADOT layer:
```typescript
const adotLayer = lambda.LayerVersion.fromLayerVersionArn(
  this, 'AdotLayer',
  `arn:aws:lambda:${cdk.Aws.REGION}:901920570463:layer:aws-otel-python-amd64-ver-1-25-0:1`
);
ssmLambda.addLayers(adotLayer);
ssmLambda.addEnvironment('AWS_LAMBDA_EXEC_WRAPPER', '/opt/otel-instrument');
```

**Metrics to emit:**
| Metric | Type | Description |
|--------|------|-------------|
| `tool.latency` | Histogram | Per-tool p50/p95/p99 |
| `tool.success_rate` | Counter | Success vs error |
| `tool.bytes_scanned` | Counter | S3 bytes read |
| `tool.files_scanned` | Counter | Files processed |
| `tool.time_to_first_finding` | Histogram | Latency to first result |
| `tool.findings_count` | Histogram | Findings per invocation |

### 5.2 Evaluation-ready interface

Add a `_debug` envelope to every response when `X-Debug: true` header is present:

```python
if os.environ.get('ENABLE_DEBUG_ENVELOPE') == 'true':
    response_body['_debug'] = {
        'tool': tool_name,
        'input_hash': hashlib.sha256(json.dumps(arguments, sort_keys=True).encode()).hexdigest(),
        'output_hash': hashlib.sha256(body.encode()).hexdigest(),
        'latency_ms': int((time.time() - start) * 1000),
        'schema_version': '2.0',
        'deterministic': True,  # Same input → same output (for cached findings)
    }
```

This enables building a regression suite: capture `(input_hash, output_hash)` pairs and assert
stability across deployments.

### 5.3 KMS encryption context on S3 writes *(GAP 6.3 — SHOULD)*

**Research requirement:** Include encryption context with `job_id` on all S3 writes so CloudTrail logs show which job wrote which object. Enables audit trail for compliance.

**File:** `src/lambda/ssm-automation-enhanced.py` — in all `s3_client.put_object()` calls:

```python
def s3_put_with_context(key: str, body: str, execution_id: str = None, tool_name: str = ''):
    """Wrapper for S3 put_object with KMS encryption context."""
    params = {
        'Bucket': LOGS_BUCKET,
        'Key': key,
        'Body': body,
        'ContentType': 'application/json',
    }
    kms_key_id = os.environ.get('KMS_KEY_ID')
    if kms_key_id:
        params['ServerSideEncryption'] = 'aws:kms'
        params['SSEKMSKeyId'] = kms_key_id
        params['SSEKMSEncryptionContext'] = json.dumps({
            'job_id': execution_id or 'unknown',
            'tool': tool_name,
            'timestamp': datetime.utcnow().isoformat(),
        })
    s3_client.put_object(**params)
```

**File:** `src/ssm-automation-gateway-construct-v2.ts` — ensure KMS key policy allows `kms:EncryptionContextKeys` condition:
```typescript
kmsKey.addToResourcePolicy(new iam.PolicyStatement({
  actions: ['kms:Encrypt', 'kms:GenerateDataKey'],
  principals: [ssmLambda.role!],
  resources: ['*'],
  conditions: {
    StringEquals: {
      'kms:EncryptionContext:tool': ['errors', 'search', 'correlate', 'summarize', 'collect'],
    },
  },
}));
```

### 5.4 PII/PHI redaction on evidence excerpts *(GAP 6.4 — SHOULD)*

**Research requirement:** Log excerpts returned to the agent may contain PII (IP addresses, hostnames, usernames, tokens). Use Amazon Comprehend `DetectPiiEntities` to redact before returning.

**File:** `src/lambda/ssm-automation-enhanced.py` — add redaction helper:

```python
comprehend_client = boto3.client('comprehend') if os.environ.get('ENABLE_PII_REDACTION') else None

def redact_pii(text: str, redact_types: List[str] = None) -> str:
    """Redact PII from text using Amazon Comprehend. Feature-flagged."""
    if not comprehend_client or not text:
        return text
    if len(text) > 5000:  # Comprehend limit per call
        text = text[:5000]
    try:
        response = comprehend_client.detect_pii_entities(Text=text, LanguageCode='en')
        for entity in sorted(response['Entities'], key=lambda e: e['BeginOffset'], reverse=True):
            if redact_types is None or entity['Type'] in redact_types:
                text = text[:entity['BeginOffset']] + f'[{entity["Type"]}]' + text[entity['EndOffset']:]
        return text
    except Exception:
        return text  # Fail open — don't block on redaction failure
```

Apply to `evidence.excerpt` in all finding responses:
```python
# In format_finding():
finding['evidence']['excerpt'] = redact_pii(finding['evidence']['excerpt'])
```

**File:** `src/ssm-automation-gateway-construct-v2.ts` — add Comprehend permissions:
```typescript
ssmLambda.addToRolePolicy(new iam.PolicyStatement({
    actions: ['comprehend:DetectPiiEntities'],
    resources: ['*'],
}));
ssmLambda.addEnvironment('ENABLE_PII_REDACTION', 'false');  // Default off
```

**Risk:** Comprehend adds ~100-200ms latency per call and ~$0.0001 per 100 chars. Feature-flagged via `ENABLE_PII_REDACTION` env var.

### 5.5 S3 VPC endpoint policy *(GAP 6.5 — SHOULD)*

**Research requirement:** If Lambda runs in a VPC, the S3 VPC endpoint should restrict access to only the logs bucket. Prevents data exfiltration.

**File:** `src/ssm-automation-gateway-construct-v2.ts` — if VPC is configured:

```typescript
// Only applies when Lambda is VPC-attached (future hardening)
if (props.vpc) {
  const s3Endpoint = props.vpc.addGatewayEndpoint('S3Endpoint', {
    service: ec2.GatewayVpcEndpointAwsService.S3,
  });
  s3Endpoint.addToPolicy(new iam.PolicyStatement({
    principals: [new iam.AnyPrincipal()],
    actions: ['s3:GetObject', 's3:PutObject', 's3:ListBucket', 's3:HeadObject'],
    resources: [logsBucket.bucketArn, `${logsBucket.bucketArn}/*`],
  }));
}
```

**Note:** Currently Lambda is not VPC-attached. This is a future hardening item, included here so it's not forgotten when VPC attachment is added.

---

## Phase 6: Evaluation Framework *(NEW — from GAP 5.1, 5.2, 5.6)*

**Timeline:** 5 days
**Risk:** Low — test infrastructure only, no production impact
**Rollback:** N/A — test code only
**Dependencies:** Phase 0 (finding_id format), Phase 2 (findings_index v2)

### 6.1 Test harness architecture *(GAP 5.1 — SHOULD)*

**Research requirement:** Structured evaluation framework with synthetic log bundles, ground truth labels, automated comparison, and CI-integrated regression runs.

**Create:** `tests/evaluation/` directory:

```
tests/evaluation/
├── test_bundles/                    # Synthetic S3 bundles with known errors
│   ├── oom_bundle/                  # OOM scenario: kernel + kubelet + containerd
│   │   ├── var_log/messages         # Injected: 3x OOM killer
│   │   ├── kubelet/kubelet.log      # Injected: 5x OOMKilled
│   │   └── containerd/containerd.log
│   ├── cni_failure_bundle/          # CNI/networking scenario
│   ├── cert_expiry_bundle/          # Certificate expiry scenario
│   └── mixed_bundle/               # Multiple issue types
├── ground_truth/                    # Expected findings per bundle
│   ├── oom_bundle.json              # {"findings": [{"finding_id": "F-001", "severity": "critical", ...}]}
│   ├── cni_failure_bundle.json
│   ├── cert_expiry_bundle.json
│   └── mixed_bundle.json
├── eval_runner.py                   # Invokes tools against bundles, compares to ground truth
├── metrics.py                       # Computes precision, recall, F1, hallucination rate
└── conftest.py                      # Pytest fixtures for S3 mock / localstack
```

**File:** `tests/evaluation/eval_runner.py`:

```python
import json
from typing import Dict, List, Tuple

def evaluate_tool(tool_name: str, test_input: Dict, ground_truth: Dict) -> Dict:
    """Run a tool against a test bundle and compare to ground truth."""
    response = invoke_tool(tool_name, test_input)
    predicted = extract_finding_ids(response)
    expected = set(f['finding_id'] for f in ground_truth['findings'])

    tp = len(predicted & expected)
    fp = len(predicted - expected)
    fn = len(expected - predicted)

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)

    # Hallucination: findings with no evidence or fabricated evidence
    hallucinated = [fid for fid in predicted - expected
                    if not has_valid_evidence(response, fid)]

    return {
        'tool': tool_name,
        'precision': round(precision, 3),
        'recall': round(recall, 3),
        'f1': round(f1, 3),
        'true_positives': tp,
        'false_positives': fp,
        'false_negatives': fn,
        'hallucination_count': len(hallucinated),
        'hallucination_rate': round(len(hallucinated) / max(len(predicted), 1), 3),
    }

def run_full_evaluation(bundles_dir: str, ground_truth_dir: str) -> List[Dict]:
    """Run evaluation across all test bundles."""
    results = []
    for bundle in list_bundles(bundles_dir):
        gt = load_ground_truth(ground_truth_dir, bundle)
        for tool in ['errors', 'search', 'correlate']:
            result = evaluate_tool(tool, build_input(bundle, tool), gt)
            result['bundle'] = bundle
            results.append(result)
    return results
```

### 6.2 Define 9 evaluation metrics *(GAP 5.2 — SHOULD)*

**File:** `tests/evaluation/metrics.py`:

```python
from dataclasses import dataclass
from typing import List, Dict

@dataclass
class EvaluationMetrics:
    """9 metrics from research requirements."""
    finding_precision: float      # correct findings / total returned
    finding_recall: float         # correct findings / total actual errors
    hallucination_rate: float     # fabricated findings / total returned
    citation_accuracy: float      # findings with valid evidence / total findings
    coverage_completeness: float  # files scanned / total files (from coverage_report)
    severity_accuracy: float      # correctly classified severity / total findings
    latency_p50_ms: float         # per-tool p50 latency
    latency_p95_ms: float         # per-tool p95 latency
    time_to_first_finding_ms: float  # time from tool call to first finding

def compute_citation_accuracy(response: Dict) -> float:
    """Check that every finding has valid evidence with source_file and excerpt."""
    findings = response.get('findings', [])
    if not findings:
        return 1.0
    valid = sum(1 for f in findings
                if f.get('evidence', {}).get('source_file')
                and f.get('evidence', {}).get('excerpt'))
    return round(valid / len(findings), 3)

def compute_severity_accuracy(predicted: List[Dict], ground_truth: List[Dict]) -> float:
    """Compare severity classifications against ground truth."""
    gt_map = {f['finding_id']: f['severity'] for f in ground_truth}
    correct = sum(1 for f in predicted
                  if f['finding_id'] in gt_map
                  and f['severity'] == gt_map[f['finding_id']])
    matched = sum(1 for f in predicted if f['finding_id'] in gt_map)
    return round(correct / max(matched, 1), 3)
```

**Integration:** Phase 5.1 OTEL covers `latency_p50_ms`, `latency_p95_ms`, `time_to_first_finding_ms`. The remaining 6 metrics are computed by the eval runner.

### 6.3 Baseline subtraction *(GAP 5.6 — SHOULD)*

**Research requirement:** Maintain per-cluster error baselines so "normal" errors are flagged as `baseline` rather than `new`. Prevents alert fatigue.

**DynamoDB record type:**
```json
{
  "pk": "BASELINE#my-cluster#OOM killer invoked",
  "sk": "BASELINE",
  "clusterName": "my-cluster",
  "pattern": "OOM killer invoked",
  "count": 47,
  "first_seen": "2025-01-01T00:00:00Z",
  "last_seen": "2025-01-14T23:59:00Z",
  "is_baseline": true,
  "ttl": 1740000000
}
```

**File:** `src/lambda/ssm-automation-enhanced.py` — in `get_error_summary()`:

```python
def load_baselines(cluster_name: str) -> Dict[str, Dict]:
    """Load baseline patterns for a cluster from DynamoDB."""
    if not state_table or not cluster_name:
        return {}
    try:
        resp = state_table.query(
            KeyConditionExpression=Key('pk').begins_with(f'BASELINE#{cluster_name}#'),
        )
        return {item['pattern']: item for item in resp.get('Items', [])}
    except Exception:
        return {}

def update_baseline(cluster_name: str, pattern: str):
    """Increment baseline counter for a pattern."""
    if not state_table or not cluster_name:
        return
    import time
    state_table.update_item(
        Key={'pk': f'BASELINE#{cluster_name}#{pattern}', 'sk': 'BASELINE'},
        UpdateExpression='SET #count = if_not_exists(#count, :zero) + :one, '
                         'last_seen = :now, clusterName = :cluster, pattern = :pattern, '
                         'is_baseline = if_not_exists(is_baseline, :false), '
                         'ttl = :ttl',
        ExpressionAttributeNames={'#count': 'count'},
        ExpressionAttributeValues={
            ':one': 1, ':zero': 0,
            ':now': datetime.utcnow().isoformat(),
            ':cluster': cluster_name, ':pattern': pattern,
            ':false': False,
            ':ttl': int(time.time()) + 2592000,  # 30 day TTL
        },
    )
```

Apply in `get_error_summary()`:
```python
# After loading findings, annotate with baseline info
cluster_name = arguments.get('clusterContext')
if cluster_name:
    baselines = load_baselines(cluster_name)
    for finding in findings:
        baseline = baselines.get(finding['pattern'])
        if baseline and baseline.get('count', 0) > 10:
            finding['is_baseline'] = True
            finding['baseline_note'] = (
                f'This pattern has been seen {baseline["count"]} times '
                f'across cluster {cluster_name}. Likely normal operation.'
            )
    # Update baselines with current findings
    for finding in findings:
        update_baseline(cluster_name, finding['pattern'])
```

**Note:** Baseline data requires a collection period (~1-2 weeks) before it becomes useful. Initial deployments will have no baselines, so all findings appear as `new`.

---

## Section 2: Tool Contract Updates (Complete)

### Tool: `collect` (start_collection_job)

```yaml
Name: collect
Description: >
  Start EKS log collection from a worker node. Returns a Task object for async polling.
  Supports idempotency tokens to prevent duplicate SSM executions.
  Supports cross-region: auto-detects instance region or accepts explicit region parameter.
  IMPORTANT: This is a long-running operation. Poll with status() using the returned taskId.
Execution:
  TaskSupport: required
InputSchema:
  Type: object
  Properties:
    instanceId: { Type: string, Description: "EC2 instance ID (e.g., i-0123456789abcdef0)" }
    idempotencyToken: { Type: string, Description: "Dedup token. Same token+instance returns existing task." }
    region: { Type: string, Description: "AWS region (auto-detected if omitted)" }
  Required: [instanceId]
OutputSchema:
  Type: object
  Properties:
    task:
      Type: object
      Properties:
        taskId: { Type: string }
        state: { Type: string, Enum: [working, completed, failed, cancelled] }
        message: { Type: string }
        ttl: { Type: integer, Description: "Max seconds before timeout" }
        suggestedPollInterval: { Type: integer }
      Required: [taskId, state]
    executionId: { Type: string }
    instanceId: { Type: string }
    region: { Type: string }
    idempotencyKey: { Type: string }
  Required: [task, executionId, instanceId]
```

**Example response:**
```json
{
  "success": true,
  "task": {
    "taskId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "state": "working",
    "message": "Log collection started for i-0abc123def456",
    "ttl": 600,
    "suggestedPollInterval": 15
  },
  "executionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "instanceId": "i-0abc123def456",
  "region": "us-west-2",
  "idempotencyKey": "incident-2025-01-15-node1"
}
```

### Tool: `validate` (validate_manifest)

```yaml
Name: validate
Description: >
  Verify all expected files were extracted from the log bundle using manifest.json checksums.
  Returns file-level verification with coverage report.
  Call AFTER status() shows completed.
InputSchema:
  Type: object
  Properties:
    executionId: { Type: string }
    instanceId: { Type: string }
OutputSchema:
  Type: object
  Properties:
    manifest_version: { Type: string }
    complete: { Type: boolean }
    verified_files: { Type: integer }
    total_expected: { Type: integer }
    missing_files: { Type: array, Items: { Type: string } }
    corrupted_files:
      Type: array
      Items:
        Type: object
        Properties:
          file: { Type: string }
          expected_size: { Type: integer }
          actual_size: { Type: integer }
    coverage_report:
      Type: object
      Properties:
        files_scanned: { Type: integer }
        total_files: { Type: integer }
        coverage_pct: { Type: number }
        missing_files: { Type: array, Items: { Type: string } }
    truncated: { Type: boolean, Const: false }
```

### Tool: `errors` (get_findings)

```yaml
Name: errors
Description: >
  Get pre-indexed error findings by severity (fast path — reads findings_index.json).
  Each finding has a finding_id (e.g., F-001) and evidence object with source file, excerpt, and line range.
  When reporting to the user, you MUST cite finding_id and quote evidence.excerpt verbatim.
  Returns coverage_report showing scan completeness.
InputSchema:
  Type: object
  Properties:
    instanceId: { Type: string, Description: "EC2 instance ID" }
    severity: { Type: string, Enum: [critical, high, medium, low, info, all], Description: "Filter (default: all)" }
    response_format: { Type: string, Enum: [concise, detailed], Description: "concise = finding_id+severity+pattern. detailed = full evidence (default)." }
    pageSize: { Type: integer, Description: "Results per page (default: 50, max: 200)" }
    pageToken: { Type: string, Description: "Cursor from previous response for next page" }
  Required: [instanceId]
OutputSchema:
  Type: object
  Properties:
    instanceId: { Type: string }
    findings:
      Type: array
      Items:
        Type: object
        Properties:
          finding_id: { Type: string, Pattern: "^F-\\d{3,}$" }
          severity: { Type: string, Enum: [critical, high, medium, low, info] }
          pattern: { Type: string }
          count: { Type: integer }
          evidence:
            Type: object
            Properties:
              source_file: { Type: string }
              full_key: { Type: string }
              excerpt: { Type: string, MaxLength: 500 }
              line_range: { Type: object, Properties: { start: { Type: integer }, end: { Type: integer } } }
              byte_offset: { Type: object, Properties: { start: { Type: integer }, end: { Type: integer } } }
              timestamp: { Type: string }
            Required: [source_file, excerpt]
        Required: [finding_id, severity, evidence]
    coverage_report:
      Type: object
      Properties:
        files_scanned: { Type: integer }
        total_files: { Type: integer }
        coverage_pct: { Type: number }
        skipped_files: { Type: array }
    pagination:
      Type: object
      Properties:
        page_size: { Type: integer }
        total_findings: { Type: integer }
        next_page_token: { Type: string }
        has_more: { Type: boolean }
    truncated: { Type: boolean }
```

**Example response:**
```json
{
  "success": true,
  "instanceId": "i-0abc123def456",
  "findings": [
    {
      "finding_id": "F-001",
      "severity": "critical",
      "pattern": "OOM killer invoked",
      "count": 3,
      "evidence": {
        "source_file": "var_log/messages",
        "full_key": "eks_i-0abc123def456/extracted/var_log/messages",
        "excerpt": "Jan 15 10:25:03 ip-10-0-1-5 kernel: Out of memory: Kill process 4567 (java) score 900 or sacrifice child",
        "line_range": {"start": 1523, "end": 1523},
        "byte_offset": {"start": 98304, "end": 98450},
        "timestamp": "2025-01-15T10:25:03Z"
      }
    },
    {
      "finding_id": "F-002",
      "severity": "high",
      "pattern": "container OOMKilled",
      "count": 5,
      "evidence": {
        "source_file": "kubelet/kubelet.log",
        "full_key": "eks_i-0abc123def456/extracted/kubelet/kubelet.log",
        "excerpt": "E0115 10:25:10 kubelet.go:1234] Container my-app in pod my-app-7b9f8 OOMKilled",
        "line_range": {"start": 4501, "end": 4501},
        "byte_offset": {"start": 512000, "end": 512100},
        "timestamp": "2025-01-15T10:25:10Z"
      }
    }
  ],
  "coverage_report": {
    "files_scanned": 42,
    "total_files": 47,
    "coverage_pct": 89.4,
    "skipped_files": [
      {"file": "containerd-images.txt", "reason": "config_file"},
      {"file": "modinfo/nvidia.txt", "reason": "not_log"}
    ]
  },
  "truncated": false
}
```

### Tool: `search` (search_logs)

```yaml
Name: search
Description: >
  Full-text regex search across all collected logs. Returns matches with evidence pointers.
  Each match includes finding_id, evidence.source_file, evidence.excerpt, and evidence.line_range.
  When reporting, MUST cite finding_id and quote evidence.excerpt.
  Handles files >10MB via chunked scanning or S3 Select. Returns coverage_report.
InputSchema:
  Type: object
  Properties:
    instanceId: { Type: string }
    query: { Type: string, Description: "Regex pattern (e.g., 'OOMKilled|MemoryPressure')" }
    logTypes: { Type: string, Description: "Comma-separated log types (default: all)" }
    maxResults: { Type: integer, Description: "Max results per file (default: 100, max: 500)" }
    response_format: { Type: string, Enum: [concise, detailed], Description: "concise = finding_id+severity+pattern. detailed = full evidence (default)." }
  Required: [instanceId, query]
OutputSchema:
  Type: object
  Properties:
    instanceId: { Type: string }
    query: { Type: string }
    results:
      Type: array
      Items:
        Type: object
        Properties:
          finding_id: { Type: string, Pattern: "^S-\\d{3,}$" }
          file: { Type: string }
          full_key: { Type: string }
          evidence:
            Type: object
            Properties:
              source_file: { Type: string }
              excerpt: { Type: string, MaxLength: 500 }
              line_range: { Type: object }
              byte_offset: { Type: object }
              timestamp: { Type: string }
            Required: [source_file, excerpt]
    coverage_report:
      Type: object
      Properties:
        files_scanned: { Type: integer }
        total_files: { Type: integer }
        coverage_pct: { Type: number }
        bytes_scanned: { Type: integer }
        skipped_files: { Type: array }
    truncated: { Type: boolean }
```

### Tool: `read` (fetch_log_chunk)

```yaml
Name: read
Description: >
  Byte-range streaming for log files with line-aligned chunking. NO TRUNCATION.
  Returns content trimmed to complete lines. Use byte_offset from findings for targeted reads.
InputSchema:
  Type: object
  Properties:
    logKey: { Type: string, Description: "S3 key from evidence.full_key" }
    startByte: { Type: integer, Description: "Start offset (default: 0)" }
    endByte: { Type: integer, Description: "End offset (default: start + 1MB)" }
    startLine: { Type: integer, Description: "Alternative: line number (1-based)" }
    lineCount: { Type: integer, Description: "Lines to return (default: 1000)" }
  Required: [logKey]
OutputSchema:
  Type: object
  Properties:
    logKey: { Type: string }
    content: { Type: string }
    startByte: { Type: integer }
    endByte: { Type: integer }
    lineCount: { Type: integer }
    totalSize: { Type: integer }
    hasMore: { Type: boolean }
    nextChunkStart: { Type: integer }
    truncated: { Type: boolean, Const: false }
    lineAligned: { Type: boolean, Const: true }
```

### Tool: `correlate` (correlate_timeline)

```yaml
Name: correlate
Description: >
  Cross-file timeline correlation. Groups events by component and identifies causal patterns.
  Each timeline entry includes finding_id and evidence. Cite finding_id when reporting.
InputSchema:
  Type: object
  Properties:
    instanceId: { Type: string }
    timeWindow: { Type: integer, Description: "Seconds around pivot (default: 60)" }
    pivotEvent: { Type: string }
    components: { Type: array }
    response_format: { Type: string, Enum: [concise, detailed], Description: "concise = finding_id+severity+pattern. detailed = full evidence (default)." }
  Required: [instanceId]
OutputSchema:
  Type: object
  Properties:
    timeline:
      Type: array
      Items:
        Type: object
        Properties:
          finding_id: { Type: string }
          timestamp: { Type: string }
          source: { Type: string }
          severity: { Type: string, Enum: [critical, high, medium, low, info] }
          event: { Type: string }
          evidence:
            Type: object
            Properties:
              source_file: { Type: string }
              excerpt: { Type: string, MaxLength: 500 }
    correlations: { Type: array }
    clusters:
      Type: array
      Description: "Temporal event clusters (GAP 4.4)"
      Items:
        Type: object
        Properties:
          cluster_id: { Type: string, Pattern: "^C-\\d{3,}$" }
          start_time: { Type: string }
          end_time: { Type: string }
          event_count: { Type: integer }
          dominant_severity: { Type: string, Enum: [critical, high, medium, low, info] }
          events: { Type: array }
    potential_root_cause_chains:
      Type: array
      Description: "Causal chains identified from known patterns (GAP 4.5)"
      Items:
        Type: object
        Properties:
          chain: { Type: array, Items: { Type: string } }
          confidence: { Type: string, Enum: [high, medium, low] }
          cluster_id: { Type: string }
    confidence:
      Type: object
      Properties:
        level: { Type: string, Enum: [high, medium, low] }
        basis: { Type: string }
        gaps: { Type: array, Items: { Type: string } }
    coverage_report: { Type: object }
```

### Tool: `summarize` (generate_incident_report)

```yaml
Name: summarize
Description: >
  Generate structured incident report from PREVIOUSLY RETRIEVED findings.
  REQUIRES finding_ids from errors() or search(). MUST call retrieval tools FIRST.
  Do NOT call this without prior evidence retrieval.
  When reporting to user, MUST cite finding_id and quote evidence.excerpt.
InputSchema:
  Type: object
  Properties:
    instanceId: { Type: string }
    finding_ids:
      Type: array
      Items: { Type: string }
      Description: "finding_ids from errors() or search(). REQUIRED."
    clusterContext: { Type: string }
    includeRecommendations: { Type: boolean }
  Required: [instanceId, finding_ids]
OutputSchema:
  Type: object
  Properties:
    instanceId: { Type: string }
    finding_ids_requested: { Type: array }
    finding_ids_resolved: { Type: integer }
    findings:
      Type: array
      Items:
        Type: object
        Properties:
          finding_id: { Type: string }
          severity: { Type: string }
          pattern: { Type: string }
          evidence: { Type: object }
          count: { Type: integer }
    affected_components: { Type: array, Items: { Type: string } }
    recommendations: { Type: array }
    confidence:
      Type: object
      Properties:
        level: { Type: string, Enum: [high, medium, low] }
        basis: { Type: string }
        gaps: { Type: array, Items: { Type: string } }
    coverage_report: { Type: object }
    truncated: { Type: boolean, Const: false }
```

---

## Section 3: S3 Artifact Schemas

### S3 Bundle Structure

```
s3://{LOGS_BUCKET}/
└── eks_{instanceId}/
    ├── manifest.json                          ← NEW: written by Unzip Lambda
    ├── findings_index.json                    ← UPGRADED: v2 with finding_ids + byte_offsets
    ├── {instanceId}_eks-log-collector.tar.gz  ← Original archive from SSM
    ├── extracted/                             ← Unzipped by Unzip Lambda
    │   ├── kubelet/
    │   │   └── kubelet.log
    │   ├── containerd/
    │   │   └── containerd.log
    │   ├── var_log/
    │   │   ├── messages
    │   │   ├── dmesg
    │   │   └── secure
    │   ├── networking/
    │   │   ├── iptables-save.txt
    │   │   ├── ip-route.txt
    │   │   └── ifconfig.txt
    │   ├── pods/
    │   │   └── ...
    │   ├── storage/
    │   │   └── ...
    │   └── ...
    └── metadata/
        └── region.txt                         ← Existing: stores execution region
```

### `manifest.json` Schema

Written by the Unzip Lambda immediately after extraction completes.
Read by `validate` for checksum-based verification.

```json
{
  "version": "2.0",
  "instanceId": "i-0abc123def456",
  "createdAt": "2025-01-15T10:20:00Z",
  "source_archive": "eks_i-0abc123def456/i-0abc123def456_eks-log-collector.tar.gz",
  "source_archive_size_bytes": 52428800,
  "source_archive_md5": "d41d8cd98f00b204e9800998ecf8427e",
  "extraction_duration_ms": 3200,
  "expected_files": [
    {
      "key": "eks_i-0abc123def456/extracted/kubelet/kubelet.log",
      "relative_path": "kubelet/kubelet.log",
      "size_bytes": 2097152,
      "md5": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
      "status": "extracted",
      "file_type": "log"
    },
    {
      "key": "eks_i-0abc123def456/extracted/networking/iptables-save.txt",
      "relative_path": "networking/iptables-save.txt",
      "size_bytes": 8192,
      "md5": "f6e5d4c3b2a1f6e5d4c3b2a1f6e5d4c3",
      "status": "extracted",
      "file_type": "config"
    }
  ],
  "total_files": 47,
  "total_size_bytes": 157286400,
  "file_type_summary": {
    "log": 32,
    "config": 10,
    "binary": 3,
    "unknown": 2
  }
}
```

**Field definitions:**

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Schema version. Always `"2.0"` for new format. |
| `instanceId` | string | EC2 instance ID this bundle belongs to. |
| `createdAt` | string (ISO 8601) | When extraction completed. |
| `source_archive` | string | S3 key of the original `.tar.gz`. |
| `source_archive_size_bytes` | integer | Size of the archive before extraction. |
| `source_archive_md5` | string | MD5 of the archive for integrity. |
| `extraction_duration_ms` | integer | How long extraction took. |
| `expected_files[].key` | string | Full S3 key of the extracted file. |
| `expected_files[].relative_path` | string | Path relative to `extracted/`. |
| `expected_files[].size_bytes` | integer | Expected file size after extraction. |
| `expected_files[].md5` | string | MD5 checksum of extracted content. |
| `expected_files[].status` | enum | `extracted` / `failed` / `skipped` |
| `expected_files[].file_type` | enum | `log` / `config` / `binary` / `unknown` |
| `total_files` | integer | Count of all entries in `expected_files`. |
| `total_size_bytes` | integer | Sum of all `size_bytes`. |
| `file_type_summary` | object | Count by `file_type`. |

### `findings_index.json` Schema (v2)

Written by the Findings Indexer Lambda after Unzip completes.
Read by `errors` (Tier 1 fast path) and `summarize` (for finding resolution).

```json
{
  "version": "2.0",
  "instanceId": "i-0abc123def456",
  "indexedAt": "2025-01-15T10:20:05Z",
  "manifest_ref": "eks_i-0abc123def456/manifest.json",
  "indexing_duration_ms": 4500,
  "coverage": {
    "files_scanned": 42,
    "total_files": 47,
    "coverage_pct": 89.4,
    "bytes_scanned": 134217728,
    "skipped_files": [
      {
        "file": "containerd-images.txt",
        "reason": "config_file",
        "size_bytes": 4096
      },
      {
        "file": "modinfo/nvidia.txt",
        "reason": "not_log",
        "size_bytes": 2048
      },
      {
        "file": "coredump.bin",
        "reason": "binary",
        "size_bytes": 10485760
      }
    ]
  },
  "findings": [
    {
      "finding_id": "F-001",
      "severity": "critical",
      "pattern": "OOM killer invoked",
      "description": "Kernel invoked the OOM killer to free memory",
      "count": 3,
      "first_seen": "2025-01-15T10:25:03Z",
      "last_seen": "2025-01-15T10:25:08Z",
      "confirmation": {
        "signals": 2,
        "confirmed": true,
        "sources": ["var_log/messages", "kubelet/kubelet.log"]
      },
      "evidence": {
        "source_file": "var_log/messages",
        "full_key": "eks_i-0abc123def456/extracted/var_log/messages",
        "excerpt": "Jan 15 10:25:03 ip-10-0-1-5 kernel: [12345.678] Out of memory: Kill process 4567 (java) score 900 or sacrifice child",
        "line_range": {
          "start": 1523,
          "end": 1523
        },
        "byte_offset": {
          "start": 98304,
          "end": 98450
        },
        "timestamp": "2025-01-15T10:25:03Z"
      },
      "additional_occurrences": [
        {
          "line": 1530,
          "byte_offset": 98700,
          "timestamp": "2025-01-15T10:25:05Z"
        },
        {
          "line": 1542,
          "byte_offset": 99100,
          "timestamp": "2025-01-15T10:25:08Z"
        }
      ]
    },
    {
      "finding_id": "F-002",
      "severity": "high",
      "pattern": "container OOMKilled",
      "description": "Container exceeded memory limit and was killed",
      "count": 5,
      "first_seen": "2025-01-15T10:25:10Z",
      "last_seen": "2025-01-15T10:25:15Z",
      "evidence": {
        "source_file": "kubelet/kubelet.log",
        "full_key": "eks_i-0abc123def456/extracted/kubelet/kubelet.log",
        "excerpt": "E0115 10:25:10.123456 1234 kubelet.go:1234] Container my-app in pod my-app-7b9f8c6d5-x2k4m OOMKilled",
        "line_range": {
          "start": 4501,
          "end": 4501
        },
        "byte_offset": {
          "start": 512000,
          "end": 512100
        },
        "timestamp": "2025-01-15T10:25:10Z"
      },
      "additional_occurrences": [
        {
          "line": 4510,
          "byte_offset": 513000,
          "timestamp": "2025-01-15T10:25:15Z"
        }
      ]
    }
  ],
  "summary": {
    "critical": 5,
    "high": 8,
    "medium": 4,
    "low": 2,
    "info": 3,
    "total": 22
  }
}
```

**Key differences from v1:**

| Field | v1 (current) | v2 (new) |
|-------|-------------|----------|
| `version` | absent | `"2.0"` |
| `finding_id` | absent | `"F-001"` sequential |
| `severity` levels | 3 (`critical`/`warning`/`info`) | 5 (`critical`/`high`/`medium`/`low`/`info`) |
| `first_seen`/`last_seen` | absent | ISO 8601 timestamps *(GAP 4.3)* |
| `confirmation` | absent | `{signals, confirmed, sources}` for CRITICAL *(GAP 5.5)* |
| `evidence` wrapper | absent (flat `file`, `sample`) | structured object |
| `evidence.byte_offset` | absent | `{start, end}` for Tier 3 reads |
| `evidence.line_range` | absent | `{start, end}` for line reads |
| `evidence.timestamp` | absent | parsed from log line |
| `coverage` | absent | full scan coverage report |
| `manifest_ref` | absent | pointer to `manifest.json` |
| `additional_occurrences` | `lines[]` (line numbers only) | objects with byte_offset + timestamp |
| `description` | absent | human-readable pattern description |

**Backward compatibility:** The `errors` tool checks `version` field. If absent or `"1.0"`,
it falls back to the old flat format. The Findings Indexer always writes v2 going forward.

### Per-Node Index (Optional, for Scale)

For clusters with 100+ nodes where a single `findings_index.json` per node is sufficient,
no per-node sub-indices are needed. The current design (one index per instance prefix) already
scales to thousands of nodes since each node has its own S3 prefix.

For future consideration if a single node produces >500 findings:
```
eks_{instanceId}/
├── findings_index.json          ← Summary with top 500 findings
├── findings_detail/
│   ├── critical.json            ← All critical findings (no limit)
│   ├── high.json                ← All high findings
│   ├── medium.json              ← All medium findings
│   ├── low.json                 ← All low findings
│   └── info.json                ← All info findings
```

This is NOT required for Phase 2 but documented as a scaling escape hatch.

---

## Section 4: Idempotency & State Storage

### Current State

Idempotency currently uses S3 metadata files:
- `s3://{bucket}/idempotency/{instanceId}/{token}` → contains `executionId`
- Region stored at `s3://{bucket}/eks_{instanceId}/metadata/region.txt`
- Subject to S3 eventual consistency on reads-after-writes

### Target State: DynamoDB

#### Table Schema

```
Table: EksLogMcpState
Billing: PAY_PER_REQUEST
TTL attribute: ttl

Partition Key: pk (String)
Sort Key: sk (String)
```

#### Record Types

**1. Idempotency Record**
```json
{
  "pk": "IDEMP#i-0abc123def456#incident-2025-01-15-node1",
  "sk": "IDEMPOTENCY",
  "executionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "instanceId": "i-0abc123def456",
  "idempotencyToken": "incident-2025-01-15-node1",
  "taskState": "working",
  "region": "us-west-2",
  "createdAt": "2025-01-15T10:15:00Z",
  "updatedAt": "2025-01-15T10:15:00Z",
  "ttl": 1737043200
}
```

**2. Execution Region Record**
```json
{
  "pk": "EXEC#a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "sk": "REGION",
  "executionId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "region": "us-west-2",
  "instanceId": "i-0abc123def456",
  "createdAt": "2025-01-15T10:15:00Z",
  "ttl": 1737129600
}
```

**3. Batch Record** (for `batch_collect` tracking)
```json
{
  "pk": "BATCH#batch-20250115-103000-abc",
  "sk": "META",
  "batchId": "batch-20250115-103000-abc",
  "clusterName": "my-cluster",
  "region": "us-west-2",
  "executionIds": ["exec-1", "exec-2", "exec-3"],
  "strategy": "sample",
  "createdAt": "2025-01-15T10:30:00Z",
  "ttl": 1737129600
}
```

#### CDK Definition

**File:** `src/ssm-automation-gateway-construct-v2.ts`

```typescript
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';

const stateTable = new dynamodb.Table(this, 'StateTable', {
  tableName: `${props.stackPrefix || 'eks-log-mcp'}-state`,
  partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
  sortKey: { name: 'sk', type: dynamodb.AttributeType.STRING },
  billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
  timeToLiveAttribute: 'ttl',
  removalPolicy: cdk.RemovalPolicy.DESTROY,
  pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: false },
});

// Grant Lambda read/write
stateTable.grantReadWriteData(ssmLambda);

// Pass table name to Lambda
ssmLambda.addEnvironment('STATE_TABLE_NAME', stateTable.tableName);
```

#### Lambda Implementation

**File:** `src/lambda/ssm-automation-enhanced.py`

Replace S3-based idempotency functions:

```python
import boto3
from botocore.exceptions import ClientError

STATE_TABLE = os.environ.get('STATE_TABLE_NAME')
dynamodb_client = boto3.resource('dynamodb')
state_table = dynamodb_client.Table(STATE_TABLE) if STATE_TABLE else None

def find_execution_by_idempotency_token(instance_id: str, token: str) -> Optional[Dict]:
    """Atomic lookup of existing execution for idempotency token."""
    if not state_table:
        return None  # Fall back to S3 if DynamoDB not configured
    try:
        resp = state_table.get_item(
            Key={
                'pk': f'IDEMP#{instance_id}#{token}',
                'sk': 'IDEMPOTENCY',
            }
        )
        item = resp.get('Item')
        if item:
            return {
                'executionId': item['executionId'],
                'status': item.get('taskState', 'working'),
                'region': item.get('region'),
            }
        return None
    except Exception as e:
        print(f"DynamoDB lookup failed, falling back: {e}")
        return None  # Graceful degradation

def store_idempotency_mapping(instance_id: str, token: str, execution_id: str,
                               region: str = None):
    """Atomic store with conditional write to prevent races."""
    if not state_table:
        return  # Fall back to S3
    import time
    ttl = int(time.time()) + 86400  # 24h TTL
    try:
        state_table.put_item(
            Item={
                'pk': f'IDEMP#{instance_id}#{token}',
                'sk': 'IDEMPOTENCY',
                'executionId': execution_id,
                'instanceId': instance_id,
                'idempotencyToken': token,
                'taskState': 'working',
                'region': region or DEFAULT_REGION,
                'createdAt': datetime.utcnow().isoformat(),
                'updatedAt': datetime.utcnow().isoformat(),
                'ttl': ttl,
            },
            ConditionExpression='attribute_not_exists(pk)',  # Prevent overwrite
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            pass  # Already exists — idempotent, no-op
        else:
            print(f"DynamoDB store failed: {e}")

def store_execution_region(execution_id: str, region: str) -> bool:
    """Store execution→region mapping for cross-region resolution."""
    if not state_table:
        return False
    import time
    try:
        state_table.put_item(
            Item={
                'pk': f'EXEC#{execution_id}',
                'sk': 'REGION',
                'executionId': execution_id,
                'region': region,
                'createdAt': datetime.utcnow().isoformat(),
                'ttl': int(time.time()) + 172800,  # 48h TTL
            }
        )
        return True
    except Exception as e:
        print(f"Failed to store execution region: {e}")
        return False

def get_execution_region(execution_id: str) -> Optional[str]:
    """Resolve region for an execution ID."""
    if not state_table:
        return None
    try:
        resp = state_table.get_item(
            Key={
                'pk': f'EXEC#{execution_id}',
                'sk': 'REGION',
            }
        )
        item = resp.get('Item')
        return item.get('region') if item else None
    except Exception:
        return None
```

#### Safe Retry Behavior

The idempotency flow:

```
Agent calls collect(instanceId="i-abc", idempotencyToken="tok-123")
  │
  ├─ DynamoDB get_item(pk="IDEMP#i-abc#tok-123")
  │   ├─ Found → return existing executionId (no SSM call)
  │   └─ Not found → continue
  │
  ├─ SSM StartAutomationExecution(...)
  │   └─ Returns executionId
  │
  ├─ DynamoDB put_item(ConditionExpression=attribute_not_exists(pk))
  │   ├─ Success → stored
  │   └─ ConditionalCheckFailed → race condition, another Lambda won
  │       └─ Read back the winner's executionId and return it
  │
  └─ Return executionId + task state
```

**Race condition handling:** If two concurrent Lambda invocations race with the same
idempotency token, the `ConditionExpression` ensures only one writes. The loser reads
back the winner's record and returns it. No duplicate SSM executions.

#### Migration Path

1. Deploy DynamoDB table alongside existing S3 metadata
2. Lambda checks DynamoDB first, falls back to S3
3. New writes go to DynamoDB only
4. After 48h (S3 TTL equivalent), S3 metadata is stale and DynamoDB is authoritative
5. Remove S3 fallback code in a follow-up deployment

---

## Section 5: Hallucination Reduction Guardrails

These are engineering-enforced constraints, not suggestions. They are implemented in tool
contracts (schemas), Lambda code (validation), and tool descriptions (agent instructions).

### Guardrail 1: Retrieval-Before-Report (Enforced)

**Mechanism:** `summarize` tool requires `finding_ids` input parameter.

```python
# In generate_incident_summary():
if not finding_ids:
    return error_response(400,
        'finding_ids is required. You MUST call errors() or search() first '
        'to retrieve findings, then pass finding_ids to this tool.')
```

**Tool description enforcement:**
```
"REQUIRES finding_ids from errors() or search(). MUST call retrieval tools FIRST.
 This tool does NOT perform its own evidence retrieval."
```

**What this prevents:** Agent generating a "summary" from its own knowledge without
actually reading the logs. Every claim in the report traces back to a specific finding.

### Guardrail 2: No Unstructured Conclusions (Enforced)

**Mechanism:** Every tool that returns interpretive content MUST include:
- `confidence.level` (high/medium/low)
- `confidence.basis` (what was analyzed)
- `confidence.gaps` (what was NOT analyzed)
- `caveat` (methodology limitations)

```python
# Template for all interpretation responses:
response['confidence'] = {
    'level': compute_confidence(coverage_pct, finding_count),
    'basis': f'Analyzed {files_scanned} files, {finding_count} findings',
    'gaps': gaps,
}
response['caveat'] = (
    'Analysis based on log pattern matching. '
    'Verify with kubectl describe node/pod and component-specific logs.'
)
```

**Confidence computation:**
```python
def compute_confidence(coverage_pct: float, finding_count: int) -> str:
    if coverage_pct >= 90 and finding_count > 0:
        return 'high'
    elif coverage_pct >= 70 or finding_count > 0:
        return 'medium'
    else:
        return 'low'
```

### Guardrail 3: Citation Requirement (Instructed + Validated)

**Tool descriptions** for all retrieval tools include:
```
"Each finding includes a finding_id (e.g., F-001) and evidence object.
 When reporting to the user, you MUST cite finding_id and quote evidence.excerpt verbatim."
```

**`summarize` output** includes findings with evidence, making it trivial for the agent
to cite rather than paraphrase:
```json
{
  "findings": [
    {
      "finding_id": "F-001",
      "evidence": {
        "excerpt": "Out of memory: Kill process 4567 (java) score 900"
      }
    }
  ]
}
```

The agent sees structured evidence and is instructed to quote it. This is not 100%
enforceable at the tool level (the agent could still ignore instructions), but the
combination of:
1. Structured output with `finding_id` prominently placed
2. Tool description with explicit citation instructions
3. `summarize` requiring `finding_ids` as input (proving retrieval happened)

...makes hallucination significantly harder than the current free-form approach.

### Guardrail 4: No Silent Truncation (Enforced)

**Every response** includes `truncated: false` or explicit truncation metadata:

```python
# In success_response() wrapper:
if '_payloadTruncated' in data:
    data['truncated'] = True
    data['truncation_info'] = {
        'original_count': data.get('_originalCount'),
        'returned_count': data.get('_returnedCount'),
        'next_step': 'Use more specific filters or fetch individual findings',
    }
else:
    data['truncated'] = False
```

**`read` tool** guarantees `truncated: false` — it returns exactly the requested byte range,
line-aligned. If the file is too large for direct return, it returns a presigned URL instead
of silently truncating.

### Guardrail 5: Coverage Transparency (Enforced)

**Every retrieval tool** returns `coverage_report`:
```json
{
  "coverage_report": {
    "files_scanned": 42,
    "total_files": 47,
    "coverage_pct": 89.4,
    "bytes_scanned": 134217728,
    "skipped_files": [
      {"file": "large-coredump.bin", "reason": "binary"},
      {"file": "containerd-images.txt", "reason": "config_file"}
    ]
  }
}
```

The agent sees exactly what was and wasn't scanned. If coverage is <100%, the agent
can report "42 of 47 files analyzed" rather than implying completeness.

### Guardrail Summary Matrix

| Guardrail | Where Enforced | Failure Mode |
|-----------|---------------|--------------|
| Retrieval-before-report | `summarize` input validation | 400 error with instructions |
| No unstructured conclusions | All interpretation tools | Always includes confidence+gaps |
| Citation requirement | Tool descriptions + output structure | Agent sees finding_id prominently |
| No silent truncation | `success_response()` wrapper | `truncated` field always present |
| Coverage transparency | All retrieval tools | `coverage_report` always present |

---

## Section 6: Acceptance Criteria (Definition of Done)

### AC-1: Schema-Valid Outputs (99%+)

**Test:** For each tool, call with valid inputs and validate response against `outputSchema`.
```bash
# Pseudocode for test harness
for tool in [errors, search, read, validate, correlate, summarize]:
    response = invoke_tool(tool, valid_input)
    assert jsonschema.validate(response, tool.outputSchema) == True
    assert 'truncated' in response
    assert isinstance(response['truncated'], bool)
```

**Pass criteria:** 99%+ of invocations return schema-valid responses (allowing for
transient AWS errors that return graceful error envelopes).

### AC-2: Every Report Cites finding_ids

**Test:** Call `summarize` with valid `finding_ids`. Verify response contains
the same `finding_ids` in the output `findings` array.
```python
response = invoke_tool('summarize', {
    'instanceId': 'i-test',
    'finding_ids': ['F-001', 'F-003']
})
output_ids = [f['finding_id'] for f in response['findings']]
assert set(output_ids) == {'F-001', 'F-003'}
assert all('evidence' in f for f in response['findings'])
assert all('excerpt' in f['evidence'] for f in response['findings'])
```

**Negative test:** Call `summarize` without `finding_ids`. Verify 400 error.
```python
response = invoke_tool('summarize', {'instanceId': 'i-test'})
assert response['statusCode'] == 400
assert 'finding_ids is required' in response['body']
```

### AC-3: validate_manifest Coverage Shown

**Test:** After collection + extraction, call `validate`. Verify manifest-based verification.
```python
response = invoke_tool('validate', {'instanceId': 'i-test'})
assert 'manifest_version' in response  # Uses manifest.json
assert 'coverage_report' in response
assert response['coverage_report']['total_files'] > 0
assert 0 <= response['coverage_report']['coverage_pct'] <= 100
assert isinstance(response['missing_files'], list)
```

### AC-4: fetch_log_chunk is Line-Aligned

**Test:** Read a chunk starting mid-file. Verify first and last characters are line boundaries.
```python
response = invoke_tool('read', {
    'logKey': 'eks_i-test/extracted/kubelet/kubelet.log',
    'startByte': 50000,
    'endByte': 51000
})
content = response['content']
assert response['lineAligned'] == True
# Content should not start with a partial line (unless startByte=0)
# Content should end with a newline
assert content.endswith('\n') or response['hasMore'] == False
# Verify byte offsets are adjusted
assert response['startByte'] >= 50000  # May be slightly after due to alignment
assert response['endByte'] <= 51000
```

### AC-5: Tasks Workflow End-to-End

**Test:** Full lifecycle of a long-running collection.
```python
# 1. Start collection
start = invoke_tool('collect', {
    'instanceId': 'i-test',
    'idempotencyToken': 'test-e2e-001'
})
assert start['task']['state'] == 'working'
assert start['task']['taskId'] is not None
assert start['task']['suggestedPollInterval'] > 0
task_id = start['task']['taskId']

# 2. Poll until complete
for _ in range(40):  # 40 * 15s = 10 min max
    status = invoke_tool('status', {'executionId': task_id})
    if status['task']['state'] in ('completed', 'failed'):
        break
    assert status['task']['state'] == 'working'
    assert status['task']['suggestedPollInterval'] > 0
    time.sleep(status['task']['suggestedPollInterval'])

assert status['task']['state'] == 'completed'

# 3. Idempotency: same token returns same execution
retry = invoke_tool('collect', {
    'instanceId': 'i-test',
    'idempotencyToken': 'test-e2e-001'
})
assert retry['executionId'] == task_id
assert retry.get('idempotent') == True  # Or similar flag
```

### AC-6: Coverage Report Present on All Retrieval Tools

**Test:** Every retrieval tool returns `coverage_report`.
```python
for tool, args in [
    ('errors', {'instanceId': 'i-test'}),
    ('search', {'instanceId': 'i-test', 'query': 'OOM'}),
    ('correlate', {'instanceId': 'i-test'}),
]:
    response = invoke_tool(tool, args)
    assert 'coverage_report' in response
    cr = response['coverage_report']
    assert 'files_scanned' in cr
    assert 'total_files' in cr
    assert 'coverage_pct' in cr
    assert isinstance(cr['coverage_pct'], (int, float))
```

### AC-7: finding_id Format Consistency

**Test:** All findings across all tools use the `F-NNN` format.
```python
response = invoke_tool('errors', {'instanceId': 'i-test'})
for finding in response['findings']:
    assert re.match(r'^F-\d{3,}$', finding['finding_id'])
    assert 'evidence' in finding
    assert 'source_file' in finding['evidence']
    assert 'excerpt' in finding['evidence']
    assert len(finding['evidence']['excerpt']) <= 500
```

### AC-8: Confidence + Gaps on Interpretation Tools

**Test:** Tools that return conclusions include confidence metadata.
```python
for tool, args in [
    ('summarize', {'instanceId': 'i-test', 'finding_ids': ['F-001']}),
    ('correlate', {'instanceId': 'i-test'}),
    ('network_diagnostics', {'instanceId': 'i-test'}),
]:
    response = invoke_tool(tool, args)
    assert 'confidence' in response
    assert response['confidence']['level'] in ('high', 'medium', 'low')
    assert 'basis' in response['confidence']
    assert isinstance(response['confidence']['gaps'], list)
```

### AC-9: 5-Level Severity Enum *(GAP 4.6)*

**Test:** All findings use the 5-level severity enum.
```python
response = invoke_tool('errors', {'instanceId': 'i-test'})
valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
for finding in response['findings']:
    assert finding['severity'] in valid_severities, f"Invalid severity: {finding['severity']}"

# Backward compat: old v1 index with 'warning' is mapped to 'medium'
old_index = load_v1_index()
response_old = invoke_tool_with_index('errors', old_index)
for finding in response_old['findings']:
    assert finding['severity'] != 'warning', "v1 'warning' should be mapped to 'medium'"
```

### AC-10: Pagination on `errors` *(GAP 3.6)*

**Test:** Cursor-based pagination returns all findings across pages.
```python
all_findings = []
page_token = None
while True:
    args = {'instanceId': 'i-test', 'pageSize': 10}
    if page_token:
        args['pageToken'] = page_token
    response = invoke_tool('errors', args)
    all_findings.extend(response['findings'])
    pagination = response.get('pagination', {})
    if not pagination.get('has_more'):
        break
    page_token = pagination['next_page_token']

assert len(all_findings) == pagination['total_findings']
assert len(set(f['finding_id'] for f in all_findings)) == len(all_findings)  # No duplicates
```

### AC-11: `response_format` Concise Mode *(GAP 2.7)*

**Test:** Concise mode returns minimal fields, detailed mode returns full evidence.
```python
concise = invoke_tool('errors', {'instanceId': 'i-test', 'response_format': 'concise'})
for f in concise['findings']:
    assert 'finding_id' in f
    assert 'severity' in f
    assert 'pattern' in f
    assert 'evidence' not in f  # Concise omits evidence

detailed = invoke_tool('errors', {'instanceId': 'i-test', 'response_format': 'detailed'})
for f in detailed['findings']:
    assert 'evidence' in f
    assert 'excerpt' in f['evidence']
```

### AC-12: `first_seen`/`last_seen` on Findings *(GAP 4.3)*

**Test:** Deduplicated findings with count > 1 have time range.
```python
response = invoke_tool('errors', {'instanceId': 'i-test'})
for f in response['findings']:
    if f.get('count', 1) > 1:
        assert 'first_seen' in f, f"Finding {f['finding_id']} missing first_seen"
        assert 'last_seen' in f, f"Finding {f['finding_id']} missing last_seen"
        assert f['first_seen'] <= f['last_seen']
```

### AC-13: Temporal Clusters in Correlate *(GAP 4.4)*

**Test:** Correlate returns structured event clusters.
```python
response = invoke_tool('correlate', {'instanceId': 'i-test'})
assert 'clusters' in response
for cluster in response['clusters']:
    assert re.match(r'^C-\d{3,}$', cluster['cluster_id'])
    assert 'start_time' in cluster
    assert 'end_time' in cluster
    assert 'event_count' in cluster
    assert cluster['dominant_severity'] in ('critical', 'high', 'medium', 'low', 'info')
    assert len(cluster['events']) == cluster['event_count']
```

### AC-14: Multi-Signal Confirmation for CRITICAL *(GAP 5.5)*

**Test:** CRITICAL findings include confirmation metadata.
```python
response = invoke_tool('errors', {'instanceId': 'i-test', 'severity': 'critical'})
for f in response['findings']:
    assert 'confirmation' in f
    assert 'signals' in f['confirmation']
    assert 'confirmed' in f['confirmation']
    assert isinstance(f['confirmation']['confirmed'], bool)
    if not f['confirmation']['confirmed']:
        assert 'severity_note' in f
```

### AC-15: Evaluation Metrics Compute Correctly *(GAP 5.1, 5.2)*

**Test:** Eval runner produces all 9 metrics against a known test bundle.
```python
from tests.evaluation.eval_runner import evaluate_tool
from tests.evaluation.metrics import compute_citation_accuracy

result = evaluate_tool('errors', oom_bundle_input, oom_ground_truth)
assert 0 <= result['precision'] <= 1
assert 0 <= result['recall'] <= 1
assert 0 <= result['f1'] <= 1
assert result['hallucination_rate'] >= 0
assert result['true_positives'] + result['false_negatives'] == len(oom_ground_truth['findings'])
```

---

## Appendix A: Change Impact Matrix

| File | Phase | Changes |
|------|-------|---------|
| `src/lambda/ssm-automation-enhanced.py` | 0,1,2,3,4,5,6 | finding_id, coverage, Tasks, DynamoDB, line-align, summarize gate, tracing, severity enum, response_format, pagination, temporal clusters, root cause chains, KMS context, PII redaction, baseline subtraction |
| `src/ssm-automation-gateway-construct-v2.ts` | 0,1,2,5 | outputSchema (5-level severity, pagination, response_format, clusters, root_cause_chains), TaskSupport, DynamoDB table, ADOT layer, manifest in unzip, KMS policy, Comprehend IAM, VPC endpoint |
| `src/ssm-automation-gateway-construct-v2.ts` (Findings Indexer) | 0,2 | v2 index format, finding_id, byte_offset, coverage, 5-level severity, first_seen/last_seen, multi-signal confirmation, false positive suppression |
| `src/ssm-automation-gateway-construct-v2.ts` (Unzip Lambda) | 2 | manifest.json generation with checksums |
| `tests/evaluation/` (NEW) | 6 | Test harness, eval runner, metrics, synthetic bundles, ground truth |

## Appendix B: Risk Register

| Risk | Phase | Mitigation |
|------|-------|------------|
| `summarize` breaking change (requires `finding_ids`) | 4 | Deprecation period: accept empty `finding_ids` with warning for 2 weeks |
| DynamoDB cold start latency | 1 | Table is PAY_PER_REQUEST (no provisioning). First call ~50ms overhead. |
| S3 Select not available for all file formats | 3 | Feature-flagged (`ENABLE_S3_SELECT`). Falls back to chunked Lambda scan. |
| Findings Indexer v2 format breaks old `errors` reads | 2 | Version field check. Old format still parseable. |
| ADOT layer increases Lambda cold start | 5 | Measure before/after. Can disable via env var. |
| Large clusters (1000+ nodes) overwhelm DynamoDB | 1 | PAY_PER_REQUEST scales automatically. Batch writes for `batch_collect`. |
| Agent ignores citation instructions | 0 | Not fully enforceable. Mitigated by structured output + required finding_ids. |
| 5-level severity breaks existing consumers *(GAP 4.6)* | 0 | Backward-compat mapping: `warning` → `medium`. Version field on index. |
| Root cause chain false positives *(GAP 4.5)* | 4 | Known-chain approach only (no ML). Confidence levels. Agent instructed to say "potential". |
| PII redaction latency *(GAP 6.4)* | 5 | Feature-flagged (`ENABLE_PII_REDACTION`). ~100-200ms per Comprehend call. Default off. |
| Baseline subtraction cold start *(GAP 5.6)* | 6 | Requires 1-2 weeks of data collection. Initial deployment has no baselines. |
| False positive suppression too aggressive *(GAP 5.7)* | 2 | Suppressions logged. Patterns kept narrow. Can be disabled per-pattern. |
| KMS encryption context requires key policy update *(GAP 6.3)* | 5 | Test in dev account first. Additive policy change. |

## Appendix C: Dependency Order

```
Phase 0 (no dependencies) — 2-3 days
    ↓
Phase 1 (depends on Phase 0 for finding_id format) — 3-5 days
    ↓
Phase 2 (depends on Phase 0 for coverage_report format) — 4-5 days
    ↓
Phase 3 (depends on Phase 2 for manifest.json) — 4-5.5 days
    ↓
Phase 4 (depends on Phase 0 for finding_id, Phase 2 for findings_index v2) — 4-5 days
    ↓
Phase 5 (independent, can run in parallel with Phase 3-4) — 5-6 days
    ↓
Phase 6 (depends on Phase 0 for finding_id, Phase 2 for v2 index) — 5 days
```

**Total estimated effort: ~27-35 days** (Phases 0-6, some parallelizable)

Phases 0-2 are the highest-impact changes for hallucination reduction.
Phase 0 alone (2-3 days) delivers ~60% of the anti-hallucination value.
Phase 5 can run in parallel with Phases 3-4, saving ~5 days on the critical path.
Phase 6 (evaluation framework) can begin as soon as Phase 2 completes.
