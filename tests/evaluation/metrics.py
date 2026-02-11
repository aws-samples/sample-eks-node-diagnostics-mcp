"""
Phase 6.2 — 9 Evaluation Metrics for Anti-Hallucination MCP Server.

Computes precision, recall, F1, hallucination rate, citation accuracy,
coverage completeness, severity accuracy, and latency metrics.

MATCHING STRATEGY: Pattern-based, not finding_id-based.
Finding IDs (F-001, F-002...) are assigned at scan time and vary by detection
order. The stable identifier is the `pattern` field. All precision/recall/
hallucination computations match on normalized pattern strings.
"""

import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set


def _normalize_pattern(p: str) -> str:
    """Lowercase + strip for stable comparison."""
    return p.strip().lower()


def extract_patterns(findings: List[Dict]) -> Set[str]:
    """Extract normalized pattern set from a findings list."""
    return {_normalize_pattern(f['pattern']) for f in findings if f.get('pattern')}


def extract_patterns_from_response(response: Dict) -> Set[str]:
    """Extract patterns from a tool response (findings or results key)."""
    findings = response.get('findings', [])
    if not findings and 'results' in response:
        findings = response['results']
    return extract_patterns(findings)


@dataclass
class EvaluationMetrics:
    """9 metrics from research requirements (GAP 5.2)."""
    finding_precision: float = 0.0       # correct findings / total returned
    finding_recall: float = 0.0          # correct findings / total actual errors
    hallucination_rate: float = 0.0      # fabricated findings / total returned
    citation_accuracy: float = 0.0       # findings with valid evidence / total findings
    coverage_completeness: float = 0.0   # files scanned / total files (from coverage_report)
    severity_accuracy: float = 0.0       # correctly classified severity / total findings
    latency_p50_ms: float = 0.0          # per-tool p50 latency
    latency_p95_ms: float = 0.0          # per-tool p95 latency
    time_to_first_finding_ms: float = 0.0  # time from tool call to first finding

    def to_dict(self) -> Dict:
        return asdict(self)

    def passes_threshold(self, thresholds: Dict[str, float]) -> Dict[str, bool]:
        """Check each metric against a threshold dict. Returns {metric: pass/fail}."""
        results = {}
        d = self.to_dict()
        for metric, threshold in thresholds.items():
            if metric in d:
                if metric == 'hallucination_rate':
                    results[metric] = d[metric] <= threshold
                else:
                    results[metric] = d[metric] >= threshold
        return results


def compute_precision_recall_f1(
    predicted_patterns: Set[str], expected_patterns: Set[str]
) -> Dict[str, float]:
    """Compute precision, recall, F1 from predicted vs expected PATTERNS."""
    tp = len(predicted_patterns & expected_patterns)
    fp = len(predicted_patterns - expected_patterns)
    fn = len(expected_patterns - predicted_patterns)

    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-6)

    return {
        'precision': round(precision, 4),
        'recall': round(recall, 4),
        'f1': round(f1, 4),
        'true_positives': tp,
        'false_positives': fp,
        'false_negatives': fn,
        'missed_patterns': sorted(expected_patterns - predicted_patterns),
        'extra_patterns': sorted(predicted_patterns - expected_patterns),
    }


def compute_hallucination_rate(
    predicted_patterns: Set[str], expected_patterns: Set[str], response: Dict
) -> Dict[str, float]:
    """
    Hallucination = findings whose pattern doesn't exist in ground truth
    AND that lack valid evidence (source_file + excerpt).
    A finding with a novel pattern but valid evidence is a false positive,
    not a hallucination.
    """
    extra_patterns = predicted_patterns - expected_patterns
    findings = response.get('findings', [])

    hallucinated = []
    for pat in extra_patterns:
        # Find the finding with this pattern
        match = next(
            (f for f in findings if _normalize_pattern(f.get('pattern', '')) == pat),
            None,
        )
        if match and not _has_valid_evidence_on_finding(match):
            hallucinated.append(pat)

    total = max(len(predicted_patterns), 1)
    return {
        'hallucination_count': len(hallucinated),
        'hallucination_rate': round(len(hallucinated) / total, 4),
        'hallucinated_patterns': sorted(hallucinated),
    }


def _has_valid_evidence_on_finding(finding: Dict) -> bool:
    """Check if a single finding dict has valid evidence."""
    ev = finding.get('evidence', {})
    return bool(ev.get('source_file') and ev.get('excerpt'))


def compute_citation_accuracy(response: Dict) -> float:
    """Check that every finding has valid evidence with source_file and excerpt."""
    findings = response.get('findings', [])
    if not findings:
        return 1.0
    valid = sum(1 for f in findings if _has_valid_evidence_on_finding(f))
    return round(valid / len(findings), 4)


def compute_coverage_completeness(response: Dict) -> float:
    """Extract coverage_pct from coverage_report, or compute from counts."""
    cr = response.get('coverage_report', {})
    if 'coverage_pct' in cr:
        return round(cr['coverage_pct'], 4)
    scanned = cr.get('files_scanned', 0)
    total = cr.get('total_files', cr.get('files_available', 0))
    if total == 0:
        return 1.0
    return round(scanned / total, 4)


def compute_severity_accuracy(
    predicted: List[Dict], ground_truth: List[Dict]
) -> float:
    """
    Compare severity classifications against ground truth.
    Matches on normalized pattern, not finding_id.
    """
    gt_map = {_normalize_pattern(f['pattern']): f['severity'] for f in ground_truth}
    matched = 0
    correct = 0
    for f in predicted:
        pat = _normalize_pattern(f.get('pattern', ''))
        if pat in gt_map:
            matched += 1
            if f.get('severity') == gt_map[pat]:
                correct += 1
    return round(correct / max(matched, 1), 4)


def compute_latency_percentiles(latencies_ms: List[float]) -> Dict[str, float]:
    """Compute p50 and p95 from a list of latency measurements in ms."""
    if not latencies_ms:
        return {'p50': 0.0, 'p95': 0.0}
    s = sorted(latencies_ms)
    n = len(s)
    p50 = s[int(n * 0.5)] if n > 0 else 0.0
    p95 = s[int(n * 0.95)] if n > 1 else s[-1]
    return {'p50': round(p50, 2), 'p95': round(p95, 2)}


class LatencyTracker:
    """Context manager to measure tool invocation latency."""

    def __init__(self):
        self.start_time: float = 0
        self.end_time: float = 0
        self.first_finding_time: Optional[float] = None

    def __enter__(self):
        self.start_time = time.monotonic() * 1000
        return self

    def __exit__(self, *args):
        self.end_time = time.monotonic() * 1000

    def mark_first_finding(self):
        if self.first_finding_time is None:
            self.first_finding_time = time.monotonic() * 1000

    @property
    def elapsed_ms(self) -> float:
        return round(self.end_time - self.start_time, 2)

    @property
    def time_to_first_finding_ms(self) -> float:
        if self.first_finding_time is None:
            return self.elapsed_ms
        return round(self.first_finding_time - self.start_time, 2)


def build_full_metrics(
    predicted_patterns: Set[str],
    expected_patterns: Set[str],
    response: Dict,
    ground_truth_findings: List[Dict],
    latencies_ms: List[float],
    first_finding_ms: float = 0.0,
) -> EvaluationMetrics:
    """Assemble all 9 metrics into a single EvaluationMetrics object."""
    prf = compute_precision_recall_f1(predicted_patterns, expected_patterns)
    hall = compute_hallucination_rate(predicted_patterns, expected_patterns, response)
    lat = compute_latency_percentiles(latencies_ms)

    predicted_findings = response.get('findings', [])

    return EvaluationMetrics(
        finding_precision=prf['precision'],
        finding_recall=prf['recall'],
        hallucination_rate=hall['hallucination_rate'],
        citation_accuracy=compute_citation_accuracy(response),
        coverage_completeness=compute_coverage_completeness(response),
        severity_accuracy=compute_severity_accuracy(predicted_findings, ground_truth_findings),
        latency_p50_ms=lat['p50'],
        latency_p95_ms=lat['p95'],
        time_to_first_finding_ms=first_finding_ms,
    )
