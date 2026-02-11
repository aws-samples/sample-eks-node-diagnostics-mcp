"""
Phase 6.1 — Evaluation Runner for Anti-Hallucination MCP Server.

Invokes tools against synthetic test bundles, compares results to ground truth,
and computes precision/recall/F1/hallucination metrics per tool per bundle.

Usage:
    # Run full evaluation (requires deployed stack or localstack)
    python -m pytest tests/evaluation/test_eval.py -v

    # Run standalone
    python tests/evaluation/eval_runner.py --bundles-dir tests/evaluation/test_bundles \
        --ground-truth-dir tests/evaluation/ground_truth
"""

import json
import os
import time
import argparse
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from .metrics import (
    EvaluationMetrics,
    LatencyTracker,
    build_full_metrics,
    compute_citation_accuracy,
    compute_coverage_completeness,
    compute_hallucination_rate,
    compute_precision_recall_f1,
    compute_severity_accuracy,
    extract_patterns,
    extract_patterns_from_response,
)

# Tools under evaluation
EVAL_TOOLS = ['errors', 'search', 'correlate']

# Default acceptance thresholds (GAP 5.2)
DEFAULT_THRESHOLDS = {
    'finding_precision': 0.80,
    'finding_recall': 0.70,
    'hallucination_rate': 0.05,   # max 5% hallucination
    'citation_accuracy': 0.90,
    'coverage_completeness': 0.85,
    'severity_accuracy': 0.75,
}


def load_ground_truth(ground_truth_dir: str, bundle_name: str) -> Dict:
    """Load ground truth JSON for a bundle."""
    gt_path = Path(ground_truth_dir) / f'{bundle_name}.json'
    if not gt_path.exists():
        raise FileNotFoundError(f'Ground truth not found: {gt_path}')
    with open(gt_path) as f:
        return json.load(f)


def list_bundles(bundles_dir: str) -> List[str]:
    """List available test bundle names."""
    bd = Path(bundles_dir)
    if not bd.exists():
        return []
    return sorted([
        d.name for d in bd.iterdir()
        if d.is_dir() and not d.name.startswith('.')
    ])


def extract_finding_ids(response: Dict) -> Set[str]:
    """Extract finding_id set from a tool response (kept for backward compat)."""
    findings = response.get('findings', [])
    if not findings and 'results' in response:
        for r in response['results']:
            fid = r.get('finding_id')
            if fid:
                findings.append(r)
    return {f['finding_id'] for f in findings if 'finding_id' in f}


def build_tool_input(bundle_name: str, tool_name: str, instance_id: str = 'i-eval000000000') -> Dict:
    """Build the input arguments for a tool invocation against a test bundle."""
    base = {'instanceId': instance_id}

    if tool_name == 'errors':
        base['severity'] = 'all'
        base['response_format'] = 'detailed'
    elif tool_name == 'search':
        # Search for common critical patterns
        base['query'] = 'OOM|OOMKilled|NetworkNotReady|certificate.*expired|CrashLoopBackOff|NXDOMAIN|DiskPressure'
        base['maxResults'] = 500
    elif tool_name == 'correlate':
        base['timeWindow'] = 300

    return base


def evaluate_tool(
    tool_name: str,
    response: Dict,
    ground_truth: Dict,
) -> Dict:
    """
    Compare a tool response against ground truth using PATTERN matching.
    Finding IDs are unstable (assigned at scan time), so we match on the
    pattern string which is the actual error signature.
    """
    predicted_patterns = extract_patterns_from_response(response)
    expected_patterns = extract_patterns(ground_truth.get('findings', []))

    prf = compute_precision_recall_f1(predicted_patterns, expected_patterns)
    hall = compute_hallucination_rate(predicted_patterns, expected_patterns, response)

    return {
        'tool': tool_name,
        'precision': prf['precision'],
        'recall': prf['recall'],
        'f1': prf['f1'],
        'true_positives': prf['true_positives'],
        'false_positives': prf['false_positives'],
        'false_negatives': prf['false_negatives'],
        'missed_patterns': prf['missed_patterns'],
        'extra_patterns': prf['extra_patterns'],
        'hallucination_count': hall['hallucination_count'],
        'hallucination_rate': hall['hallucination_rate'],
        'citation_accuracy': compute_citation_accuracy(response),
        'coverage_completeness': compute_coverage_completeness(response),
        'severity_accuracy': compute_severity_accuracy(
            response.get('findings', []),
            ground_truth.get('findings', []),
        ),
    }


def evaluate_bundle(
    bundle_name: str,
    responses: Dict[str, Dict],
    ground_truth: Dict,
) -> List[Dict]:
    """Evaluate all tools for a single bundle."""
    results = []
    for tool_name in EVAL_TOOLS:
        if tool_name in responses:
            result = evaluate_tool(tool_name, responses[tool_name], ground_truth)
            result['bundle'] = bundle_name
            results.append(result)
    return results


def run_full_evaluation(
    bundles_dir: str,
    ground_truth_dir: str,
    invoke_fn=None,
) -> Dict:
    """
    Run evaluation across all test bundles.

    Args:
        bundles_dir: Path to test_bundles/ directory
        ground_truth_dir: Path to ground_truth/ directory
        invoke_fn: Optional callable(tool_name, arguments) -> response Dict.
                   If None, uses mock responses for offline testing.

    Returns:
        {
            'bundles': {bundle_name: [per-tool results]},
            'aggregate': {metric: average across all bundles/tools},
            'pass': bool (all thresholds met),
        }
    """
    bundles = list_bundles(bundles_dir)
    if not bundles:
        return {'error': f'No bundles found in {bundles_dir}', 'pass': False}

    all_results = {}
    all_latencies = []

    for bundle_name in bundles:
        gt = load_ground_truth(ground_truth_dir, bundle_name)
        responses = {}

        for tool_name in EVAL_TOOLS:
            tool_input = build_tool_input(bundle_name, tool_name)

            if invoke_fn:
                tracker = LatencyTracker()
                with tracker:
                    resp = invoke_fn(tool_name, tool_input)
                    if resp.get('findings'):
                        tracker.mark_first_finding()
                all_latencies.append(tracker.elapsed_ms)
                responses[tool_name] = resp
            else:
                # Offline mode: use empty response for structure validation
                responses[tool_name] = {'findings': [], 'coverage_report': {}}

        bundle_results = evaluate_bundle(bundle_name, responses, gt)
        all_results[bundle_name] = bundle_results

    # Aggregate metrics across all bundles and tools
    aggregate = _compute_aggregate(all_results)

    # Check thresholds
    passes = all(
        aggregate.get(k, 0) >= v if k != 'hallucination_rate' else aggregate.get(k, 1) <= v
        for k, v in DEFAULT_THRESHOLDS.items()
        if k in aggregate
    )

    return {
        'bundles': all_results,
        'aggregate': aggregate,
        'thresholds': DEFAULT_THRESHOLDS,
        'pass': passes,
    }


def _compute_aggregate(all_results: Dict[str, List[Dict]]) -> Dict[str, float]:
    """Average metrics across all bundle/tool combinations."""
    metrics_keys = [
        'precision', 'recall', 'f1', 'hallucination_rate',
        'citation_accuracy', 'coverage_completeness', 'severity_accuracy',
    ]
    totals = {k: 0.0 for k in metrics_keys}
    count = 0

    for bundle_results in all_results.values():
        for result in bundle_results:
            for k in metrics_keys:
                totals[k] += result.get(k, 0.0)
            count += 1

    if count == 0:
        return totals

    return {k: round(v / count, 4) for k, v in totals.items()}


def print_report(evaluation: Dict):
    """Print a human-readable evaluation report."""
    print('\n' + '=' * 70)
    print('EKS NODE LOG MCP — EVALUATION REPORT')
    print('=' * 70)

    for bundle_name, results in evaluation.get('bundles', {}).items():
        print(f'\n--- Bundle: {bundle_name} ---')
        for r in results:
            status = '✓' if r['hallucination_rate'] <= 0.05 else '✗'
            print(f"  [{status}] {r['tool']:12s}  P={r['precision']:.3f}  R={r['recall']:.3f}  "
                  f"F1={r['f1']:.3f}  Hall={r['hallucination_rate']:.3f}  "
                  f"Cite={r['citation_accuracy']:.3f}")

    agg = evaluation.get('aggregate', {})
    print(f'\n--- Aggregate ---')
    for k, v in sorted(agg.items()):
        threshold = DEFAULT_THRESHOLDS.get(k)
        marker = ''
        if threshold is not None:
            if k == 'hallucination_rate':
                marker = ' ✓' if v <= threshold else f' ✗ (max {threshold})'
            else:
                marker = ' ✓' if v >= threshold else f' ✗ (min {threshold})'
        print(f'  {k:30s}: {v:.4f}{marker}')

    overall = '✓ PASS' if evaluation.get('pass') else '✗ FAIL'
    print(f'\nOverall: {overall}')
    print('=' * 70)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run MCP evaluation')
    parser.add_argument('--bundles-dir', default='tests/evaluation/test_bundles')
    parser.add_argument('--ground-truth-dir', default='tests/evaluation/ground_truth')
    args = parser.parse_args()

    result = run_full_evaluation(args.bundles_dir, args.ground_truth_dir)
    print_report(result)
