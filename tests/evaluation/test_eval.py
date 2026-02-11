"""
Phase 6.1 — Evaluation tests.

Tests the evaluation framework itself (metrics computation, ground truth loading,
bundle scanning) and runs mock evaluations against synthetic bundles.

All matching is PATTERN-BASED, not finding_id-based. Finding IDs are unstable
(assigned at scan time in detection order). Patterns are the stable identifiers.
"""

import json
import pytest
from pathlib import Path

from .metrics import (
    EvaluationMetrics,
    compute_citation_accuracy,
    compute_coverage_completeness,
    compute_hallucination_rate,
    compute_precision_recall_f1,
    compute_severity_accuracy,
    extract_patterns,
    extract_patterns_from_response,
    build_full_metrics,
)
from .eval_runner import (
    evaluate_tool,
    extract_finding_ids,
    list_bundles,
    load_ground_truth,
    run_full_evaluation,
    DEFAULT_THRESHOLDS,
)


class TestMetricsComputation:
    """Test the 9 evaluation metrics computations."""

    def test_precision_recall_perfect(self):
        predicted = {'oom killer invoked', 'oomkilled', 'memorypressure'}
        expected = {'oom killer invoked', 'oomkilled', 'memorypressure'}
        result = compute_precision_recall_f1(predicted, expected)
        assert result['precision'] == 1.0
        assert result['recall'] == 1.0
        assert result['f1'] == 1.0

    def test_precision_recall_partial(self):
        predicted = {'oom killer invoked', 'oomkilled', 'extra pattern'}
        expected = {'oom killer invoked', 'oomkilled', 'memorypressure'}
        result = compute_precision_recall_f1(predicted, expected)
        assert result['true_positives'] == 2
        assert result['false_positives'] == 1
        assert result['false_negatives'] == 1
        assert result['precision'] == pytest.approx(2/3, abs=0.01)
        assert result['recall'] == pytest.approx(2/3, abs=0.01)

    def test_precision_recall_empty(self):
        result = compute_precision_recall_f1(set(), {'oom killer invoked'})
        assert result['precision'] == 0.0
        assert result['recall'] == 0.0

    def test_hallucination_rate_zero(self):
        response = {
            'findings': [
                {'pattern': 'OOM killer invoked', 'evidence': {'source_file': 'a.log', 'excerpt': 'error'}},
            ]
        }
        result = compute_hallucination_rate(
            {'oom killer invoked'}, {'oom killer invoked'}, response
        )
        assert result['hallucination_rate'] == 0.0

    def test_hallucination_with_fabricated(self):
        response = {
            'findings': [
                {'pattern': 'OOM killer invoked', 'evidence': {'source_file': 'a.log', 'excerpt': 'error'}},
                {'pattern': 'fake error', 'evidence': {}},  # no valid evidence
            ]
        }
        result = compute_hallucination_rate(
            {'oom killer invoked', 'fake error'}, {'oom killer invoked'}, response
        )
        assert result['hallucination_count'] == 1
        assert result['hallucination_rate'] == 0.5

    def test_hallucination_extra_with_evidence_is_not_hallucination(self):
        """Extra finding with valid evidence = false positive, NOT hallucination."""
        response = {
            'findings': [
                {'pattern': 'OOM killer invoked', 'evidence': {'source_file': 'a.log', 'excerpt': 'err'}},
                {'pattern': 'bonus finding', 'evidence': {'source_file': 'b.log', 'excerpt': 'real'}},
            ]
        }
        result = compute_hallucination_rate(
            {'oom killer invoked', 'bonus finding'}, {'oom killer invoked'}, response
        )
        assert result['hallucination_count'] == 0

    def test_citation_accuracy_all_valid(self):
        response = {
            'findings': [
                {'evidence': {'source_file': 'a.log', 'excerpt': 'err'}},
                {'evidence': {'source_file': 'b.log', 'excerpt': 'warn'}},
            ]
        }
        assert compute_citation_accuracy(response) == 1.0

    def test_citation_accuracy_missing_evidence(self):
        response = {
            'findings': [
                {'evidence': {'source_file': 'a.log', 'excerpt': 'err'}},
                {'evidence': {}},
            ]
        }
        assert compute_citation_accuracy(response) == 0.5

    def test_coverage_completeness(self):
        response = {
            'coverage_report': {'files_scanned': 80, 'total_files': 100}
        }
        assert compute_coverage_completeness(response) == 0.8

    def test_severity_accuracy(self):
        predicted = [
            {'pattern': 'OOM killer invoked', 'severity': 'critical'},
            {'pattern': 'MemoryPressure', 'severity': 'high'},
            {'pattern': 'connection refused', 'severity': 'low'},  # wrong
        ]
        ground_truth = [
            {'pattern': 'OOM killer invoked', 'severity': 'critical'},
            {'pattern': 'MemoryPressure', 'severity': 'high'},  # note: GT says high, not medium
            {'pattern': 'connection refused', 'severity': 'medium'},
        ]
        # 2 out of 3 match
        assert compute_severity_accuracy(predicted, ground_truth) == pytest.approx(2/3, abs=0.01)

    def test_build_full_metrics(self):
        response = {
            'findings': [
                {'pattern': 'OOM killer invoked', 'severity': 'critical',
                 'evidence': {'source_file': 'a.log', 'excerpt': 'OOM'}},
            ],
            'coverage_report': {'files_scanned': 10, 'total_files': 10},
        }
        gt = [{'pattern': 'OOM killer invoked', 'severity': 'critical'}]
        m = build_full_metrics(
            predicted_patterns={'oom killer invoked'},
            expected_patterns={'oom killer invoked'},
            response=response,
            ground_truth_findings=gt,
            latencies_ms=[100, 200, 150],
            first_finding_ms=50.0,
        )
        assert isinstance(m, EvaluationMetrics)
        assert m.finding_precision == 1.0
        assert m.finding_recall == 1.0
        assert m.hallucination_rate == 0.0
        assert m.citation_accuracy == 1.0
        assert m.time_to_first_finding_ms == 50.0

    def test_extract_patterns(self):
        findings = [
            {'pattern': 'OOM killer invoked'},
            {'pattern': 'MemoryPressure'},
        ]
        pats = extract_patterns(findings)
        assert pats == {'oom killer invoked', 'memorypressure'}

    def test_extract_patterns_from_response(self):
        response = {'findings': [{'pattern': 'OOM killer invoked'}]}
        pats = extract_patterns_from_response(response)
        assert 'oom killer invoked' in pats


class TestEvalRunner:
    """Test the evaluation runner infrastructure."""

    def test_list_bundles(self, bundles_dir):
        bundles = list_bundles(bundles_dir)
        assert len(bundles) == 4
        assert 'oom_bundle' in bundles
        assert 'cni_failure_bundle' in bundles
        assert 'cert_expiry_bundle' in bundles
        assert 'mixed_bundle' in bundles

    def test_load_ground_truth(self, ground_truth_dir):
        gt = load_ground_truth(ground_truth_dir, 'oom_bundle')
        assert 'findings' in gt
        assert len(gt['findings']) == 5
        # All findings must have a pattern field
        for f in gt['findings']:
            assert 'pattern' in f, f"Finding missing pattern: {f}"

    def test_extract_finding_ids(self):
        """Backward compat: extract_finding_ids still works."""
        response = {
            'findings': [
                {'finding_id': 'F-001', 'pattern': 'OOM killer invoked'},
                {'finding_id': 'F-002', 'pattern': 'OOMKilled'},
            ]
        }
        ids = extract_finding_ids(response)
        assert ids == {'F-001', 'F-002'}

    def test_evaluate_tool_perfect(self):
        """Perfect response should yield precision=1.0, recall=1.0, hallucination=0."""
        response = {
            'findings': [
                {'finding_id': 'F-001', 'pattern': 'OOM killer invoked', 'severity': 'critical',
                 'evidence': {'source_file': 'var/log/dmesg', 'excerpt': 'Out of memory: Killed process'}},
                {'finding_id': 'F-002', 'pattern': 'OOMKilled', 'severity': 'critical',
                 'evidence': {'source_file': 'var/log/pods', 'excerpt': 'OOMKilled'}},
                {'finding_id': 'F-003', 'pattern': 'memory cgroup out of memory', 'severity': 'high',
                 'evidence': {'source_file': 'var/log/messages', 'excerpt': 'memory cgroup out of memory'}},
                {'finding_id': 'F-004', 'pattern': 'exit code 137', 'severity': 'high',
                 'evidence': {'source_file': 'var/log/containers', 'excerpt': 'exit code 137'}},
                {'finding_id': 'F-005', 'pattern': 'MemoryPressure', 'severity': 'medium',
                 'evidence': {'source_file': 'var/log/kubelet.log', 'excerpt': 'MemoryPressure'}},
            ],
            'coverage_report': {'files_scanned': 10, 'total_files': 10},
        }
        gt = {
            'findings': [
                {'finding_id': 'F-001', 'pattern': 'OOM killer invoked', 'severity': 'critical'},
                {'finding_id': 'F-002', 'pattern': 'OOMKilled', 'severity': 'critical'},
                {'finding_id': 'F-003', 'pattern': 'memory cgroup out of memory', 'severity': 'high'},
                {'finding_id': 'F-004', 'pattern': 'exit code 137', 'severity': 'high'},
                {'finding_id': 'F-005', 'pattern': 'MemoryPressure', 'severity': 'medium'},
            ]
        }
        result = evaluate_tool('errors', response, gt)
        assert result['precision'] == 1.0
        assert result['recall'] == 1.0
        assert result['hallucination_rate'] == 0.0
        assert result['citation_accuracy'] == 1.0
        assert result['severity_accuracy'] == 1.0

    def test_run_full_evaluation_offline(self, bundles_dir, ground_truth_dir):
        """Offline evaluation (no invoke_fn) should run without errors."""
        result = run_full_evaluation(bundles_dir, ground_truth_dir)
        assert 'bundles' in result
        assert 'aggregate' in result
        assert len(result['bundles']) == 4


class TestMockBundleScanning:
    """
    Test mock scanner against each bundle and verify pattern-based metrics
    show high accuracy (>80% precision/recall).

    The mock scanner in conftest.py uses regex patterns that should match
    the synthetic log content in test_bundles/, and the ground truth patterns
    should align with what the scanner detects.
    """

    def test_oom_bundle_mock_scan(self, mock_lambda_invoke, oom_ground_truth):
        response = mock_lambda_invoke('errors', {}, bundle_name='oom_bundle')
        result = evaluate_tool('errors', response, oom_ground_truth)
        assert result['precision'] >= 0.80, (
            f"OOM precision {result['precision']:.2f} < 0.80. "
            f"Extra: {result['extra_patterns']}"
        )
        assert result['recall'] >= 0.80, (
            f"OOM recall {result['recall']:.2f} < 0.80. "
            f"Missed: {result['missed_patterns']}"
        )
        assert result['hallucination_rate'] <= 0.05

    def test_cni_bundle_mock_scan(self, mock_lambda_invoke, cni_ground_truth):
        response = mock_lambda_invoke('errors', {}, bundle_name='cni_failure_bundle')
        result = evaluate_tool('errors', response, cni_ground_truth)
        assert result['precision'] >= 0.80, (
            f"CNI precision {result['precision']:.2f} < 0.80. "
            f"Extra: {result['extra_patterns']}"
        )
        assert result['recall'] >= 0.80, (
            f"CNI recall {result['recall']:.2f} < 0.80. "
            f"Missed: {result['missed_patterns']}"
        )
        assert result['hallucination_rate'] <= 0.05

    def test_cert_bundle_mock_scan(self, mock_lambda_invoke, cert_ground_truth):
        response = mock_lambda_invoke('errors', {}, bundle_name='cert_expiry_bundle')
        result = evaluate_tool('errors', response, cert_ground_truth)
        assert result['precision'] >= 0.80, (
            f"Cert precision {result['precision']:.2f} < 0.80. "
            f"Extra: {result['extra_patterns']}"
        )
        assert result['recall'] >= 0.80, (
            f"Cert recall {result['recall']:.2f} < 0.80. "
            f"Missed: {result['missed_patterns']}"
        )
        assert result['hallucination_rate'] <= 0.05

    def test_mixed_bundle_mock_scan(self, mock_lambda_invoke, mixed_ground_truth):
        response = mock_lambda_invoke('errors', {}, bundle_name='mixed_bundle')
        result = evaluate_tool('errors', response, mixed_ground_truth)
        assert result['precision'] >= 0.80, (
            f"Mixed precision {result['precision']:.2f} < 0.80. "
            f"Extra: {result['extra_patterns']}"
        )
        assert result['recall'] >= 0.80, (
            f"Mixed recall {result['recall']:.2f} < 0.80. "
            f"Missed: {result['missed_patterns']}"
        )
        assert result['hallucination_rate'] <= 0.05

    def test_all_findings_have_evidence(self, mock_lambda_invoke):
        """Every finding from mock scanner should have valid evidence."""
        for bundle in ['oom_bundle', 'cni_failure_bundle', 'cert_expiry_bundle', 'mixed_bundle']:
            response = mock_lambda_invoke('errors', {}, bundle_name=bundle)
            for f in response.get('findings', []):
                ev = f.get('evidence', {})
                assert ev.get('source_file'), f"Finding {f.get('pattern')} in {bundle} missing source_file"
                assert ev.get('excerpt'), f"Finding {f.get('pattern')} in {bundle} missing excerpt"
