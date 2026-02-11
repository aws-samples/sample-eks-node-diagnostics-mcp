"""
Phase 6.1 — Pytest fixtures for evaluation framework.

Provides S3 mock fixtures, ground truth loaders, and bundle uploaders
for running evaluations against localstack or mocked S3.
"""

import json
import os
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path
from typing import Dict
from unittest.mock import MagicMock, patch

import pytest

BUNDLES_DIR = Path(__file__).parent / 'test_bundles'
GROUND_TRUTH_DIR = Path(__file__).parent / 'ground_truth'
EVAL_INSTANCE_PREFIX = 'i-eval'


@pytest.fixture
def bundles_dir():
    return str(BUNDLES_DIR)


@pytest.fixture
def ground_truth_dir():
    return str(GROUND_TRUTH_DIR)


@pytest.fixture
def oom_ground_truth():
    with open(GROUND_TRUTH_DIR / 'oom_bundle.json') as f:
        return json.load(f)


@pytest.fixture
def cni_ground_truth():
    with open(GROUND_TRUTH_DIR / 'cni_failure_bundle.json') as f:
        return json.load(f)


@pytest.fixture
def cert_ground_truth():
    with open(GROUND_TRUTH_DIR / 'cert_expiry_bundle.json') as f:
        return json.load(f)


@pytest.fixture
def mixed_ground_truth():
    with open(GROUND_TRUTH_DIR / 'mixed_bundle.json') as f:
        return json.load(f)


@pytest.fixture
def all_ground_truths(oom_ground_truth, cni_ground_truth, cert_ground_truth, mixed_ground_truth):
    return {
        'oom_bundle': oom_ground_truth,
        'cni_failure_bundle': cni_ground_truth,
        'cert_expiry_bundle': cert_ground_truth,
        'mixed_bundle': mixed_ground_truth,
    }


def bundle_to_tar_gz(bundle_path: Path) -> bytes:
    """Create a tar.gz archive from a test bundle directory."""
    buf = BytesIO()
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for root, dirs, files in os.walk(bundle_path):
            for fname in files:
                fpath = Path(root) / fname
                arcname = str(fpath.relative_to(bundle_path))
                tar.add(str(fpath), arcname=arcname)
    buf.seek(0)
    return buf.read()


@pytest.fixture
def mock_s3_with_bundle():
    """
    Returns a factory that sets up a mock S3 client with a bundle's files
    pre-loaded as if they were extracted to S3.
    """
    def _setup(bundle_name: str, instance_id: str = 'i-eval000000000'):
        bundle_path = BUNDLES_DIR / bundle_name
        if not bundle_path.exists():
            raise FileNotFoundError(f'Bundle not found: {bundle_path}')

        # Build a fake S3 object store
        objects = {}
        prefix = f'eks_{instance_id}/extracted/'

        for root, dirs, files in os.walk(bundle_path):
            for fname in files:
                fpath = Path(root) / fname
                rel = str(fpath.relative_to(bundle_path))
                key = prefix + rel
                objects[key] = fpath.read_bytes()

        return objects, prefix

    return _setup


@pytest.fixture
def mock_lambda_invoke(mock_s3_with_bundle):
    """
    Returns a callable that simulates Lambda tool invocation
    by running the scan logic against mock S3 data.
    """
    def _invoke(tool_name: str, arguments: Dict, bundle_name: str = 'oom_bundle') -> Dict:
        # This is a simplified mock — real evaluation should hit the deployed Lambda
        objects, prefix = mock_s3_with_bundle(bundle_name)

        if tool_name == 'errors':
            # Simulate scanning files for error patterns
            findings = _mock_scan_for_errors(objects, prefix)
            return {
                'findings': findings,
                'totalFindings': len(findings),
                'coverage_report': {
                    'files_scanned': len(objects),
                    'total_files': len(objects),
                    'coverage_pct': 1.0,
                },
            }
        elif tool_name == 'search':
            return {'findings': [], 'results': [], 'coverage_report': {}}
        elif tool_name == 'correlate':
            return {'findings': [], 'timeline': [], 'coverage_report': {}}

        return {'findings': []}

    return _invoke


def _mock_scan_for_errors(objects: Dict[str, bytes], prefix: str):
    """Simplified error scanner for mock testing."""
    import re

    ERROR_PATTERNS = [
        (r'Out of memory.*Killed process', 'critical', 'OOM killer invoked'),
        (r'OOMKilled', 'critical', 'OOMKilled'),
        (r'memory cgroup out of memory', 'high', 'memory cgroup out of memory'),
        (r'exit code 137', 'high', 'exit code 137'),
        (r'MemoryPressure', 'medium', 'MemoryPressure'),
        (r'NetworkNotReady', 'critical', 'NetworkNotReady'),
        (r'plugin type.*aws-cni.*failed', 'critical', 'plugin type="aws-cni" failed'),
        (r'failed to assign an IP address', 'high', 'failed to assign an IP address to container'),
        (r'CrashLoopBackOff', 'high', 'CrashLoopBackOff'),
        (r'ENI not found', 'medium', 'ENI not found'),
        (r'failed to setup network', 'medium', 'failed to setup network for sandbox'),
        (r'certificate has expired', 'critical', 'certificate has expired'),
        (r'x509.*certificate.*expired', 'critical', 'x509: certificate has expired or is not yet valid'),
        (r'Unable to connect to the server', 'high', 'Unable to connect to the server'),
        (r'TLS handshake error', 'high', 'TLS handshake error'),
        (r'NodeNotReady', 'medium', 'NodeNotReady'),
        (r'NXDOMAIN', 'high', 'NXDOMAIN'),
        (r'DiskPressure', 'high', 'DiskPressure'),
        (r'Evicted', 'high', 'Evicted'),
        (r'failed to garbage collect', 'medium', 'failed to garbage collect'),
        (r'connection refused', 'low', 'connection refused'),
        (r'node allocatable enforced', 'info', 'node allocatable enforced'),
    ]

    findings = []
    seen_patterns = set()
    idx = 0

    for key, content_bytes in objects.items():
        try:
            content = content_bytes.decode('utf-8', errors='replace')
        except Exception:
            continue

        rel_file = key.split('/extracted/')[-1] if '/extracted/' in key else key

        for pattern_re, severity, pattern_name in ERROR_PATTERNS:
            if pattern_name in seen_patterns:
                continue
            matches = re.findall(pattern_re, content, re.IGNORECASE)
            if matches:
                idx += 1
                seen_patterns.add(pattern_name)
                # Extract first match line as excerpt
                for line in content.split('\n'):
                    if re.search(pattern_re, line, re.IGNORECASE):
                        excerpt = line.strip()[:500]
                        break
                else:
                    excerpt = matches[0][:500]

                findings.append({
                    'finding_id': f'F-{idx:03d}',
                    'severity': severity,
                    'pattern': pattern_name,
                    'count': len(matches),
                    'evidence': {
                        'source_file': rel_file,
                        'excerpt': excerpt,
                    },
                })

    # Sort by severity
    sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    findings.sort(key=lambda f: sev_order.get(f['severity'], 4))

    # Re-assign sequential finding_ids after sort
    for i, f in enumerate(findings):
        f['finding_id'] = f'F-{i + 1:03d}'

    return findings
