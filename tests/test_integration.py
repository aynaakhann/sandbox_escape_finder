"""End-to-end integration test against the REAL, unmodified RestrictedPython.

This runs the full attributed corpus through the DynamicProber using the
configured isolation backend (subprocess by default). It is the real
integration test — distinct from the toy-sandbox oracle test in test_oracle.py.

If the required isolation backend is unavailable on this host, the test is
SKIPPED with the exact reason (reported as NOT RUN), never reported as passing
for the wrong reason.
"""

from __future__ import annotations

import json

import pytest

from sandbox_escape_finder import (
    CanaryOracle,
    Config,
    DynamicProber,
    RestrictedPythonSandbox,
    comparison_matrix,
    false_positive_negative_analysis,
    load_corpus,
    to_json,
)
from sandbox_escape_finder import prober as P

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def probe_report():
    config = Config.default()  # subprocess isolation, required
    prober = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), config)
    available, reason = prober.backend.available()
    if not available:
        pytest.skip(f"isolation backend '{prober.backend.name}' unavailable: {reason}")
    corpus = load_corpus(config)
    return prober.run_report(corpus), corpus


def test_corpus_runs_end_to_end(probe_report):
    report, corpus = probe_report
    assert report.summary["total_payloads"] == len(corpus) >= 10
    # On an isolated POSIX host nothing should be inconclusive.
    assert report.summary["inconclusive"] == 0


def test_no_escape_is_confirmed_against_unmodified_restrictedpython(probe_report):
    """Honest expected result: the unmodified setup blocks every corpus payload."""
    report, _ = probe_report
    assert report.summary["escapes_confirmed"] == 0
    for r in report.payloads:
        assert r.escape_confirmed is False
        assert r.oracle_result in (P.ORACLE_NOT_CONFIRMED,)


def test_all_outcome_classes_are_exercised(probe_report):
    report, _ = probe_report
    statuses = {r.execution_status for r in report.payloads}
    # The corpus is designed to hit compile-reject, exec-block and complete.
    assert P.COMPILE_REJECTED in statuses
    assert P.EXECUTION_BLOCKED in statuses
    assert P.EXECUTION_COMPLETED in statuses


def test_actual_dynamic_outcomes_match_documented_expectations(probe_report):
    """Validates the corpus 'expected_restricted' honesty claims against reality."""
    report, corpus = probe_report
    by_id = {r.payload_id: r for r in report.payloads}
    mismatches = []
    for case in corpus:
        actual = by_id[case.id].execution_status
        if actual != case.expected_restricted:
            mismatches.append((case.id, case.expected_restricted, actual))
    assert not mismatches, f"documented vs actual dynamic outcome mismatches: {mismatches}"


def test_benign_controls_behave(probe_report):
    report, _ = probe_report
    by_id = {r.payload_id: r for r in report.payloads}
    # Benign arithmetic: not flagged, executes to completion, no escape.
    arith = by_id["benign_arithmetic"]
    assert arith.static_flagged is False
    assert arith.execution_status == P.EXECUTION_COMPLETED
    assert arith.escape_confirmed is False
    # String mentioning dunders: not flagged (AST advantage), completes.
    s = by_id["benign_string_mentions_dunder"]
    assert s.static_flagged is False
    assert s.execution_status == P.EXECUTION_COMPLETED


def test_all_required_report_fields_are_populated(probe_report):
    report, _ = probe_report
    required = {
        "payload_id",
        "technique",
        "static_flagged",
        "detectors_fired",
        "execution_status",
        "compiled",
        "execution_attempted",
        "execution_completed",
        "oracle_result",
        "escape_confirmed",
        "duration_seconds",
        "comparison",
        "expected_restricted",
    }
    for r in report.payloads:
        d = r.to_dict()
        missing = required - set(d)
        assert not missing, f"{r.payload_id} missing fields: {missing}"
        assert d["duration_seconds"] >= 0


def test_report_is_json_serializable(probe_report):
    report, _ = probe_report
    text = to_json(report)
    parsed = json.loads(text)
    assert parsed["summary"]["total_payloads"] == len(report.payloads)


def test_comparison_matrix_sums_to_total(probe_report):
    report, _ = probe_report
    m = comparison_matrix(report)
    assert sum(m.values()) == report.summary["total_payloads"]
    # Against unmodified RestrictedPython: no confirmed escapes in either row.
    assert m["static_positive_escape_confirmed"] == 0
    assert m["static_negative_escape_confirmed"] == 0


def test_false_positive_negative_analysis(probe_report):
    """The required FP/FN comparison deliverable."""
    report, _ = probe_report
    a = false_positive_negative_analysis(report)
    # No true static false negatives against unmodified RestrictedPython.
    assert a["escaped_but_not_flagged"] == []
    # The flagged-but-blocked probes are surfaced (candidate FPs, not true FPs).
    assert len(a["flagged_but_no_escape"]) == report.summary["static_flagged"]
    # Nothing inconclusive on an isolated POSIX host.
    assert a["inconclusive"] == []
