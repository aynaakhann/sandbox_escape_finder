"""End-to-end integration test using the DOCKER container-isolation backend.

This is the stronger-isolation counterpart to test_integration.py. It runs the
full corpus through a disposable container (--network none, read-only rootfs,
tmpfs workspace, non-root user, resource limits).

It is SKIPPED with the exact reason when Docker is unavailable or the image has
not been built (so it is reported NOT RUN, never falsely passing). To run it:

    docker build -t sandbox-escape-finder:latest .
    python -m pytest -m docker
"""

from __future__ import annotations

import pytest

from sandbox_escape_finder import (
    CanaryOracle,
    Config,
    DynamicProber,
    RestrictedPythonSandbox,
    comparison_matrix,
    load_corpus,
)
from sandbox_escape_finder import prober as P

pytestmark = pytest.mark.docker


@pytest.fixture(scope="module")
def docker_report():
    config = Config.from_dict({"isolation": {"mode": "docker"}})
    prober = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), config)
    available, reason = prober.backend.available()
    if not available:
        pytest.skip(f"docker backend unavailable: {reason}")
    corpus = load_corpus(config)
    return prober.run_report(corpus), corpus


def test_docker_corpus_runs_end_to_end(docker_report):
    report, corpus = docker_report
    assert report.backend == "docker"
    assert report.summary["total_payloads"] == len(corpus) >= 10
    assert report.summary["inconclusive"] == 0


def test_docker_no_escape_confirmed(docker_report):
    report, _ = docker_report
    assert report.summary["escapes_confirmed"] == 0
    for r in report.payloads:
        assert r.escape_confirmed is False


def test_docker_outcomes_match_documented_expectations(docker_report):
    report, corpus = docker_report
    by_id = {r.payload_id: r for r in report.payloads}
    mismatches = [
        (c.id, c.expected_restricted, by_id[c.id].execution_status)
        for c in corpus
        if by_id[c.id].execution_status != c.expected_restricted
    ]
    assert not mismatches, f"docker dynamic outcome mismatches: {mismatches}"


def test_docker_outcome_classes_exercised(docker_report):
    report, _ = docker_report
    statuses = {r.execution_status for r in report.payloads}
    assert P.COMPILE_REJECTED in statuses
    assert P.EXECUTION_BLOCKED in statuses
    assert P.EXECUTION_COMPLETED in statuses


def test_docker_comparison_matrix_sums_to_total(docker_report):
    report, _ = docker_report
    m = comparison_matrix(report)
    assert sum(m.values()) == report.summary["total_payloads"]
    assert m["static_positive_escape_confirmed"] == 0
    assert m["static_negative_escape_confirmed"] == 0


def test_docker_oracle_confirms_contained_escape():
    """Positive control through the container: a toy-sandbox escape is confirmed
    by the oracle AND fully contained inside the disposable container tmpfs."""
    from sandbox_escape_finder.isolation import DockerIsolation, WorkerSpec

    config = Config.from_dict({"isolation": {"mode": "docker"}})
    backend = DockerIsolation(config)
    available, reason = backend.available()
    if not available:
        pytest.skip(f"docker backend unavailable: {reason}")

    spec = WorkerSpec(
        payload_source="with open(MARKER_PATH, 'w') as f:\n    f.write('pwned')\n",
        sandbox_runner="sandbox_escape_finder.runners:build_toy_broken_sandbox",
        sandbox_kwargs={"marker_name": "ESCAPE_MARKER"},
        oracle_runner="sandbox_escape_finder.runners:build_canary_oracle",
    )
    result = backend.run(spec)
    assert result.status == "ok"
    assert result.outcome["execution_completed"] is True
    assert result.verdict["confirmed"] is True
    assert "ESCAPE_MARKER" in result.verdict["reason"]


def test_docker_required_string_input_and_list_output():
    config = Config.from_dict({"isolation": {"mode": "docker"}})
    prober = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), config)
    available, reason = prober.backend.available()
    if not available:
        pytest.skip(reason)
    rows = prober.run(iter(["answer = 42\n"]))
    assert type(rows) is list and type(rows[0]) is dict
    assert rows[0]["execution_completed"] is True
    assert rows[0]["isolation_backend"] == "docker"


def test_docker_retains_effect_followed_by_exception():
    from sandbox_escape_finder import Corpus, ToyBrokenSandbox

    config = Config.from_dict({"isolation": {"mode": "docker"}})
    prober = DynamicProber(ToyBrokenSandbox(), CanaryOracle(), config)
    available, reason = prober.backend.available()
    if not available:
        pytest.skip(reason)
    corpus = Corpus([])
    corpus.add_custom({"id": "partial", "source":
        "with open(MARKER_PATH, 'w') as f:\n    f.write('marker')\nraise RuntimeError('after')\n"})
    row = prober.run(corpus)[0]
    assert row["execution_completed"] is False
    assert row["oracle_observations"]["marker_appeared"] is True
    assert row["escape_confirmed"] is True
