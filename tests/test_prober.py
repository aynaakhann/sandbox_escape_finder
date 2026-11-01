"""Prober, config, corpus, classification, and import tests.

Covers (per the assignment):
* configuration validation (valid + invalid/unsafe),
* payload attribution,
* seed reproducibility,
* timeout and execution-error handling,
* the outcome taxonomy and the static-vs-dynamic comparison,
* installation / public-API import,
* the rule that inconclusive results are never treated as "safe".
"""

from __future__ import annotations

import pytest

from sandbox_escape_finder import (
    CanaryOracle,
    Config,
    Corpus,
    DynamicProber,
    PayloadCase,
    RestrictedPythonSandbox,
    load_corpus,
)
from sandbox_escape_finder.config import ConfigError
from sandbox_escape_finder.isolation import (
    ISO_INFRA,
    ISO_OK,
    ISO_RESOURCE,
    ISO_TIMEOUT,
    ISO_UNAVAILABLE,
    IsolationResult,
)
from sandbox_escape_finder import prober as P


# --------------------------------------------------------------------------- #
# Installation / import.
# --------------------------------------------------------------------------- #
def test_public_api_importable():
    import sandbox_escape_finder as s

    for name in [
        "StaticAnalyzer",
        "DynamicProber",
        "RestrictedPythonSandbox",
        "CanaryOracle",
        "Config",
        "load_corpus",
        "Finding",
    ]:
        assert hasattr(s, name), f"public API missing {name}"
    assert isinstance(s.__version__, str)


# --------------------------------------------------------------------------- #
# Configuration validation.
# --------------------------------------------------------------------------- #
def test_config_defaults_are_valid():
    cfg = Config.default()
    cfg.validate()
    assert cfg.isolation.mode == "subprocess"
    assert cfg.isolation.require_isolation is True
    assert Config.from_file("config/default.json").isolation.mode == "subprocess"
    assert Config.from_file("config/docker.json").isolation.mode == "docker"


def test_config_rejects_unknown_detector():
    with pytest.raises(ConfigError):
        Config.from_dict({"enabled_detectors": ["not_a_detector"]})


def test_config_rejects_unknown_key():
    with pytest.raises(ConfigError):
        Config.from_dict({"totally_unknown": 1})


def test_config_rejects_nonpositive_timeout():
    with pytest.raises(ConfigError):
        Config.from_dict({"timeout_seconds": 0})


def test_config_rejects_inprocess_without_optin():
    # Unsafe combination must be refused, not silently accepted.
    with pytest.raises(ConfigError):
        Config.from_dict({"isolation": {"mode": "inprocess", "allow_in_process": False}})


def test_config_allows_inprocess_with_explicit_optin():
    cfg = Config.from_dict({"isolation": {"mode": "inprocess", "allow_in_process": True}})
    assert cfg.isolation.mode == "inprocess"


def test_config_rejects_bad_isolation_mode():
    with pytest.raises(ConfigError):
        Config.from_dict({"isolation": {"mode": "vm"}})


def test_config_rejects_bad_resource_limit():
    with pytest.raises(ConfigError):
        Config.from_dict({"resource_limits": {"cpu_seconds": -1}})


def test_config_comment_keys_ignored():
    cfg = Config.from_dict({"_comment": "hello", "seed": 7})
    assert cfg.seed == 7


# --------------------------------------------------------------------------- #
# Payload attribution.
# --------------------------------------------------------------------------- #
def test_corpus_has_at_least_ten_cases():
    corpus = load_corpus()
    assert len(corpus) >= 10


def test_every_payload_is_attributed():
    corpus = load_corpus()
    for case in corpus:
        assert case.id
        assert case.category
        assert case.technique
        assert case.source.strip()
        assert case.reference
        assert case.provenance  # honesty note always present
        assert case.dynamic_note or case.category == "benign_control"


def test_corpus_custom_payload_can_be_added():
    corpus = Corpus.builtin()
    n = len(corpus)
    corpus.add_custom({"id": "my_case", "source": "x = 1\n", "category": "custom"})
    assert len(corpus) == n + 1
    assert corpus.get("my_case").source == "x = 1\n"


def test_corpus_custom_payload_requires_id_and_source():
    corpus = Corpus.builtin()
    with pytest.raises(Exception):
        corpus.add_custom({"source": "x = 1\n"})  # missing id


def test_custom_payload_via_config():
    cfg = Config.from_dict(
        {
            "enabled_categories": ["custom"],
            "custom_payloads": [{"id": "cfgcase", "source": "y = 2\n", "category": "custom"}],
        }
    )
    corpus = load_corpus(cfg)
    assert len(corpus) == 1
    assert corpus.get("cfgcase").category == "custom"


# --------------------------------------------------------------------------- #
# Seed reproducibility.
# --------------------------------------------------------------------------- #
def test_seed_reproducibility():
    corpus = load_corpus()
    order1 = [c.id for c in corpus.ordered(1337)]
    order2 = [c.id for c in corpus.ordered(1337)]
    assert order1 == order2  # same seed => identical order


def test_different_seed_changes_order():
    corpus = load_corpus()
    a = [c.id for c in corpus.ordered(1)]
    b = [c.id for c in corpus.ordered(999999)]
    # With 12 items, different seeds almost always reorder. Guard against the
    # vanishingly unlikely collision by requiring that SOME permutation differs
    # across a few seeds.
    seeds = [a] + [[c.id for c in corpus.ordered(s)] for s in (2, 3, 4, 5)]
    assert any(order != b for order in seeds)


# --------------------------------------------------------------------------- #
# Outcome taxonomy — pure classification (no subprocess needed).
# --------------------------------------------------------------------------- #
def _iso(status=ISO_OK, outcome=None, verdict=None):
    return IsolationResult(
        backend="subprocess", status=status, duration=0.01, outcome=outcome, verdict=verdict
    )


def test_classify_compile_rejected():
    iso = _iso(outcome={"compiled": False, "execution_completed": False}, verdict={"confirmed": False})
    status, oracle, escape = DynamicProber._classify(iso)
    assert status == P.COMPILE_REJECTED and escape is False


def test_classify_execution_blocked():
    iso = _iso(
        outcome={"compiled": True, "execution_completed": False, "error_type": "NameError"},
        verdict={"confirmed": False},
    )
    status, oracle, escape = DynamicProber._classify(iso)
    assert status == P.EXECUTION_BLOCKED and escape is False


def test_classify_execution_completed_no_escape():
    iso = _iso(
        outcome={"compiled": True, "execution_completed": True}, verdict={"confirmed": False}
    )
    status, oracle, escape = DynamicProber._classify(iso)
    assert status == P.EXECUTION_COMPLETED
    assert oracle == P.ORACLE_NOT_CONFIRMED and escape is False


def test_classify_escape_confirmed():
    iso = _iso(
        outcome={"compiled": True, "execution_completed": True},
        verdict={"confirmed": True, "reason": "marker"},
    )
    status, oracle, escape = DynamicProber._classify(iso)
    assert oracle == P.ORACLE_CONFIRMED and escape is True


def test_classify_timeout_is_not_safe():
    status, oracle, escape = DynamicProber._classify(_iso(status=ISO_TIMEOUT))
    assert status == P.TIMEOUT
    assert oracle == P.ORACLE_NOT_EVALUATED
    assert escape is False


def test_classify_resource_and_infra_are_inconclusive_not_safe():
    s1, o1, e1 = DynamicProber._classify(_iso(status=ISO_RESOURCE))
    s2, o2, e2 = DynamicProber._classify(_iso(status=ISO_INFRA))
    s3, o3, e3 = DynamicProber._classify(_iso(status=ISO_UNAVAILABLE))
    assert s1 == P.RESOURCE_EXCEEDED
    assert s2 == P.INCONCLUSIVE
    assert s3 == P.BLOCKED
    for o in (o1, o2, o3):
        assert o == P.ORACLE_NOT_EVALUATED


def test_comparison_categories():
    assert DynamicProber._compare(True, P.EXECUTION_COMPLETED, True) == P.CMP_POS_ESCAPE
    assert DynamicProber._compare(True, P.COMPILE_REJECTED, False) == P.CMP_POS_NO_ESCAPE
    assert DynamicProber._compare(False, P.EXECUTION_COMPLETED, True) == P.CMP_NEG_ESCAPE
    assert DynamicProber._compare(False, P.EXECUTION_COMPLETED, False) == P.CMP_NEG_NO_ESCAPE
    # Any inconclusive dynamic status maps to the inconclusive bucket.
    for st in (P.TIMEOUT, P.RESOURCE_EXCEEDED, P.INCONCLUSIVE, P.BLOCKED):
        assert DynamicProber._compare(True, st, False) == P.CMP_INCONCLUSIVE


# --------------------------------------------------------------------------- #
# Timeout handling (real subprocess, short timeout, single payload).
# --------------------------------------------------------------------------- #
def test_timeout_is_reported_and_not_confirmed():
    corpus = Corpus([])
    corpus.add_custom(
        {"id": "infinite_loop", "source": "while True:\n    pass\n", "category": "custom"}
    )
    cfg = Config.from_dict({"timeout_seconds": 1.0, "isolation": {"mode": "subprocess"}})
    prober = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), cfg)
    report = prober.run_report(corpus)
    r = report.payloads[0]
    assert r.execution_status == P.TIMEOUT
    assert r.timed_out is True
    assert r.escape_confirmed is False
    assert r.comparison == P.CMP_INCONCLUSIVE


def test_timeout_kills_background_child_before_workspace_snapshot(tmp_path):
    """A toy-sandbox child must not write after timeout cleanup/observation."""
    import time

    from sandbox_escape_finder import ToyBrokenSandbox

    late_file = tmp_path / "late-child-write.txt"
    source = (
        "import os, time\\n"
        "pid = os.fork()\\n"
        "if pid == 0:\\n"
        "    time.sleep(1.0)\\n"
        f"    open({str(late_file)!r}, 'w').write('late')\\n"
        "    os._exit(0)\\n"
        "while True: pass\\n"
    ).replace("\\n", "\n")
    cfg = Config.from_dict({
        "timeout_seconds": 0.25,
        "resource_limits": {"cpu_seconds": 10, "processes": 64},
        "isolation": {"mode": "subprocess"},
    })
    report = DynamicProber(ToyBrokenSandbox(), CanaryOracle(), cfg).run_report(
        Corpus([PayloadCase(
            id="background_writer", category="custom", technique="child process",
            description="controlled timeout child", source=source,
            reference="test", provenance="test", expected_static=None,
        )])
    )
    row = report.payloads[0]
    time.sleep(1.1)
    assert row.execution_status == P.TIMEOUT
    assert row.escape_confirmed is False
    assert not late_file.exists()


def test_forged_worker_compile_claim_does_not_hide_marker_escape():
    class ForgedToy:
        runner_spec = "tests.callable_fixtures:build_forged_marker_sandbox"

        def kwargs(self):
            return {}

    source = "with open(MARKER_PATH, 'w') as f:\\n    f.write('marker')\\n".replace("\\n", "\n")
    case = PayloadCase(
        id="forged_worker", category="custom", technique="forged result",
        description="toy worker lies about compile status", source=source,
        reference="test", provenance="test", expected_static=None,
    )
    row = DynamicProber(ForgedToy(), CanaryOracle(), Config.default()).run([case])[0]
    assert row["compiled"] is False
    assert row["execution_status"] == P.COMPILE_REJECTED
    assert row["escape_confirmed"] is True


@pytest.mark.parametrize(
    ("stdout", "returncode", "expected_status"),
    [("not-json", 0, ISO_INFRA), ("", 1, ISO_RESOURCE)],
)
def test_malformed_or_empty_worker_output_is_not_no_escape(stdout, returncode, expected_status):
    from sandbox_escape_finder.isolation import SubprocessIsolation

    result = SubprocessIsolation(Config.default())._parse(stdout, "", returncode, 0.01)
    status, oracle_result, escaped = DynamicProber._classify(result)
    assert result.status == expected_status
    assert status in (P.INCONCLUSIVE, P.RESOURCE_EXCEEDED)
    assert oracle_result == P.ORACLE_NOT_EVALUATED
    assert escaped is False
    assert DynamicProber._compare(False, status, escaped) == P.CMP_INCONCLUSIVE


# --------------------------------------------------------------------------- #
# Execution-error handling via the real sandbox (fast, in-process sandbox call).
# --------------------------------------------------------------------------- #
def test_real_sandbox_execution_error_classified_blocked():
    sandbox = RestrictedPythonSandbox()
    outcome = sandbox("cls = getattr((), '__class__')\n", {"workspace": "."})
    iso = _iso(outcome=outcome.to_dict(), verdict={"confirmed": False})
    status, oracle, escape = DynamicProber._classify(iso)
    assert status == P.EXECUTION_BLOCKED
    assert outcome.error_type == "NameError"
    assert escape is False


def test_subprocess_mode_requires_runner_spec():
    # A bare callable cannot be rebuilt in a worker; the prober must refuse,
    # rather than silently running the payload in-process.
    corpus = Corpus([])
    corpus.add_custom({"id": "x", "source": "x = 1\n", "category": "custom"})
    bare_sandbox = lambda src, env: None  # noqa: E731 - no runner_spec attribute
    config = Config.from_dict({"isolation": {"mode": "subprocess"}})
    prober = DynamicProber(bare_sandbox, CanaryOracle(), config)
    with pytest.raises(TypeError):
        prober.run_report(corpus)
