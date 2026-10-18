"""Regression tests for the Task 6 API, trusted hooks, and confidence filtering.

Run inside the Linux test container so dynamic execution stays off the host.
"""

import json

import pytest

from sandbox_escape_finder import (
    CanaryOracle, Config, ConfigError, Corpus, DynamicProber,
    RestrictedPythonSandbox, StaticAnalyzer, ToyBrokenSandbox,
)
from tests.callable_fixtures import (
    invalid_oracle, never_confirm, restricted_function, result_is_five, source_length,
)


def test_required_report_is_plain_json_serializable_list():
    rows = DynamicProber(RestrictedPythonSandbox(), CanaryOracle()).run(
        iter(["x = 1\n", "g = (lambda: 0).__globals__\n"])
    )
    assert type(rows) is list and all(type(row) is dict for row in rows)
    assert len(json.loads(json.dumps(rows))) == 2
    assert {r["execution_status"] for r in rows} == {"execution_completed", "compile_rejected"}
    assert all(r["static_matches_expectation"] for r in rows)


@pytest.mark.parametrize("corpus", ["x = 1", [12], [None], [b"x = 1"]])
def test_invalid_payload_shapes_are_rejected(corpus):
    with pytest.raises(TypeError):
        DynamicProber(RestrictedPythonSandbox(), CanaryOracle()).run(corpus)


def test_empty_corpus_has_empty_required_report():
    assert DynamicProber(RestrictedPythonSandbox(), CanaryOracle()).run([]) == []


def test_importable_single_argument_sandbox_runs_in_worker():
    rows = DynamicProber(restricted_function, CanaryOracle()).run(["answer = 42\n"])
    assert rows[0]["execution_completed"] is True
    assert rows[0]["infra_error"] is None


def test_importable_custom_oracle_is_not_replaced():
    corpus = Corpus([])
    corpus.add_custom({"id": "hook", "source": "with open(MARKER_PATH, 'w') as f:\n    f.write('x')\n"})
    row = DynamicProber(ToyBrokenSandbox(), never_confirm).run(corpus)[0]
    assert row["oracle_observations"]["marker_appeared"] is True
    assert row["escape_confirmed"] is False
    assert row["infra_error"] is None


def test_custom_oracle_receives_original_sandbox_result():
    row = DynamicProber(source_length, result_is_five).run(["pass\n"])[0]
    assert row["execution_completed"] is True
    assert row["escape_confirmed"] is True
    assert row["oracle_result"] == "confirmed"


def test_invalid_custom_oracle_result_is_inconclusive():
    row = DynamicProber(restricted_function, invalid_oracle).run(["pass\n"])[0]
    assert row["execution_status"] == "inconclusive"
    assert row["oracle_result"] == "not_evaluated"
    assert "must return bool" in row["infra_error"]


def test_closure_oracle_is_explicitly_rejected():
    with pytest.raises(TypeError, match="oracle.*importable"):
        DynamicProber(RestrictedPythonSandbox(), lambda before, result, after: False).run(["pass\n"])


def test_confidence_threshold_filters_findings_inclusively():
    source = "g = (lambda: 0).__globals__\n"  # confidence 0.85
    assert StaticAnalyzer({"min_confidence": 0.85}).scan(source)
    assert StaticAnalyzer({"min_confidence": 0.86}).scan(source) == []
    assert Config.from_dict({"min_confidence": 0.85}).to_dict()["min_confidence"] == 0.85


@pytest.mark.parametrize("value", [-0.1, 1.1, True, "high", None, float("nan")])
def test_invalid_confidence_threshold_is_rejected(value):
    with pytest.raises(ConfigError, match="min_confidence"):
        Config.from_dict({"min_confidence": value})


def test_config_instance_is_validated_before_scanning():
    with pytest.raises(ConfigError, match="min_confidence"):
        StaticAnalyzer(Config(min_confidence=2))


def test_config_instance_cannot_bypass_inprocess_optin():
    from sandbox_escape_finder.config import IsolationConfig

    config = Config(isolation=IsolationConfig(mode="inprocess", allow_in_process=False))
    with pytest.raises(ConfigError, match="inprocess"):
        DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), config)


def test_explicit_controlled_inprocess_mode_accepts_local_callables():
    config = {"isolation": {"mode": "inprocess", "allow_in_process": True}}
    prober = DynamicProber(lambda source: len(source), lambda pre, result, post: result == 5, config)
    row = prober.run(["pass\n"])[0]
    assert row["execution_completed"] is True
    assert row["escape_confirmed"] is True
