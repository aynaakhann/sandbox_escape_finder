"""Independent Task 6 acceptance checks, separate from the original suite.

Run explicitly: python -m pytest -q validation/test_task6_requirements.py
Checks exercise both the required API and the optional rich reporting API.
Dynamic checks must run inside the disposable Linux test container.
"""

from sandbox_escape_finder import (
    CanaryOracle,
    Config,
    Corpus,
    DynamicProber,
    RestrictedPythonSandbox,
    StaticAnalyzer,
    ToyBrokenSandbox,
    false_positive_negative_analysis,
    load_corpus,
)


def test_static_findings_match_required_schema():
    findings = StaticAnalyzer().scan("g = (lambda: 0).__globals__\n")
    assert isinstance(findings, list) and findings
    assert all(isinstance(item, dict) for item in findings)
    assert {"technique", "node_type", "lineno", "col_offset", "confidence"} <= findings[0].keys()


def test_at_least_five_techniques_have_positive_and_negative_tests():
    # Inspect the actual parametrized cases, rather than counting detector IDs.
    from tests.test_detectors import NEGATIVE_CASES, POSITIVE_CASES

    covered = {item[0] for item in POSITIVE_CASES} & {item[0] for item in NEGATIVE_CASES}
    assert len(covered) >= 5


def test_prober_accepts_iterable_of_source_strings():
    prober = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), Config.default())
    report = prober.run(iter(["x = 1 + 1\n"]))
    rows = report if isinstance(report, list) else report.to_dict()["payloads"]
    assert len(rows) == 1
    assert rows[0]["execution_completed"] is True


def test_prober_returns_list_of_dicts_as_specified():
    prober = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), Config.default())
    corpus = Corpus([load_corpus().get("benign_arithmetic")])
    report = prober.run(corpus)
    assert isinstance(report, list), "Task 6 specifies report: list[dict]"
    assert report and all(isinstance(row, dict) for row in report)


def test_at_least_ten_probes_are_attributed_to_the_required_catalogs():
    catalogs = {
        "https://github.com/jailctf/pyjailbreaker",
        "https://github.com/moshekaplan/python_sandbox_escapes",
    }
    cases = [case for case in load_corpus() if case.category != "benign_control"]
    attributed = [case for case in cases if any(
        case.reference.rstrip("/") == catalog or case.reference.startswith(catalog + "/")
        for catalog in catalogs
    )]
    assert len(attributed) >= 10, (
        f"Only {len(attributed)} non-benign probes reference the two required catalogs; "
        f"{len(cases)} non-benign probes exist in total. Attribution also needs manual review."
    )


def test_custom_payload_executes_from_config():
    config = Config.from_dict({
        "enabled_categories": ["custom"],
        "custom_payloads": [{"id": "acceptance_custom", "source": "answer = 42\n"}],
    })
    report = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), config).run_report(load_corpus(config))
    assert len(report.payloads) == 1
    assert report.payloads[0].execution_completed is True


def test_seed_reproduces_order_and_semantic_outcomes():
    config = Config.from_dict({"seed": 1337})
    prober = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), config)
    first, second = prober.run_report(load_corpus(config)), prober.run_report(load_corpus(config))
    def semantics(report):
        return [(r.payload_id, r.static_flagged, r.execution_status, r.escape_confirmed)
                for r in report.payloads]
    assert semantics(first) == semantics(second)
    assert first.summary["inconclusive"] == second.summary["inconclusive"] == 0


def test_effect_followed_by_exception_is_still_an_escape():
    corpus = Corpus([])
    corpus.add_custom({
        "id": "marker_then_error",
        "source": "with open(MARKER_PATH, 'w') as f:\n    f.write('marker')\nraise RuntimeError('after effect')\n",
    })
    report = DynamicProber(ToyBrokenSandbox(), CanaryOracle(), Config.default()).run_report(corpus)
    row = report.payloads[0]
    assert row.oracle_observations.get("marker_appeared") is True
    assert row.execution_completed is False
    assert row.escape_confirmed is True, "A later exception must not erase an observed escape effect"


def test_supplied_oracle_is_used_or_explicitly_rejected():
    corpus = Corpus([])
    corpus.add_custom({
        "id": "custom_oracle_contract",
        "source": "with open(MARKER_PATH, 'w') as f:\n    f.write('marker')\n",
    })
    # This deliberately negative oracle tests whether the passed callable is
    # honored. It must not be silently replaced by the built-in canary oracle.
    def supplied_oracle(before, result, after):
        return False
    prober = DynamicProber(ToyBrokenSandbox(), supplied_oracle, Config.default())
    try:
        report = prober.run_report(corpus)
    except (TypeError, ValueError):
        return  # Explicit rejection is preferable to silently using another oracle.
    assert report.payloads[0].escape_confirmed is False, "The supplied oracle was silently replaced"


def test_false_negative_reporting_with_a_contained_positive_control():
    corpus = Corpus([])
    corpus.add_custom({
        "id": "marker_control",
        "source": "with open(MARKER_PATH, 'w') as f:\n    f.write('marker')\n",
    })
    config = Config.from_dict({"enabled_detectors": []})
    report = DynamicProber(ToyBrokenSandbox(), CanaryOracle(), config).run_report(corpus)
    assert report.payloads[0].escape_confirmed is True
    assert false_positive_negative_analysis(report)["escaped_but_not_flagged"] == ["marker_control"]
