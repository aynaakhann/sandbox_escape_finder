"""Static-analysis / detector tests.

Covers (per the assignment):
* positive examples for every detector,
* negative examples for every detector (incl. strings/comments that merely
  mention dunders),
* accurate source-location reporting,
* malformed-source handling,
* detector enable/disable via configuration.
"""

from __future__ import annotations

import pytest

from sandbox_escape_finder import StaticAnalyzer
from sandbox_escape_finder.config import Config
from sandbox_escape_finder.detectors import DETECTOR_IDS


def detectors_for(source: str, config=None) -> set[str]:
    analyzer = StaticAnalyzer(config)
    # scan() returns list[dict] (the public API shape).
    return {f["detector"] for f in analyzer.scan(source)}


# --------------------------------------------------------------------------- #
# Positive examples — each detector fires on its technique.
# --------------------------------------------------------------------------- #
POSITIVE_CASES = [
    ("subclasses_traversal", "x = ().__class__.__bases__[0].__subclasses__()\n"),
    ("globals_access", "g = (lambda: 0).__globals__\n"),
    ("closure_cell", "c = f.__closure__[0].cell_contents\n"),
    ("builtins_recovery", "e = __builtins__['eval']\n"),
    ("frame_introspection", "import sys\nf = sys._getframe(0).f_globals\n"),
    ("format_string_traversal", 'r = "{0.__class__.__init__}".format(obj)\n'),
    ("dangerous_builtin_call", "m = __import__('os')\n"),
]


@pytest.mark.parametrize("detector_id,source", POSITIVE_CASES)
def test_positive_detection(detector_id, source):
    fired = detectors_for(source)
    assert detector_id in fired, f"{detector_id} should fire on: {source!r} (fired={fired})"


# --------------------------------------------------------------------------- #
# Negative examples — benign code must not fire the respective detector.
# --------------------------------------------------------------------------- #
NEGATIVE_CASES = [
    # A string literal mentioning a dunder is an ast.Constant, not attribute
    # access — the key AST advantage over regex.
    ("subclasses_traversal", 'note = "do not call __subclasses__ ever"\n'),
    # __class__ alone is common and benign; we only flag traversal dunders.
    ("subclasses_traversal", "t = type(obj)\nname = obj.__class__\n"),
    ("globals_access", "config = settings.globals_table\n"),
    ("closure_cell", "cells = battery.cell_contents_count\n"),  # different identifier
    ("builtins_recovery", "value = mapping['eval_result']\n"),  # not a builtins mapping
    ("frame_introspection", "frame = video.frame_count\n"),
    ("format_string_traversal", 'msg = "hello {name}".format(name="world")\n'),
    ("dangerous_builtin_call", "total = evaluate(data)\n"),  # 'evaluate' != 'eval'
]


@pytest.mark.parametrize("detector_id,source", NEGATIVE_CASES)
def test_negative_detection(detector_id, source):
    fired = detectors_for(source)
    assert detector_id not in fired, (
        f"{detector_id} should NOT fire on benign: {source!r} (fired={fired})"
    )


def test_comment_mentioning_dunder_is_not_flagged():
    source = "# this comment mentions __subclasses__ and __globals__\nx = 1\n"
    assert detectors_for(source) == set()


def test_closure_cell_different_identifier_not_flagged():
    # 'cell_contents_count' is a different attribute name, must not match.
    assert "closure_cell" not in detectors_for("n = widget.cell_contents_count\n")


# --------------------------------------------------------------------------- #
# Multiple findings in one file.
# --------------------------------------------------------------------------- #
def test_multiple_findings_in_one_file():
    source = (
        "a = ().__class__.__bases__[0].__subclasses__()\n"
        "b = (lambda: 0).__globals__\n"
        "c = __import__('os')\n"
    )
    analyzer = StaticAnalyzer()
    findings = analyzer.scan(source)
    fired = {f["detector"] for f in findings}
    assert {"subclasses_traversal", "globals_access", "dangerous_builtin_call"} <= fired


def test_scan_returns_list_of_plain_dicts():
    # The required public API shape: findings is list[dict].
    findings = StaticAnalyzer().scan("g = (lambda: 0).__globals__\n")
    assert isinstance(findings, list)
    assert findings and all(isinstance(f, dict) for f in findings)
    expected_keys = {
        "detector", "technique", "message", "node_type", "lineno",
        "col_offset", "end_lineno", "end_col_offset", "confidence",
        "confidence_label", "snippet",
    }
    assert expected_keys <= set(findings[0])


# --------------------------------------------------------------------------- #
# Accurate source locations.
# --------------------------------------------------------------------------- #
def test_source_location_accuracy():
    source = "x = 1\ny = 2\nleak = (lambda: 0).__globals__\n"
    analyzer = StaticAnalyzer()
    findings = [f for f in analyzer.scan(source) if f["detector"] == "globals_access"]
    assert len(findings) == 1
    f = findings[0]
    assert f["lineno"] == 3
    # The __globals__ attribute starts after "leak = ".
    assert f["col_offset"] >= 7
    assert f["end_lineno"] == 3
    assert "__globals__" in f["snippet"]


def test_confidence_fields_present_and_labelled():
    analyzer = StaticAnalyzer()
    f = analyzer.scan("x = ().__class__.__bases__[0].__subclasses__()\n")[0]
    assert 0.0 <= f["confidence"] <= 1.0
    assert f["confidence_label"] in {"low", "medium", "high"}
    assert f["technique"] and f["node_type"] and f["message"]


# --------------------------------------------------------------------------- #
# Malformed source handling (documented behaviour: no crash, no findings).
# --------------------------------------------------------------------------- #
def test_malformed_source_returns_no_findings_and_records_error():
    analyzer = StaticAnalyzer()
    report = analyzer.analyze("def broken(:\n    pass\n")
    assert report.syntax_ok is False
    assert report.findings == []
    assert report.error and "Error" in report.error or report.error


def test_scan_of_malformed_source_is_empty_list():
    analyzer = StaticAnalyzer()
    assert analyzer.scan("this is (not python") == []


def test_empty_source_is_clean():
    analyzer = StaticAnalyzer()
    report = analyzer.analyze("")
    assert report.syntax_ok is True
    assert report.findings == []


# --------------------------------------------------------------------------- #
# Detector enable/disable via configuration.
# --------------------------------------------------------------------------- #
def test_detector_can_be_disabled_via_config():
    source = "x = ().__class__.__bases__[0].__subclasses__()\n"
    cfg = Config.from_dict({"enabled_detectors": ["globals_access"]})
    fired = detectors_for(source, cfg)
    assert "subclasses_traversal" not in fired  # disabled
    # And a globals payload still works with this single-detector config.
    assert detectors_for("g = (lambda: 0).__globals__\n", cfg) == {"globals_access"}


def test_all_detectors_enabled_by_default():
    analyzer = StaticAnalyzer()
    assert {d.id for d in analyzer.detectors if d.enabled} == set(DETECTOR_IDS)


def test_no_duplicate_findings():
    # Same node should not be reported twice by the same detector.
    source = "x = (lambda: 0).__globals__\n"
    findings = StaticAnalyzer().analyze(source).findings  # rich objects expose .key()
    keys = [f.key() for f in findings]
    assert len(keys) == len(set(keys))
