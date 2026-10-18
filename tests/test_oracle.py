"""Oracle-correctness tests.

The assignment requires:
* an intentionally-broken toy sandbox whose permitted marker effect IS detected
  by the oracle (positive), and
* an ordinary-behaviour test confirming the oracle does NOT report a false
  escape (negative).

These use the toy sandbox *in-process* on purpose: the toy sandbox is a
controlled fixture with a harmless marker payload inside a disposable
workspace. This is NOT the real RestrictedPython integration test (that lives
in test_integration.py).
"""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from sandbox_escape_finder import CanaryOracle, RestrictedPythonSandbox, ToyBrokenSandbox
from sandbox_escape_finder.oracle import OracleVerdict


# A harmless marker-writing payload. MARKER_PATH is injected by the toy sandbox.
MARKER_PAYLOAD = "with open(MARKER_PATH, 'w') as fh:\n    fh.write('marker')\n"
BENIGN_PAYLOAD = "x = 1 + 1\n"


@pytest.fixture
def workspace():
    d = pathlib.Path(tempfile.mkdtemp(prefix="sbxef_test_"))
    yield d
    import shutil

    shutil.rmtree(d, ignore_errors=True)


def test_oracle_confirms_toy_sandbox_escape(workspace):
    """Positive: a deliberately-broken sandbox lets the marker effect through."""
    oracle = CanaryOracle()
    toy = ToyBrokenSandbox()
    before = oracle.setup(workspace)
    outcome = toy(MARKER_PAYLOAD, {"workspace": str(workspace)})
    verdict = oracle.evaluate(workspace, before)

    assert outcome.execution_completed is True
    assert isinstance(verdict, OracleVerdict)
    assert verdict.confirmed is True
    assert verdict.observations["marker_appeared"] is True
    assert "ESCAPE_MARKER" in verdict.reason


def test_oracle_does_not_confirm_benign_behaviour(workspace):
    """Negative: ordinary safe code produces no observable effect."""
    oracle = CanaryOracle()
    toy = ToyBrokenSandbox()
    before = oracle.setup(workspace)
    outcome = toy(BENIGN_PAYLOAD, {"workspace": str(workspace)})
    verdict = oracle.evaluate(workspace, before)

    assert outcome.execution_completed is True
    assert verdict.confirmed is False
    assert verdict.observations["marker_appeared"] is False
    assert verdict.observations["canary_broken"] is False


def test_oracle_detects_canary_tampering(workspace):
    """A payload that overwrites the canary is also caught."""
    oracle = CanaryOracle()
    toy = ToyBrokenSandbox()
    before = oracle.setup(workspace)
    tamper = (
        "import os\n"
        "with open(os.path.join(WORKSPACE, 'CANARY.txt'), 'w') as fh:\n"
        "    fh.write('tampered')\n"
    )
    toy(tamper, {"workspace": str(workspace)})
    verdict = oracle.evaluate(workspace, before)
    assert verdict.confirmed is True
    assert verdict.observations["canary_broken"] is True


def test_real_restrictedpython_blocks_the_marker_payload(workspace):
    """The SAME marker payload is blocked by unmodified RestrictedPython.

    This contrasts the toy sandbox with the real one and shows the oracle does
    not confirm an escape when the environment blocks the effect.
    """
    oracle = CanaryOracle()
    sandbox = RestrictedPythonSandbox()
    before = oracle.setup(workspace)
    outcome = sandbox(MARKER_PAYLOAD, {"workspace": str(workspace)})
    verdict = oracle.evaluate(workspace, before)

    assert outcome.compiled is True
    assert outcome.execution_completed is False
    assert outcome.error_type == "NameError"  # 'open' is not defined
    assert verdict.confirmed is False


def test_oracle_scope_note_is_present(workspace):
    oracle = CanaryOracle()
    before = oracle.setup(workspace)
    verdict = oracle.evaluate(workspace, before)
    assert "does not" in verdict.scope_note.lower() or "not" in verdict.scope_note.lower()
    assert verdict.confirmed is False  # nothing ran


def test_oracle_callable_signature_matches_spec(workspace):
    """The required API: oracle(pre_state, exec_result, post_state) -> bool."""
    oracle = CanaryOracle()
    toy = ToyBrokenSandbox()

    pre_state = oracle.setup(workspace)              # before state
    result = toy(MARKER_PAYLOAD, {"workspace": str(workspace)})  # exec_result
    post_state = oracle.snapshot_state(workspace)    # after state

    escaped = oracle(pre_state, result, post_state)  # <-- spec signature, returns bool
    assert escaped is True

    # And a benign run with the spec signature returns False.
    pre2 = oracle.setup(workspace)
    r2 = toy(BENIGN_PAYLOAD, {"workspace": str(workspace)})
    post2 = oracle.snapshot_state(workspace)
    assert oracle(pre2, r2, post2) is False
