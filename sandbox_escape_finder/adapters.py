"""Adapters for trusted, importable functions used by isolated workers.

Only the trusted sandbox/oracle functions are imported. Payload source remains
a string passed to the sandbox. Closures and functions defined in __main__ are
rejected by the parent instead of being pickled or run on the host.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import traceback
from pathlib import Path

from .oracle import CanaryOracle, OracleVerdict
from .runners import ExecOutcome


def resolve_callable(spec: str):
    """Resolve a trusted module:qualified_name reference."""
    module, _, name = spec.partition(":")
    obj = importlib.import_module(module)
    for part in name.split("."):
        obj = getattr(obj, part)
    if not callable(obj):
        raise TypeError(f"{spec!r} does not identify a callable")
    return obj


class CallableSandbox:
    """Adapt sandbox_exec(source) to the worker's structured outcome protocol."""

    def __init__(self, callable_spec: str | None = None, *, func=None) -> None:
        self.func = func if func is not None else resolve_callable(callable_spec)
        self.last_result = None

    def __call__(self, source: str, env=None) -> ExecOutcome:
        output = io.StringIO()
        try:
            with contextlib.redirect_stdout(output):
                self.last_result = self.func(source)
        except BaseException as exc:
            return ExecOutcome(
                compiled=True, execution_attempted=True, execution_completed=False,
                error_type=type(exc).__name__, error_message=str(exc),
                traceback=traceback.format_exc(limit=5), stdout=output.getvalue(),
            )
        if isinstance(self.last_result, ExecOutcome):
            self.last_result.stdout = output.getvalue() + self.last_result.stdout
            return self.last_result
        if isinstance(self.last_result, dict) and "compiled" in self.last_result:
            outcome = ExecOutcome(**self.last_result)
            outcome.stdout = output.getvalue() + outcome.stdout
            return outcome
        return ExecOutcome(
            compiled=True, execution_attempted=True, execution_completed=True,
            stdout=output.getvalue(),
        )


class CallableOracle(CanaryOracle):
    """Supply workspace snapshots to oracle(pre_state, exec_result, post_state)."""

    def __init__(self, callable_spec: str | None = None, *, func=None) -> None:
        super().__init__()
        self.func = func if func is not None else resolve_callable(callable_spec)

    def __call__(self, pre_state, exec_result=None, post_state=None) -> bool:
        with contextlib.redirect_stdout(io.StringIO()):
            result = self.func(pre_state, exec_result, post_state)
        if not isinstance(result, bool):
            raise TypeError("A custom oracle must return bool")
        return result

    def evaluate(self, workspace: Path, before: dict, exec_result=None) -> OracleVerdict:
        after = self.snapshot_state(workspace)
        observed = self.judge(before, after)
        return OracleVerdict(
            confirmed=self(before, exec_result, after),
            reason="caller-supplied oracle evaluated before/result/after",
            observations=observed.observations,
            scope_note="Caller-supplied oracle using disposable workspace snapshots and the sandbox result.",
        )
