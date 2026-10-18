"""Sandbox *runners*: the callables that actually compile and execute a payload.

Two sandboxes are provided:

* :class:`RestrictedPythonSandbox` — the **real, unmodified** RestrictedPython
  documented restricted-compilation/execution mechanism. This is the target of
  the end-to-end integration test.
* :class:`ToyBrokenSandbox` — an intentionally *insecure* sandbox used only by
  the oracle-correctness unit test. It deliberately permits a controlled marker
  effect so we can prove the oracle notices a real escape. It is NOT
  RestrictedPython and must only ever be used with controlled payloads inside a
  disposable workspace.

Each sandbox exposes a ``runner_spec`` (a ``module:function`` string) and
serializable ``kwargs`` so the isolation worker can *rebuild* it in a fresh
process. The payload source is always passed as **data** — never imported.
"""

from __future__ import annotations

import contextlib
import io
import traceback as _tb
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class ExecOutcome:
    """Structured result of compiling + executing one payload in a sandbox."""

    compiled: bool
    compile_error: Optional[str] = None
    execution_attempted: bool = False
    execution_completed: bool = False
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    traceback: Optional[str] = None
    stdout: str = ""
    namespace_keys: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Real RestrictedPython sandbox.
# --------------------------------------------------------------------------- #
class RestrictedPythonSandbox:
    """Compile + execute a payload using the documented RestrictedPython setup."""

    runner_spec = "sandbox_escape_finder.runners:build_restricted_sandbox"

    def __init__(self) -> None:
        # Import here so static-only use of the package does not require
        # RestrictedPython to be installed.
        from RestrictedPython import (
            compile_restricted,
            safe_globals,
            safe_builtins,
            utility_builtins,
            PrintCollector,
        )
        from RestrictedPython.Guards import (
            safer_getattr,
            full_write_guard,
            guarded_iter_unpack_sequence,
            guarded_unpack_sequence,
        )

        self._compile_restricted = compile_restricted
        self._safe_globals = safe_globals
        self._safe_builtins = safe_builtins
        self._utility_builtins = utility_builtins
        self._PrintCollector = PrintCollector
        self._safer_getattr = safer_getattr
        self._full_write_guard = full_write_guard
        self._guarded_iter_unpack_sequence = guarded_iter_unpack_sequence
        self._guarded_unpack_sequence = guarded_unpack_sequence

    def kwargs(self) -> dict:
        return {}

    def _make_globals(self) -> dict:
        g = dict(self._safe_globals)
        builtins = dict(self._safe_builtins)
        builtins.update(self._utility_builtins)
        g["__builtins__"] = builtins
        # Guards required for the restricted bytecode to run.
        g["_getattr_"] = self._safer_getattr
        g["_getiter_"] = iter
        g["_getitem_"] = lambda obj, key: obj[key]
        g["_write_"] = self._full_write_guard
        g["_iter_unpack_sequence_"] = self._guarded_iter_unpack_sequence
        g["_unpack_sequence_"] = self._guarded_unpack_sequence
        g["_print_"] = self._PrintCollector
        return g

    def __call__(self, payload_source: str, env: Optional[dict] = None) -> ExecOutcome:
        # 1. Restricted compilation.
        try:
            code = self._compile_restricted(payload_source, "<payload>", "exec")
        except SyntaxError as exc:
            return ExecOutcome(compiled=False, compile_error=str(exc))
        if code is None:  # pragma: no cover - defensive
            return ExecOutcome(compiled=False, compile_error="compile_restricted returned None")

        # 2. Restricted execution, capturing stdout.
        glb = self._make_globals()
        loc: dict = {}
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exec(code, glb, loc)
        except BaseException as exc:  # noqa: BLE001 - we must report any failure
            return ExecOutcome(
                compiled=True,
                execution_attempted=True,
                execution_completed=False,
                error_type=type(exc).__name__,
                error_message=str(exc),
                traceback=_tb.format_exc(limit=5),
                stdout=buf.getvalue(),
            )
        return ExecOutcome(
            compiled=True,
            execution_attempted=True,
            execution_completed=True,
            stdout=buf.getvalue(),
            namespace_keys=[k for k in loc if not k.startswith("_")],
        )


def build_restricted_sandbox(**kwargs) -> RestrictedPythonSandbox:
    """Factory used both directly and by the isolation worker."""
    return RestrictedPythonSandbox()


# --------------------------------------------------------------------------- #
# Toy broken sandbox (intentionally insecure; oracle test only).
# --------------------------------------------------------------------------- #
class ToyBrokenSandbox:
    """A deliberately-leaky sandbox that permits a controlled marker effect.

    It runs the payload with ordinary builtins (including ``open``) plus two
    injected names:

    * ``WORKSPACE`` — the test workspace path (string).
    * ``MARKER_PATH`` — the full path of the escape marker to write.

    This exists so the oracle-correctness test can confirm that a *real* effect
    is detected. It is NOT a security sandbox and must only be used with
    controlled payloads in a disposable workspace.
    """

    runner_spec = "sandbox_escape_finder.runners:build_toy_broken_sandbox"

    def __init__(self, marker_name: str = "ESCAPE_MARKER") -> None:
        self.marker_name = marker_name

    def kwargs(self) -> dict:
        return {"marker_name": self.marker_name}

    def __call__(self, payload_source: str, env: Optional[dict] = None) -> ExecOutcome:
        env = env or {}
        workspace = Path(env.get("workspace", "."))
        marker_path = str(workspace / self.marker_name)
        try:
            code = compile(payload_source, "<toy-payload>", "exec")
        except SyntaxError as exc:
            return ExecOutcome(compiled=False, compile_error=str(exc))
        glb = {
            "__builtins__": __builtins__,
            "WORKSPACE": str(workspace),
            "MARKER_PATH": marker_path,
        }
        loc: dict = {}
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                exec(code, glb, loc)
        except BaseException as exc:  # noqa: BLE001
            return ExecOutcome(
                compiled=True,
                execution_attempted=True,
                execution_completed=False,
                error_type=type(exc).__name__,
                error_message=str(exc),
                traceback=_tb.format_exc(limit=5),
                stdout=buf.getvalue(),
            )
        return ExecOutcome(
            compiled=True,
            execution_attempted=True,
            execution_completed=True,
            stdout=buf.getvalue(),
            namespace_keys=[k for k in loc if not k.startswith("_")],
        )


def build_toy_broken_sandbox(**kwargs) -> ToyBrokenSandbox:
    return ToyBrokenSandbox(**kwargs)


# --------------------------------------------------------------------------- #
# Oracle factory (lives here so the worker can import it by dotted path).
# --------------------------------------------------------------------------- #
def build_canary_oracle(**kwargs):
    from .oracle import CanaryOracle

    return CanaryOracle(**kwargs)


def build_callable_sandbox(**kwargs):
    """Rebuild a trusted one-argument sandbox function inside a worker."""
    from .adapters import CallableSandbox

    return CallableSandbox(**kwargs)


def build_callable_oracle(**kwargs):
    """Rebuild a trusted three-argument oracle function inside a worker."""
    from .adapters import CallableOracle

    return CallableOracle(**kwargs)
