"""The public dynamic entry point: :class:`DynamicProber`.

Usage (as required by the assignment)::

    from sandbox_escape_finder import DynamicProber
    prober = DynamicProber(sandbox_exec, oracle, config)
    report = prober.run(payload_corpus)

The dynamic prober runs each payload through the configured **isolation
backend**, which rebuilds the sandbox in an isolated worker. It classifies the
outcome into an explicit taxonomy. Static analysis and the final static/dynamic
comparison are handled by :mod:`pipeline` as separate corpus-wide phases.

Crucially: a successful Python execution, an exception, or a timeout is **never**
treated as a confirmed escape. Only the oracle confirms an escape. An
inconclusive/infrastructure result is never silently classified as safe.
"""

from __future__ import annotations

import time
import importlib
import inspect
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from .config import Config
from .corpus import PayloadCase
from .isolation import (
    ISO_INFRA,
    ISO_OK,
    ISO_RESOURCE,
    ISO_TIMEOUT,
    ISO_UNAVAILABLE,
    InProcessExecutor,
    IsolationResult,
    WorkerSpec,
    make_backend,
)


# Execution-level outcome taxonomy.
COMPILE_REJECTED = "compile_rejected"
EXECUTION_BLOCKED = "execution_blocked"
EXECUTION_COMPLETED = "execution_completed"
TIMEOUT = "timeout"
RESOURCE_EXCEEDED = "resource_exceeded"
INCONCLUSIVE = "inconclusive"
BLOCKED = "blocked"  # isolation prerequisite missing

# Oracle verdict tokens.
ORACLE_CONFIRMED = "confirmed"
ORACLE_NOT_CONFIRMED = "not_confirmed"
ORACLE_NOT_EVALUATED = "not_evaluated"

# Static-vs-dynamic comparison categories.
CMP_POS_ESCAPE = "static_positive_escape_confirmed"
CMP_POS_NO_ESCAPE = "static_positive_no_escape"
CMP_NEG_ESCAPE = "static_negative_escape_confirmed"
CMP_NEG_NO_ESCAPE = "static_negative_no_escape"
CMP_INCONCLUSIVE = "inconclusive"


@dataclass
class PayloadReport:
    """Per-payload result with every field the assignment requires."""

    payload_id: str
    technique: str
    category: str
    reference: str
    provenance: str

    # Static side.
    static_flagged: bool
    detectors_fired: list[str]
    static_findings: list[dict]
    static_syntax_ok: bool
    static_error: Optional[str]
    expected_static: Optional[bool]
    static_matches_expectation: bool

    # Dynamic side.
    isolation_backend: str
    isolation_available: bool
    execution_status: str
    compiled: Optional[bool]
    compile_error: Optional[str]
    execution_attempted: Optional[bool]
    execution_completed: Optional[bool]
    error_type: Optional[str]
    error_message: Optional[str]
    duration_seconds: float
    timed_out: bool
    infra_error: Optional[str]
    payload_stdout: str

    # Oracle side.
    oracle_result: str
    oracle_reason: Optional[str]
    oracle_observations: dict
    oracle_scope_note: Optional[str]
    escape_confirmed: bool

    # Cross-cutting.
    comparison: str
    expected_restricted: str
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ProbeReport:
    """Aggregate report for a full corpus run."""

    backend: str
    isolation_available: bool
    isolation_reason: str
    config: dict
    payloads: list[PayloadReport] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "backend": self.backend,
            "isolation_available": self.isolation_available,
            "isolation_reason": self.isolation_reason,
            "config": self.config,
            "generated_at": self.generated_at,
            "summary": self.summary,
            "payloads": [p.to_dict() for p in self.payloads],
        }


class DynamicProber:
    def __init__(self, sandbox_exec: Any, oracle: Any, config: Any = None) -> None:
        self.sandbox = sandbox_exec
        self.oracle = oracle
        self.config = Config.coerce(config)
        self.backend = make_backend(self.config)

    # ------------------------------------------------------------------ #
    def run(self, payload_corpus: Any) -> list[dict]:
        """Probe source strings or attributed cases; return one plain dict per payload.

        Use :meth:`run_report` for aggregate metadata and reporting helpers.
        """
        return [row.to_dict() for row in self.run_report(payload_corpus).payloads]

    def run_report(self, payload_corpus: Any) -> ProbeReport:
        """Run both independent analysis branches and return their joined report.

        This is a compatibility entry point. The pipeline runs the static pass
        over the corpus, runs the dynamic pass separately, and joins by payload
        ID at the end. Use :class:`AnalysisPipeline` directly when composing the
        two branches explicitly.
        """
        from .pipeline import AnalysisPipeline

        return AnalysisPipeline.for_prober(self).run_report(payload_corpus)

    def _run_dynamic_branch(self, cases: list[PayloadCase]):
        """Run only the dynamic branch for all cases; no static analysis here."""
        in_process = isinstance(self.backend, InProcessExecutor)
        if in_process:
            available, reason = True, "in-process (controlled)"
        else:
            available, reason = self.backend.available()
        results = {
            case.id: self._execute(case, available, in_process)
            for case in cases
        }
        return available, reason, results

    def _execute(self, case: PayloadCase, available: bool, in_process: bool) -> IsolationResult:
        if in_process:
            # Controlled, explicitly gated path (toy-sandbox tests).
            return self.backend.run_callables(self.sandbox, self.oracle, case.source)

        if not available:
            # Honor require_isolation: do not fall back; mark BLOCKED.
            ok, reason = self.backend.available()
            return IsolationResult(
                backend=self.backend.name,
                status=ISO_UNAVAILABLE,
                duration=0.0,
                infra_error=reason,
            )

        spec = self._build_spec(case)
        return self.backend.run(spec)

    def _build_spec(self, case: PayloadCase) -> WorkerSpec:
        runner_spec = getattr(self.sandbox, "runner_spec", None)
        sandbox_kwargs = self.sandbox.kwargs() if hasattr(self.sandbox, "kwargs") else {}
        if runner_spec is None:
            runner_spec = "sandbox_escape_finder.runners:build_callable_sandbox"
            sandbox_kwargs = {"callable_spec": self._importable_callable(self.sandbox, "sandbox")}
        oracle_runner = getattr(self.oracle, "runner_spec", None)
        oracle_kwargs = self.oracle.kwargs() if hasattr(self.oracle, "kwargs") else {}
        if oracle_runner is None:
            oracle_runner = "sandbox_escape_finder.runners:build_callable_oracle"
            oracle_kwargs = {"callable_spec": self._importable_callable(self.oracle, "oracle")}
        return WorkerSpec(
            payload_source=case.source,
            sandbox_runner=runner_spec,
            sandbox_kwargs=sandbox_kwargs,
            oracle_runner=oracle_runner,
            oracle_kwargs=oracle_kwargs,
        )

    @staticmethod
    def _importable_callable(func: Any, role: str) -> str:
        """Describe a trusted function for import in the worker, without pickling."""
        module = getattr(func, "__module__", None)
        name = getattr(func, "__qualname__", "")
        if not inspect.isfunction(func) or module == "__main__" or not module or "<" in name:
            raise TypeError(
                f"Isolated {role} must expose runner_spec or be an importable module-level "
                "function; lambdas, closures, and __main__ functions cannot be reconstructed"
            )
        resolved = importlib.import_module(module)
        for part in name.split("."):
            resolved = getattr(resolved, part)
        if resolved is not func:
            raise TypeError(f"The {role} function is not importable by its qualified name")
        return f"{module}:{name}"

    # ------------------------------------------------------------------ #
    @staticmethod
    def _classify(iso: IsolationResult) -> tuple[str, str, bool]:
        """Map raw isolation facts to (execution_status, oracle_result, escape)."""
        verdict = iso.verdict or {}
        confirmed = bool(verdict.get("confirmed"))

        # The trusted controller can still observe a workspace effect after a
        # timeout or worker crash. Keep that evidence instead of discarding it.
        if iso.status == ISO_UNAVAILABLE:
            return BLOCKED, ORACLE_NOT_EVALUATED, False
        if iso.status == ISO_TIMEOUT:
            return TIMEOUT, ORACLE_CONFIRMED if confirmed else (ORACLE_NOT_CONFIRMED if verdict else ORACLE_NOT_EVALUATED), confirmed
        if iso.status == ISO_RESOURCE:
            return RESOURCE_EXCEEDED, ORACLE_CONFIRMED if confirmed else (ORACLE_NOT_CONFIRMED if verdict else ORACLE_NOT_EVALUATED), confirmed
        if iso.status == ISO_INFRA:
            return INCONCLUSIVE, ORACLE_CONFIRMED if confirmed else (ORACLE_NOT_CONFIRMED if verdict else ORACLE_NOT_EVALUATED), confirmed
        if iso.status != ISO_OK or iso.outcome is None:
            return INCONCLUSIVE, ORACLE_CONFIRMED if confirmed else (ORACLE_NOT_CONFIRMED if verdict else ORACLE_NOT_EVALUATED), confirmed

        outcome = iso.outcome

        if not outcome.get("compiled"):
            exec_status = COMPILE_REJECTED
        elif not outcome.get("execution_completed"):
            exec_status = EXECUTION_BLOCKED
        else:
            exec_status = EXECUTION_COMPLETED

        # An effect can occur before an exception. Preserve execution status
        # independently from the worker's observed before/after verdict.
        oracle_result = ORACLE_CONFIRMED if confirmed else ORACLE_NOT_CONFIRMED
        return exec_status, oracle_result, confirmed

    @staticmethod
    def _compare(static_flagged: bool, exec_status: str, escape: bool) -> str:
        """Compatibility wrapper; final comparison lives in the pipeline."""
        from .pipeline import compare

        return compare(static_flagged, exec_status, escape)

    @staticmethod
    def _summarize(reports: list[PayloadReport]) -> dict:
        """Compatibility wrapper; aggregation lives in the final pipeline."""
        from .pipeline import summarize

        return summarize(reports)
