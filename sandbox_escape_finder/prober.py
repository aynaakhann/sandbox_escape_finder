"""The public dynamic entry point: :class:`DynamicProber`.

Usage (as required by the assignment)::

    from sandbox_escape_finder import DynamicProber
    prober = DynamicProber(sandbox_exec, oracle, config)
    report = prober.run(payload_corpus)

For each payload the prober:

1. runs the static analyzer,
2. runs the payload through the configured **isolation backend** (which rebuilds
   the sandbox + oracle inside an isolated worker),
3. classifies the dynamic outcome into an explicit taxonomy,
4. compares the static and dynamic results.

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

from .analyzer import StaticAnalyzer
from .config import Config
from .corpus import Corpus, PayloadCase
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
        self.analyzer = StaticAnalyzer(self.config)
        self.backend = make_backend(self.config)

    # ------------------------------------------------------------------ #
    def run(self, payload_corpus: Any) -> list[dict]:
        """Probe source strings or attributed cases; return one plain dict per payload.

        Use :meth:`run_report` for aggregate metadata and reporting helpers.
        """
        return [row.to_dict() for row in self.run_report(payload_corpus).payloads]

    def run_report(self, payload_corpus: Any) -> ProbeReport:
        """Run the same probes and retain aggregate metadata in a rich report."""
        cases = self._iter_cases(payload_corpus)
        in_process = isinstance(self.backend, InProcessExecutor)
        if in_process:
            available, reason = True, "in-process (controlled)"
        else:
            available, reason = self.backend.available()

        reports = [self._run_case(case, available, reason, in_process) for case in cases]
        report = ProbeReport(
            backend=self.backend.name,
            isolation_available=available,
            isolation_reason=reason,
            config=self.config.to_dict(),
            payloads=reports,
        )
        report.summary = self._summarize(reports)
        return report

    def _iter_cases(self, payload_corpus: Any) -> list[PayloadCase]:
        if isinstance(payload_corpus, (str, bytes)):
            raise TypeError("payload_corpus must be an iterable of source strings, not one string")
        if hasattr(payload_corpus, "ordered"):
            return payload_corpus.ordered(self.config.seed)
        cases = []
        for index, item in enumerate(payload_corpus):
            if isinstance(item, str):
                item = PayloadCase(
                    id=f"source_{index:04d}", category="custom", technique="User source",
                    description="Source string supplied to DynamicProber.run",
                    source=item, reference="user-supplied", provenance="user-supplied source",
                    expected_static=None,
                )
            if not isinstance(item, PayloadCase):
                raise TypeError("Each payload must be a source string or PayloadCase")
            cases.append(item)
        return Corpus(cases).ordered(self.config.seed)

    # ------------------------------------------------------------------ #
    def _run_case(
        self, case: PayloadCase, available: bool, reason: str, in_process: bool
    ) -> PayloadReport:
        # 1. Static analysis.
        scan = self.analyzer.analyze(case.source)
        static_flagged = bool(scan.findings)
        detectors_fired = sorted({f.detector for f in scan.findings})
        static_matches = case.expected_static is None or static_flagged == case.expected_static

        # 2. Dynamic analysis via the selected backend.
        iso = self._execute(case, available, in_process)

        # 3. Classify.
        exec_status, oracle_result, escape = self._classify(iso)
        comparison = self._compare(static_flagged, exec_status, escape)

        outcome = iso.outcome or {}
        verdict = iso.verdict or {}

        notes = ""
        if not static_matches:
            notes = (
                f"Static result ({'flag' if static_flagged else 'no flag'}) differs from "
                f"documented expectation ({'flag' if case.expected_static else 'no flag'})."
            )

        return PayloadReport(
            payload_id=case.id,
            technique=case.technique,
            category=case.category,
            reference=case.reference,
            provenance=case.provenance,
            static_flagged=static_flagged,
            detectors_fired=detectors_fired,
            static_findings=[f.to_dict() for f in scan.findings],
            static_syntax_ok=scan.syntax_ok,
            static_error=scan.error,
            expected_static=case.expected_static,
            static_matches_expectation=static_matches,
            isolation_backend=iso.backend,
            isolation_available=available,
            execution_status=exec_status,
            compiled=outcome.get("compiled"),
            compile_error=outcome.get("compile_error"),
            execution_attempted=outcome.get("execution_attempted"),
            execution_completed=outcome.get("execution_completed"),
            error_type=outcome.get("error_type"),
            error_message=outcome.get("error_message"),
            duration_seconds=round(iso.duration, 4),
            timed_out=iso.timed_out,
            infra_error=iso.infra_error,
            payload_stdout=outcome.get("stdout", ""),
            oracle_result=oracle_result,
            oracle_reason=verdict.get("reason"),
            oracle_observations=verdict.get("observations", {}),
            oracle_scope_note=verdict.get("scope_note"),
            escape_confirmed=escape,
            comparison=comparison,
            expected_restricted=case.expected_restricted,
            notes=notes,
        )

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
        if iso.status == ISO_UNAVAILABLE:
            return BLOCKED, ORACLE_NOT_EVALUATED, False
        if iso.status == ISO_TIMEOUT:
            return TIMEOUT, ORACLE_NOT_EVALUATED, False
        if iso.status == ISO_RESOURCE:
            return RESOURCE_EXCEEDED, ORACLE_NOT_EVALUATED, False
        if iso.status == ISO_INFRA:
            return INCONCLUSIVE, ORACLE_NOT_EVALUATED, False
        if iso.status != ISO_OK or iso.outcome is None:
            return INCONCLUSIVE, ORACLE_NOT_EVALUATED, False

        outcome = iso.outcome
        verdict = iso.verdict or {}
        confirmed = bool(verdict.get("confirmed"))

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
        if exec_status in (TIMEOUT, RESOURCE_EXCEEDED, INCONCLUSIVE, BLOCKED):
            return CMP_INCONCLUSIVE
        if static_flagged and escape:
            return CMP_POS_ESCAPE
        if static_flagged and not escape:
            return CMP_POS_NO_ESCAPE
        if not static_flagged and escape:
            return CMP_NEG_ESCAPE
        return CMP_NEG_NO_ESCAPE

    @staticmethod
    def _summarize(reports: list[PayloadReport]) -> dict:
        by_exec: dict[str, int] = {}
        by_cmp: dict[str, int] = {}
        for r in reports:
            by_exec[r.execution_status] = by_exec.get(r.execution_status, 0) + 1
            by_cmp[r.comparison] = by_cmp.get(r.comparison, 0) + 1
        inconclusive = sum(
            1
            for r in reports
            if r.execution_status in (TIMEOUT, RESOURCE_EXCEEDED, INCONCLUSIVE, BLOCKED)
        )
        return {
            "total_payloads": len(reports),
            "static_flagged": sum(1 for r in reports if r.static_flagged),
            "escapes_confirmed": sum(1 for r in reports if r.escape_confirmed),
            "inconclusive": inconclusive,
            "static_expectation_mismatches": sum(
                1 for r in reports if not r.static_matches_expectation
            ),
            "by_execution_status": by_exec,
            "by_comparison": by_cmp,
        }
