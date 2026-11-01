"""Coordinate independent static and dynamic corpus passes, then join results.

The static analyzer and dynamic prober each receive the same normalized corpus
and complete their own pass. Their results are matched by payload ID only after
both passes finish.
"""

from __future__ import annotations

from typing import Any

from .analyzer import ScanReport, StaticAnalyzer
from .corpus import Corpus, PayloadCase
from .isolation import IsolationResult
from .prober import (
    BLOCKED,
    CMP_INCONCLUSIVE,
    CMP_NEG_ESCAPE,
    CMP_NEG_NO_ESCAPE,
    CMP_POS_ESCAPE,
    CMP_POS_NO_ESCAPE,
    DynamicProber,
    INCONCLUSIVE,
    PayloadReport,
    ProbeReport,
    RESOURCE_EXCEEDED,
    TIMEOUT,
)


class AnalysisPipeline:
    """Run static and dynamic analysis as separate branches over one corpus."""

    def __init__(self, analyzer: StaticAnalyzer, prober: DynamicProber) -> None:
        self.analyzer = analyzer
        self.prober = prober

    @classmethod
    def for_prober(cls, prober: DynamicProber) -> "AnalysisPipeline":
        """Build the separate static branch for the legacy combined API."""
        return cls(StaticAnalyzer(prober.config), prober)

    def run_report(self, payload_corpus: Any) -> ProbeReport:
        """Finish each branch independently, then join on each payload ID."""
        cases = self._normalize_cases(payload_corpus)

        # Branch 1: static analysis consumes every source without executing it.
        static_by_id = {
            case.id: self.analyzer.analyze(case.source)
            for case in cases
        }

        # Branch 2: dynamic probing consumes the same cases, with no AST scan.
        available, reason, dynamic_by_id = self.prober._run_dynamic_branch(cases)

        if static_by_id.keys() != dynamic_by_id.keys():
            raise RuntimeError("Static and dynamic branches returned different payload IDs")

        # Join and compare only after both corpus-wide passes have completed.
        reports = [
            self._join(case, static_by_id[case.id], dynamic_by_id[case.id], available)
            for case in cases
        ]
        report = ProbeReport(
            backend=self.prober.backend.name,
            isolation_available=available,
            isolation_reason=reason,
            config=self.prober.config.to_dict(),
            payloads=reports,
        )
        report.summary = summarize(reports)
        return report

    def _normalize_cases(self, payload_corpus: Any) -> list[PayloadCase]:
        """Validate and seed-order the input once before the two branches fork."""
        if isinstance(payload_corpus, (str, bytes)):
            raise TypeError("payload_corpus must be an iterable of source strings, not one string")
        if hasattr(payload_corpus, "ordered"):
            return payload_corpus.ordered(self.prober.config.seed)
        cases = []
        for index, item in enumerate(payload_corpus):
            if isinstance(item, str):
                item = PayloadCase(
                    id=f"source_{index:04d}", category="custom", technique="User source",
                    description="Source string supplied to the analysis pipeline",
                    source=item, reference="user-supplied", provenance="user-supplied source",
                    expected_static=None,
                )
            if not isinstance(item, PayloadCase):
                raise TypeError("Each payload must be a source string or PayloadCase")
            cases.append(item)
        return Corpus(cases).ordered(self.prober.config.seed)

    def run(self, payload_corpus: Any) -> list[dict]:
        """Return the joined per-payload rows in the public API format."""
        return [row.to_dict() for row in self.run_report(payload_corpus).payloads]

    def _join(
        self,
        case: PayloadCase,
        scan: ScanReport,
        iso: IsolationResult,
        available: bool,
    ) -> PayloadReport:
        static_flagged = bool(scan.findings)
        static_matches = (
            case.expected_static is None or static_flagged == case.expected_static
        )
        exec_status, oracle_result, escape = self.prober._classify(iso)
        comparison = compare(static_flagged, exec_status, escape)
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
            detectors_fired=sorted({finding.detector for finding in scan.findings}),
            static_findings=[finding.to_dict() for finding in scan.findings],
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


def compare(static_flagged: bool, exec_status: str, escape: bool) -> str:
    """Compare independent static and dynamic findings for one payload."""
    if escape:
        return CMP_POS_ESCAPE if static_flagged else CMP_NEG_ESCAPE
    if exec_status in (TIMEOUT, RESOURCE_EXCEEDED, INCONCLUSIVE, BLOCKED):
        return CMP_INCONCLUSIVE
    if static_flagged:
        return CMP_POS_NO_ESCAPE
    return CMP_NEG_NO_ESCAPE


def summarize(reports: list[PayloadReport]) -> dict:
    """Aggregate the final joined rows, after both branches have completed."""
    by_exec: dict[str, int] = {}
    by_cmp: dict[str, int] = {}
    for row in reports:
        by_exec[row.execution_status] = by_exec.get(row.execution_status, 0) + 1
        by_cmp[row.comparison] = by_cmp.get(row.comparison, 0) + 1
    inconclusive = sum(
        row.execution_status in (TIMEOUT, RESOURCE_EXCEEDED, INCONCLUSIVE, BLOCKED)
        for row in reports
    )
    return {
        "total_payloads": len(reports),
        "static_flagged": sum(row.static_flagged for row in reports),
        "escapes_confirmed": sum(row.escape_confirmed for row in reports),
        "inconclusive": inconclusive,
        "static_expectation_mismatches": sum(
            not row.static_matches_expectation for row in reports
        ),
        "by_execution_status": by_exec,
        "by_comparison": by_cmp,
    }
