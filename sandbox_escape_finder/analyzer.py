"""The public static-analysis entry point: :class:`StaticAnalyzer`.

Usage (as required by the assignment)::

    from sandbox_escape_finder import StaticAnalyzer
    analyzer = StaticAnalyzer(config)
    findings = analyzer.scan(source_code)

``scan`` returns a ``list[dict]`` (one dict per finding), matching the required
public API. For the richer :class:`~sandbox_escape_finder.detectors.Finding`
objects and the parse status, use :meth:`StaticAnalyzer.analyze`, which returns
a :class:`ScanReport`.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any, Optional

from .config import Config
from .detectors import Finding, build_detectors


@dataclass
class ScanReport:
    """Result of a static scan, including parse status.

    ``syntax_ok`` is False when the source could not be parsed; in that case
    ``findings`` is empty and ``error`` explains why. This is the documented
    behaviour for malformed source: we do NOT crash and we do NOT guess —
    unparseable code simply yields no findings plus a recorded error.
    """

    findings: list[Finding] = field(default_factory=list)
    syntax_ok: bool = True
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "syntax_ok": self.syntax_ok,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "finding_count": len(self.findings),
            "flagged": bool(self.findings),
        }


class StaticAnalyzer:
    """Runs the configured AST detectors over Python source code."""

    def __init__(self, config: Any = None) -> None:
        self.config = Config.coerce(config)
        # Build every detector but only enable those named in config.
        self.detectors = build_detectors(self.config.enabled_detectors)

    def scan(self, source_code: str) -> list[dict]:
        """Return findings for ``source_code`` as a ``list[dict]`` (API shape).

        Each dict has: ``detector``, ``technique``, ``message``, ``node_type``,
        ``lineno``, ``col_offset``, ``end_lineno``, ``end_col_offset``,
        ``confidence``, ``confidence_label``, ``snippet``.

        For the richer :class:`~sandbox_escape_finder.detectors.Finding` objects
        (and the parse status), use :meth:`analyze`.
        """
        return [f.to_dict() for f in self.analyze(source_code).findings]

    def analyze(self, source_code: str) -> ScanReport:
        """Full scan returning parse status plus findings."""
        if not isinstance(source_code, str):
            raise TypeError("source_code must be a string")

        try:
            tree = ast.parse(source_code)
        except (SyntaxError, ValueError) as exc:
            # ValueError covers e.g. source containing null bytes.
            lineno = getattr(exc, "lineno", None)
            where = f" at line {lineno}" if lineno else ""
            return ScanReport(findings=[], syntax_ok=False, error=f"{type(exc).__name__}: {exc.msg if hasattr(exc, 'msg') else exc}{where}")

        source_lines = source_code.splitlines()
        findings: list[Finding] = []
        for det in self.detectors:
            if not det.enabled:
                continue
            findings.extend(det.analyze(tree, source_lines))

        findings = self._dedup([f for f in findings if f.confidence >= self.config.min_confidence])
        findings.sort(key=lambda f: (f.lineno, f.col_offset, f.detector))
        return ScanReport(findings=findings, syntax_ok=True, error=None)

    @staticmethod
    def _dedup(findings: list[Finding]) -> list[Finding]:
        seen = set()
        unique = []
        for f in findings:
            k = f.key()
            if k in seen:
                continue
            seen.add(k)
            unique.append(f)
        return unique
