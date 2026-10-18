"""SandboxEscapeFinder: static + dynamic finder for Python sandbox escapes.

Public API
----------
Static analysis::

    from sandbox_escape_finder import StaticAnalyzer
    analyzer = StaticAnalyzer(config)
    findings = analyzer.scan(source_code)

Dynamic probing::

    from sandbox_escape_finder import DynamicProber, RestrictedPythonSandbox, CanaryOracle, load_corpus
    prober = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), config)
    report = prober.run(load_corpus(config))

This package statically flags *suspicious syntax* and dynamically probes a
documented, unmodified RestrictedPython setup. RestrictedPython is not, by its
own documentation, a complete security sandbox; this tool measures that gap and
never equates execution, an exception, or a timeout with a confirmed escape.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .analyzer import ScanReport, StaticAnalyzer
from .config import Config, ConfigError
from .corpus import Corpus, PayloadCase, load_corpus
from .detectors import (
    ALL_DETECTORS,
    DETECTOR_IDS,
    Finding,
    build_detectors,
    detector_catalog,
)
from .oracle import CanaryOracle, OracleVerdict
from .prober import DynamicProber, PayloadReport, ProbeReport
from .reporting import (
    comparison_matrix,
    comparison_matrix_text,
    false_positive_negative_analysis,
    false_positive_negative_text,
    payload_results_table,
    summarize_text,
    to_json,
)
from .runners import (
    ExecOutcome,
    RestrictedPythonSandbox,
    ToyBrokenSandbox,
    build_canary_oracle,
    build_restricted_sandbox,
    build_toy_broken_sandbox,
)

__all__ = [
    "__version__",
    # Static
    "StaticAnalyzer",
    "ScanReport",
    "Finding",
    "build_detectors",
    "detector_catalog",
    "ALL_DETECTORS",
    "DETECTOR_IDS",
    # Config
    "Config",
    "ConfigError",
    # Corpus
    "Corpus",
    "PayloadCase",
    "load_corpus",
    # Dynamic
    "DynamicProber",
    "ProbeReport",
    "PayloadReport",
    "RestrictedPythonSandbox",
    "ToyBrokenSandbox",
    "ExecOutcome",
    "build_restricted_sandbox",
    "build_toy_broken_sandbox",
    "build_canary_oracle",
    # Oracle
    "CanaryOracle",
    "OracleVerdict",
    # Reporting
    "to_json",
    "payload_results_table",
    "comparison_matrix",
    "comparison_matrix_text",
    "false_positive_negative_analysis",
    "false_positive_negative_text",
    "summarize_text",
]
