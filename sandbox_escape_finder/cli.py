"""A small command-line interface.

Examples::

    sandbox-escape-finder scan path/to/file.py
    sandbox-escape-finder scan path/to/file.py --json
    sandbox-escape-finder --config config/default.json probe
    sandbox-escape-finder detectors
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import StaticAnalyzer
from .config import Config, ConfigError
from .corpus import load_corpus
from .detectors import detector_catalog
from .oracle import CanaryOracle
from .prober import DynamicProber
from .reporting import (
    comparison_matrix_text,
    false_positive_negative_text,
    payload_results_table,
    summarize_text,
    to_json,
)
from .runners import RestrictedPythonSandbox


def _load_config(path: str | None) -> Config:
    try:
        return Config.coerce(path)
    except ConfigError as exc:
        print(f"error: invalid config: {exc}", file=sys.stderr)
        raise SystemExit(2)


def _cmd_scan(args) -> int:
    source = Path(args.path).read_text(encoding="utf-8")
    analyzer = StaticAnalyzer(_load_config(args.config))
    report = analyzer.analyze(source)
    if args.json:
        print(to_json(report))
        return 0
    if not report.syntax_ok:
        print(f"[malformed source] {report.error}")
        return 0
    if not report.findings:
        print("No suspicious patterns found.")
        return 0
    for f in report.findings:
        print(
            f"{args.path}:{f.lineno}:{f.col_offset}: [{f.confidence_label} "
            f"{f.confidence}] {f.technique}: {f.message}"
        )
    return 0


def _cmd_probe(args) -> int:
    config = _load_config(args.config)
    corpus = load_corpus(config)
    prober = DynamicProber(RestrictedPythonSandbox(), CanaryOracle(), config)
    report = prober.run_report(corpus)
    if args.json:
        print(to_json(report))
        return 0
    print(summarize_text(report))
    print()
    print(payload_results_table(report))
    print()
    print(comparison_matrix_text(report))
    print()
    print(false_positive_negative_text(report))
    return 0


def _cmd_detectors(args) -> int:
    for d in detector_catalog():
        print(f"{d['id']}: {d['technique']}")
        print(f"    {d['description']}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sandbox-escape-finder")
    parser.add_argument("--config", help="path to a JSON config file")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="statically scan a Python file")
    p_scan.add_argument("path")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=_cmd_scan)

    p_probe = sub.add_parser("probe", help="run the dynamic prober over the corpus")
    p_probe.add_argument("--json", action="store_true")
    p_probe.set_defaults(func=_cmd_probe)

    p_det = sub.add_parser("detectors", help="list available detectors")
    p_det.set_defaults(func=_cmd_detectors)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
