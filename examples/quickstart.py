"""Quickstart for SandboxEscapeFinder.

Demonstrates the full flow with SAFE defaults:

1. Initialise the static analyzer and scan a short Python sample.
2. Load the attributed corpus.
3. Set up the REAL RestrictedPython integration (RestrictedPythonSandbox).
4. Run the dynamic prober through the configured isolation mechanism.
5. Print static findings and dynamic reports.
6. Produce the static-vs-dynamic comparison.

The example never silently falls back to an insecure execution path. If the
configured isolation prerequisite is unavailable, it prints a clear diagnostic
and the affected payloads are reported as BLOCKED (not as "safe").

Run it with::

    python examples/quickstart.py
"""

from __future__ import annotations

from pathlib import Path

from sandbox_escape_finder import (
    CanaryOracle,
    Config,
    DynamicProber,
    RestrictedPythonSandbox,
    StaticAnalyzer,
    comparison_matrix_text,
    false_positive_negative_text,
    load_corpus,
    payload_results_table,
    summarize_text,
)

SAMPLE = '''
# A short sample mixing benign and suspicious code.
total = sum(range(10))                      # benign
note = "the word __subclasses__ in a string"  # benign: AST sees a string, not code
danger = ().__class__.__bases__[0].__subclasses__()   # suspicious: real traversal
leaked = (lambda: 0).__globals__            # suspicious: function globals
'''


def main() -> int:
    # Load the documented default config (safe: subprocess isolation required).
    config_path = Path(__file__).resolve().parent.parent / "config" / "default.json"
    config = Config.from_file(config_path) if config_path.is_file() else Config.default()

    # ----- 1 & 5a: static analysis -----
    print("=" * 70)
    print("STATIC ANALYSIS of the inline sample")
    print("=" * 70)
    analyzer = StaticAnalyzer(config)
    findings = analyzer.scan(SAMPLE)  # list[dict]
    if not findings:
        print("No suspicious patterns found.")
    for f in findings:
        print(
            f"  line {f['lineno']}:{f['col_offset']}  "
            f"[{f['confidence_label']} {f['confidence']}]  "
            f"{f['technique']}\n      -> {f['message']}"
        )
    print("\n  (benign lines were NOT flagged, including the string that mentions "
          "a dunder.)")

    # ----- 2: load the attributed corpus -----
    corpus = load_corpus(config)
    print(f"\nLoaded corpus with {len(corpus)} attributed payloads "
          f"across categories: {corpus.categories()}")

    # ----- 3: set up the REAL RestrictedPython integration -----
    sandbox = RestrictedPythonSandbox()  # unmodified, documented restricted exec
    oracle = CanaryOracle()

    # ----- 4: run the dynamic prober through the isolation mechanism -----
    prober = DynamicProber(sandbox, oracle, config)

    # Diagnostic: is the configured isolation available?
    available, reason = prober.backend.available()
    print("\n" + "=" * 70)
    print(f"ISOLATION BACKEND: {prober.backend.name}")
    print("=" * 70)
    print(f"  available = {available}")
    print(f"  detail    = {reason}")
    if not available:
        print(
            "\n  Isolation prerequisite NOT satisfied. Payloads will be reported as\n"
            "  BLOCKED (never silently run on the host). To enable the stronger\n"
            "  container backend, start Docker and build the image:\n"
            "      docker build -t sandbox-escape-finder:latest .\n"
            "  then set isolation.mode = 'docker' in your config."
        )

    report = prober.run_report(corpus)

    # ----- 5b & 6: dynamic report + comparison -----
    print("\n" + "=" * 70)
    print("DYNAMIC PROBE REPORT")
    print("=" * 70)
    print(summarize_text(report))
    print()
    print(payload_results_table(report))
    print()
    print(comparison_matrix_text(report))
    print()
    print(false_positive_negative_text(report))
    print()
    print("Interpretation:")
    print("  * 'static_positive_no_escape' means the pattern looked suspicious but the")
    print("    tested environment blocked it. That is NOT automatically a false positive.")
    print("  * 'static_negative_escape_confirmed' would be a true static miss (none expected")
    print("    here against unmodified RestrictedPython).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
