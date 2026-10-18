"""Human- and machine-readable rendering of reports.

Supports:
* ``to_json`` — machine-readable JSON for a ScanReport or ProbeReport.
* ``payload_results_table`` — a Markdown table (payload / technique / static flag
  / dynamic outcome / oracle result).
* ``comparison_matrix`` — the static-vs-dynamic 2x2 (plus inconclusive) counts.
* ``summarize_text`` — a short text summary.
"""

from __future__ import annotations

import json
from typing import Any

from .prober import (
    CMP_INCONCLUSIVE,
    CMP_NEG_ESCAPE,
    CMP_NEG_NO_ESCAPE,
    CMP_POS_ESCAPE,
    CMP_POS_NO_ESCAPE,
    ProbeReport,
)


def to_json(obj: Any, indent: int = 2) -> str:
    """Serialize a report (or any to_dict-able object) to JSON."""
    if hasattr(obj, "to_dict"):
        obj = obj.to_dict()
    return json.dumps(obj, indent=indent, sort_keys=False, default=str)


def payload_results_table(report: ProbeReport, max_rows: int = 100) -> str:
    """Render the payload-results table as Markdown."""
    header = (
        "| Payload | Technique | Static | Detectors | Dynamic outcome | Oracle | Comparison |\n"
        "|---|---|:--:|---|---|---|---|"
    )
    rows = [header]
    for r in report.payloads[:max_rows]:
        static = "FLAG" if r.static_flagged else "—"
        detectors = ",".join(r.detectors_fired) if r.detectors_fired else "—"
        oracle = {
            "confirmed": "ESCAPE",
            "not_confirmed": "no escape",
            "not_evaluated": "n/a",
        }.get(r.oracle_result, r.oracle_result)
        rows.append(
            f"| {r.payload_id} | {r.technique} | {static} | {detectors} | "
            f"{r.execution_status} | {oracle} | {r.comparison} |"
        )
    return "\n".join(rows)


def comparison_matrix(report: ProbeReport) -> dict:
    """Return the counts for each static-vs-dynamic comparison category."""
    counts = report.summary.get("by_comparison", {})
    return {
        "static_positive_escape_confirmed": counts.get(CMP_POS_ESCAPE, 0),
        "static_positive_no_escape": counts.get(CMP_POS_NO_ESCAPE, 0),
        "static_negative_escape_confirmed": counts.get(CMP_NEG_ESCAPE, 0),
        "static_negative_no_escape": counts.get(CMP_NEG_NO_ESCAPE, 0),
        "inconclusive": counts.get(CMP_INCONCLUSIVE, 0),
    }


def comparison_matrix_text(report: ProbeReport) -> str:
    """Render the comparison matrix as a readable grid."""
    m = comparison_matrix(report)
    return (
        "Static vs Dynamic comparison\n"
        "                         | escape confirmed | no escape confirmed\n"
        "-------------------------+------------------+--------------------\n"
        f"static positive (flagged)|        {m['static_positive_escape_confirmed']:<9}|  "
        f"{m['static_positive_no_escape']}\n"
        f"static negative (clean)  |        {m['static_negative_escape_confirmed']:<9}|  "
        f"{m['static_negative_no_escape']}\n"
        f"inconclusive dynamic     : {m['inconclusive']}\n"
    )


def false_positive_negative_analysis(report: ProbeReport) -> dict:
    """The required static-vs-dynamic FP/FN comparison.

    * ``flagged_but_no_escape`` — payloads the static analyzer flagged that did
      NOT escape in practice. These are *candidate* false positives: the syntax
      is a genuine escape idiom, so a blocked one is "suspicious but contained",
      not automatically a false positive.
    * ``escaped_but_not_flagged`` — payloads that escaped but were NOT statically
      flagged. These are true static **false negatives**.
    * ``inconclusive`` — payloads with no decisive dynamic outcome (never counted
      as safe).
    """
    flagged_but_no_escape = []
    escaped_but_not_flagged = []
    inconclusive = []
    for r in report.payloads:
        if r.comparison == CMP_INCONCLUSIVE:
            inconclusive.append(r.payload_id)
        elif r.comparison == CMP_POS_NO_ESCAPE:
            flagged_but_no_escape.append(r.payload_id)
        elif r.comparison == CMP_NEG_ESCAPE:
            escaped_but_not_flagged.append(r.payload_id)
    return {
        "flagged_but_no_escape": flagged_but_no_escape,
        "escaped_but_not_flagged": escaped_but_not_flagged,
        "inconclusive": inconclusive,
        "counts": {
            "candidate_false_positives": len(flagged_but_no_escape),
            "true_false_negatives": len(escaped_but_not_flagged),
            "inconclusive": len(inconclusive),
        },
    }


def false_positive_negative_text(report: ProbeReport) -> str:
    a = false_positive_negative_analysis(report)
    return (
        "False-positive / false-negative analysis\n"
        f"  Statically flagged but NO escape (candidate false positives, "
        f"not necessarily true FPs): {a['flagged_but_no_escape'] or '[]'}\n"
        f"  Escaped but NOT statically flagged (true false negatives): "
        f"{a['escaped_but_not_flagged'] or '[]'}\n"
        f"  Inconclusive dynamic outcome (never treated as safe): "
        f"{a['inconclusive'] or '[]'}"
    )


def summarize_text(report: ProbeReport) -> str:
    s = report.summary
    lines = [
        f"Backend: {report.backend} (available={report.isolation_available})",
        f"  {report.isolation_reason}",
        f"Payloads: {s.get('total_payloads', 0)}",
        f"  static flagged:        {s.get('static_flagged', 0)}",
        f"  escapes confirmed:     {s.get('escapes_confirmed', 0)}",
        f"  inconclusive dynamic:  {s.get('inconclusive', 0)}",
        f"  static expectation mismatches: {s.get('static_expectation_mismatches', 0)}",
        f"  by execution status:   {s.get('by_execution_status', {})}",
    ]
    return "\n".join(lines)
