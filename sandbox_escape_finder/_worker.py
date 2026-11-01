"""Isolated worker process entry point.

This module is executed in a *fresh, isolated* Python process
(``python -I -m sandbox_escape_finder._worker`` or by file path). It reads a
JSON request from stdin, rebuilds only the sandbox **from a trusted dotted
path**, runs the payload as data, and writes execution facts to stdout. Oracle
code runs in the trusted controller, outside this process.

The untrusted payload is only ever handled as a string passed to the sandbox
runner; it is never imported or exec'd in the trusted controller process.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path


def _resolve(spec: str):
    """Resolve a 'module:function' dotted path to the callable."""
    module_name, _, func_name = spec.partition(":")
    module = importlib.import_module(module_name)
    return getattr(module, func_name)


def _run(request: dict) -> dict:
    # Allow the parent to make the trusted package importable under `-I`.
    for path in request.get("sys_path", []):
        if path and path not in sys.path:
            sys.path.insert(0, path)

    workspace = Path(request["workspace"])

    sandbox_factory = _resolve(request["sandbox_runner"])
    sandbox = sandbox_factory(**request.get("sandbox_kwargs", {}))
    outcome = sandbox(request["payload_source"], {"workspace": str(workspace)})
    result = getattr(sandbox, "last_result", outcome)
    if hasattr(result, "to_dict"):
        result = result.to_dict()
    # The parent must be able to serialize this untrusted execution result.
    json.dumps(result)

    return {
        "ok": True,
        "outcome": outcome.to_dict(),
        "oracle_exec_result": result,
    }


def main() -> int:
    try:
        raw = sys.stdin.read()
        request = json.loads(raw)
    except Exception as exc:  # noqa: BLE001
        sys.stdout.write(json.dumps({"ok": False, "worker_error": f"bad request: {exc!r}"}))
        return 2

    try:
        result = _run(request)
    except Exception as exc:  # noqa: BLE001
        import traceback

        result = {
            "ok": False,
            "worker_error": repr(exc),
            "worker_traceback": traceback.format_exc(limit=5),
        }
    sys.stdout.write(json.dumps(result))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
