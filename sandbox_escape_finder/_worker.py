"""Isolated worker process entry point.

This module is executed in a *fresh, isolated* Python process
(``python -I -m sandbox_escape_finder._worker`` or by file path). It reads a
JSON request from stdin, rebuilds the sandbox and oracle **from trusted dotted
paths** (never from the payload), runs the payload as data, and writes a single
JSON result object to stdout.

The untrusted payload is only ever handled as a string passed to the sandbox
runner; it is never imported or exec'd in the parent/test-runner process.
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
    oracle_factory = _resolve(request["oracle_runner"])
    sandbox = sandbox_factory(**request.get("sandbox_kwargs", {}))
    oracle = oracle_factory(**request.get("oracle_kwargs", {}))

    before = oracle.setup(workspace)
    outcome = sandbox(request["payload_source"], {"workspace": str(workspace)})
    verdict = oracle.evaluate(workspace, before, getattr(sandbox, "last_result", outcome))

    return {
        "ok": True,
        "outcome": outcome.to_dict(),
        "verdict": verdict.to_dict(),
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
