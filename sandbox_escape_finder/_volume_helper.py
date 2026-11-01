"""Trusted helper used by Docker controller containers to seed/snapshot /work."""

from __future__ import annotations

import base64
import json
import os
import sys
from pathlib import Path, PurePosixPath

from .oracle import _snapshot


def _destination(root: Path, relative: str) -> Path:
    part = PurePosixPath(relative)
    if part.is_absolute() or not part.parts or any(p in (".", "..") for p in part.parts):
        raise ValueError(f"unsafe workspace path: {relative!r}")
    target = root.joinpath(*part.parts)
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    # Refuse to traverse symlinked parents, including links created by payload.
    current = root
    for component in part.parts[:-1]:
        current = current / component
        if current.is_symlink():
            raise ValueError(f"symlink parent in workspace path: {relative!r}")
    return target


def main() -> int:
    root = Path("/work")
    request = json.loads(sys.stdin.read() or "{}")
    if request.get("action") == "restore":
        # Docker may expose the named tmpfs volume's mountpoint as 0755 in a
        # newly attached container even if another container changed it.
        # This trusted setup helper runs as root and makes it writable for the
        # non-root payload worker before creating the baseline files.
        root.chmod(0o777)
        for entry in request.get("entries", []):
            target = _destination(root, entry["path"])
            kind = entry["kind"]
            if kind == "dir":
                target.mkdir(exist_ok=True)
                target.chmod(0o777)
            elif kind == "file":
                target.write_bytes(base64.b64decode(entry["data"], validate=True))
                target.chmod(0o666)
            elif kind == "symlink":
                os.symlink(entry["target"], target)
            else:
                raise ValueError(f"unsupported workspace entry kind: {kind}")
        print(json.dumps({"ok": True}))
    elif request.get("action") == "snapshot":
        print(json.dumps({"ok": True, "snapshot": _snapshot(root)}))
    else:
        raise ValueError("unknown helper action")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
