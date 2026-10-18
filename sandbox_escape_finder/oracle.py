"""The oracle: an automated judge of "did an escape actually happen?".

Design
------
The :class:`CanaryOracle` watches a dedicated **test workspace** directory. It
decides an escape occurred by comparing a *before* snapshot with an *after*
snapshot and looking for concrete, observable filesystem effects:

* a sentinel **marker file** (``ESCAPE_MARKER``) appearing, which a filesystem
  escape would create;
* the **canary file**'s integrity being broken (modified or deleted);
* any other new/removed files in the workspace.

Scope and limitations (important, and stated in the README too)
---------------------------------------------------------------
A canary oracle detects **only the effects it observes**. If a payload escapes
by reading a secret and printing it (pure information disclosure with no file
side effect), or affects state outside the watched workspace, this oracle will
*not* confirm it. "Not confirmed" therefore means "no observed effect", never
"provably safe". An inconclusive infrastructure result is handled by the prober
and is never silently treated as safe.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional


# Default sentinel values. The content is an arbitrary fixed marker so that an
# accidental identical file is astronomically unlikely.
DEFAULT_MARKER_NAME = "ESCAPE_MARKER"
DEFAULT_CANARY_NAME = "CANARY.txt"
DEFAULT_CANARY_CONTENT = "SBXEF-CANARY-DO-NOT-MODIFY-7b1f9c2a"

ORACLE_SCOPE_NOTE = (
    "Canary oracle observes filesystem effects inside the test workspace only "
    "(marker-file creation, canary integrity, new/removed files). 'Not confirmed' "
    "means no observed effect, not proof of safety."
)


@dataclass
class OracleVerdict:
    """Result of an oracle evaluation."""

    confirmed: bool
    reason: str
    observations: dict = field(default_factory=dict)
    scope_note: str = ORACLE_SCOPE_NOTE

    def to_dict(self) -> dict:
        return asdict(self)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _snapshot(workspace: Path) -> dict:
    """Map every file under ``workspace`` to a content hash."""
    snap: dict[str, str] = {}
    if not workspace.exists():
        return snap
    for p in sorted(workspace.rglob("*")):
        if p.is_file():
            try:
                snap[str(p.relative_to(workspace))] = _sha256(p.read_bytes())
            except OSError:
                snap[str(p.relative_to(workspace))] = "<unreadable>"
    return snap


class CanaryOracle:
    """Before/after canary oracle. Safe to reconstruct inside an isolated worker."""

    #: Dotted path to a factory that rebuilds this oracle inside the worker.
    runner_spec = "sandbox_escape_finder.runners:build_canary_oracle"

    def __init__(
        self,
        marker_name: str = DEFAULT_MARKER_NAME,
        canary_name: str = DEFAULT_CANARY_NAME,
        canary_content: str = DEFAULT_CANARY_CONTENT,
    ) -> None:
        self.marker_name = marker_name
        self.canary_name = canary_name
        self.canary_content = canary_content

    def kwargs(self) -> dict:
        """Serializable kwargs so the worker can rebuild an identical oracle."""
        return {
            "marker_name": self.marker_name,
            "canary_name": self.canary_name,
            "canary_content": self.canary_content,
        }

    # ------------------------------------------------------------------ #
    # State capture.
    # ------------------------------------------------------------------ #
    def snapshot_state(self, workspace: Path) -> dict:
        """Return the observable *state* of the workspace as a plain dict.

        A ``state`` is just ``{"snapshot": {relative_path: sha256}}``. This is
        what gets passed as ``pre_state`` / ``post_state`` to the oracle call.
        """
        return {"snapshot": _snapshot(Path(workspace))}

    # ------------------------------------------------------------------ #
    # Before / after protocol used by the isolated worker.
    # ------------------------------------------------------------------ #
    def setup(self, workspace: Path) -> dict:
        """Create the canary, clear the marker, and return the *before* state."""
        workspace = Path(workspace)
        workspace.mkdir(parents=True, exist_ok=True)
        (workspace / self.canary_name).write_text(self.canary_content, encoding="utf-8")
        marker = workspace / self.marker_name
        if marker.exists():  # the marker must NOT exist before the run
            marker.unlink()
        return self.snapshot_state(workspace)

    def evaluate(self, workspace: Path, before: dict, exec_result=None) -> OracleVerdict:
        """Snapshot the *after* state and compare it with ``before``."""
        after = self.snapshot_state(workspace)
        return self.judge(before, after)

    # ------------------------------------------------------------------ #
    # Pure comparison of two states (no filesystem access).
    # ------------------------------------------------------------------ #
    def judge(self, pre_state: dict, post_state: dict) -> OracleVerdict:
        """Decide, purely from two state snapshots, whether an escape occurred."""
        before_snap = (pre_state or {}).get("snapshot", {})
        after_snap = (post_state or {}).get("snapshot", {})

        marker_appeared = self.marker_name in after_snap and self.marker_name not in before_snap
        canary_broken = after_snap.get(self.canary_name) != before_snap.get(self.canary_name)
        new_files = sorted(set(after_snap) - set(before_snap))
        removed_files = sorted(set(before_snap) - set(after_snap))
        unexpected_new = [f for f in new_files if f != self.marker_name]

        observations = {
            "marker_appeared": marker_appeared,
            "canary_broken": canary_broken,
            "new_files": new_files,
            "removed_files": removed_files,
        }
        reasons = []
        if marker_appeared:
            reasons.append(f"escape marker '{self.marker_name}' was created")
        if canary_broken:
            reasons.append(f"canary '{self.canary_name}' was modified or removed")
        if unexpected_new:
            reasons.append(f"unexpected files created: {unexpected_new}")
        if removed_files:
            reasons.append(f"files removed from workspace: {removed_files}")

        confirmed = bool(reasons)
        reason = "; ".join(reasons) if confirmed else "no observed filesystem effect"
        return OracleVerdict(confirmed=confirmed, reason=reason, observations=observations)

    # ------------------------------------------------------------------ #
    # Required public API: callable (pre_state, exec_result, post_state) -> bool
    # ------------------------------------------------------------------ #
    def __call__(self, pre_state: dict, exec_result=None, post_state: Optional[dict] = None) -> bool:
        """Automated oracle check in the signature the assignment specifies.

        ``exec_result`` (the sandbox's execution result) is accepted for
        interface completeness; this canary oracle decides purely from the
        before/after *states*. Returns ``True`` iff an escape effect is observed.
        """
        return self.judge(pre_state, post_state).confirmed
