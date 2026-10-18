"""Isolation backends that run a payload away from the main test-runner process.

Two backends are provided:

* :class:`SubprocessIsolation` — runs the worker in a fresh, isolated
  interpreter (``python -I``) with POSIX resource limits, a scrubbed
  environment, a disposable temporary workspace, and a wall-clock timeout. This
  is **process-level** isolation. It is *not* a strong security boundary: it
  does not use OS namespaces/VMs and (on a plain host) cannot block network by
  itself. It is appropriate here because the corpus consists of low-risk
  RestrictedPython probes, which RestrictedPython blocks anyway, and because it
  prevents a payload from touching the test-runner process state.

* :class:`DockerIsolation` — runs the same worker inside a disposable container
  with ``--network none``, a read-only root filesystem, a writable tmpfs
  workspace, a non-root user, and memory/CPU/pid limits. This is the
  recommended mode for untrusted or novel payloads. It requires a running
  Docker daemon and a pre-built image (see ``Dockerfile``). When unavailable it
  reports *unavailable* with a reason; the prober then marks affected cases
  BLOCKED rather than silently downgrading.

A key safety property: no backend can be silently bypassed. The prober selects
exactly one backend from config and, when ``require_isolation`` is set, refuses
to fall back to a weaker mechanism.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from .config import Config


# Status tokens describing the raw outcome at the isolation layer. The prober
# maps these (plus the oracle verdict) to the assignment's outcome taxonomy.
ISO_OK = "ok"  # worker produced a structured result
ISO_TIMEOUT = "timeout"
ISO_RESOURCE = "resource_exceeded"
ISO_INFRA = "infra_failure"
ISO_UNAVAILABLE = "unavailable"


@dataclass
class WorkerSpec:
    """What the worker needs to run one payload."""

    payload_source: str
    sandbox_runner: str
    sandbox_kwargs: dict = field(default_factory=dict)
    oracle_runner: str = "sandbox_escape_finder.runners:build_canary_oracle"
    oracle_kwargs: dict = field(default_factory=dict)


@dataclass
class IsolationResult:
    """Raw facts produced by running a payload in an isolation backend."""

    backend: str
    status: str
    duration: float
    timed_out: bool = False
    returncode: Optional[int] = None
    infra_error: Optional[str] = None
    outcome: Optional[dict] = None  # ExecOutcome dict from the worker
    verdict: Optional[dict] = None  # OracleVerdict dict from the worker
    raw_stderr: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _project_root() -> str:
    """Directory that must be on sys.path for the worker to import the package."""
    # .../sandbox_escape_finder/isolation.py -> parent of the package dir
    return str(Path(__file__).resolve().parent.parent)


class IsolationBackend:
    name = "base"

    def __init__(self, config: Config) -> None:
        self.config = config

    def available(self) -> tuple[bool, str]:
        raise NotImplementedError

    def run(self, spec: WorkerSpec) -> IsolationResult:
        raise NotImplementedError


# --------------------------------------------------------------------------- #
# Subprocess backend.
# --------------------------------------------------------------------------- #
def _apply_rlimits(limits: dict):
    """Return a preexec_fn that applies POSIX resource limits in the child.

    Each limit is applied defensively: an unsupported limit on a given OS is
    skipped rather than aborting the launch. On macOS some limits (notably
    address space) are advisory.
    """

    def _preexec():  # pragma: no cover - runs in the forked child
        import resource

        def _set(res_name, value):
            res = getattr(resource, res_name, None)
            if res is None:
                return
            try:
                resource.setrlimit(res, (value, value))
            except (ValueError, OSError):
                pass

        _set("RLIMIT_CPU", int(limits["cpu_seconds"]))
        _set("RLIMIT_FSIZE", int(limits["file_size_mb"]) * 1024 * 1024)
        _set("RLIMIT_NOFILE", int(limits["open_files"]))
        _set("RLIMIT_NPROC", int(limits["processes"]))
        _set("RLIMIT_AS", int(limits["address_space_mb"]) * 1024 * 1024)

    return _preexec


class SubprocessIsolation(IsolationBackend):
    name = "subprocess"

    def available(self) -> tuple[bool, str]:
        if os.name != "posix":
            return False, "subprocess resource limits require a POSIX OS"
        import importlib.util

        if importlib.util.find_spec("resource") is None:
            return False, "'resource' module unavailable on this interpreter"
        return True, "process isolation (python -I + POSIX rlimits + temp workspace)"

    def run(self, spec: WorkerSpec) -> IsolationResult:
        ok, reason = self.available()
        if not ok:
            return IsolationResult(
                backend=self.name, status=ISO_UNAVAILABLE, duration=0.0, infra_error=reason
            )

        workspace = Path(tempfile.mkdtemp(prefix="sbxef_ws_"))
        request = {
            "payload_source": spec.payload_source,
            "sandbox_runner": spec.sandbox_runner,
            "sandbox_kwargs": spec.sandbox_kwargs,
            "oracle_runner": spec.oracle_runner,
            "oracle_kwargs": spec.oracle_kwargs,
            "workspace": str(workspace),
            "sys_path": [_project_root()],
        }
        # Scrubbed environment: no inherited PYTHON*, point temp at the workspace.
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "TMPDIR": str(workspace),
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        limits = self.config.resource_limits.to_dict()
        preexec = _apply_rlimits(limits)

        start = time.monotonic()
        timed_out = False
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-m", "sandbox_escape_finder._worker"],
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds,
                cwd=str(workspace),
                env=env,
                preexec_fn=preexec,
            )
            duration = time.monotonic() - start
            stdout, stderr, returncode = proc.stdout, proc.stderr, proc.returncode
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            timed_out = True
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            returncode = None
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

        if timed_out:
            return IsolationResult(
                backend=self.name,
                status=ISO_TIMEOUT,
                duration=duration,
                timed_out=True,
                raw_stderr=stderr[-2000:],
            )

        return self._parse(stdout, stderr, returncode, duration)

    def _parse(self, stdout, stderr, returncode, duration) -> IsolationResult:
        try:
            data = json.loads(stdout)
        except (json.JSONDecodeError, TypeError):
            # No structured result: the worker likely died (e.g. killed by a
            # resource limit). Treat as resource/infra failure, never as "safe".
            status = ISO_RESOURCE if returncode not in (0, None) else ISO_INFRA
            return IsolationResult(
                backend=self.name,
                status=status,
                duration=duration,
                returncode=returncode,
                infra_error=f"no JSON result from worker (returncode={returncode})",
                raw_stderr=(stderr or "")[-2000:],
            )
        if not data.get("ok"):
            return IsolationResult(
                backend=self.name,
                status=ISO_INFRA,
                duration=duration,
                returncode=returncode,
                infra_error=data.get("worker_error", "worker reported failure"),
                raw_stderr=(stderr or "")[-2000:],
            )
        return IsolationResult(
            backend=self.name,
            status=ISO_OK,
            duration=duration,
            returncode=returncode,
            outcome=data.get("outcome"),
            verdict=data.get("verdict"),
            raw_stderr=(stderr or "")[-2000:],
        )


# --------------------------------------------------------------------------- #
# Docker backend.
# --------------------------------------------------------------------------- #
class DockerIsolation(IsolationBackend):
    """Run the worker inside a disposable, network-less container.

    Requires a running Docker daemon and a pre-built image (default
    ``sandbox-escape-finder:latest``; see ``Dockerfile``). The whole workspace
    lives on an in-container tmpfs, so the host filesystem is never touched by
    the payload.
    """

    name = "docker"
    DEFAULT_IMAGE = "sandbox-escape-finder:latest"

    def __init__(self, config: Config, image: Optional[str] = None) -> None:
        super().__init__(config)
        self.image = image or os.environ.get("SBXEF_DOCKER_IMAGE", self.DEFAULT_IMAGE)

    def available(self) -> tuple[bool, str]:
        if shutil.which("docker") is None:
            return False, "docker CLI not found on PATH"
        try:
            info = subprocess.run(
                ["docker", "info"], capture_output=True, text=True, timeout=10
            )
        except Exception as exc:  # noqa: BLE001
            return False, f"could not run 'docker info': {exc!r}"
        if info.returncode != 0:
            return False, "docker daemon not reachable (is Docker running?)"
        # Use `docker image ls -q <ref>`: it resolves a tag reliably even for
        # buildkit/containerd manifest-list images, where `docker image inspect
        # <tag>` can spuriously report "No such image".
        img = subprocess.run(
            ["docker", "image", "ls", "-q", self.image], capture_output=True, text=True
        )
        if img.returncode != 0 or not img.stdout.strip():
            return (
                False,
                f"docker image '{self.image}' not found; build it with the provided Dockerfile",
            )
        return True, f"container isolation using image '{self.image}'"

    def run(self, spec: WorkerSpec) -> IsolationResult:
        ok, reason = self.available()
        if not ok:
            return IsolationResult(
                backend=self.name, status=ISO_UNAVAILABLE, duration=0.0, infra_error=reason
            )

        request = {
            "payload_source": spec.payload_source,
            "sandbox_runner": spec.sandbox_runner,
            "sandbox_kwargs": spec.sandbox_kwargs,
            "oracle_runner": spec.oracle_runner,
            "oracle_kwargs": spec.oracle_kwargs,
            "workspace": "/work",
            "sys_path": [],  # package is installed in the image
        }
        limits = self.config.resource_limits.to_dict()
        cmd = [
            "docker", "run", "--rm", "-i",
            "--network", "none",
            "--read-only",
            # mode=1777 (sticky, world-writable like /tmp) so the non-root
            # worker user can create the canary/marker in the tmpfs workspace.
            "--tmpfs", f"/work:rw,size={limits['file_size_mb'] * 2}m,mode=1777",
            "--memory", f"{limits['address_space_mb']}m",
            "--cpus", "1",
            "--pids-limit", str(limits["processes"]),
            "--user", "65534:65534",  # nobody
            "-w", "/work",
            "-e", "PYTHONDONTWRITEBYTECODE=1",
            "--entrypoint", "python",
            self.image,
            "-I", "-m", "sandbox_escape_finder._worker",
        ]
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=self.config.timeout_seconds + 15,  # allow container startup
            )
            duration = time.monotonic() - start
        except subprocess.TimeoutExpired:
            duration = time.monotonic() - start
            return IsolationResult(
                backend=self.name, status=ISO_TIMEOUT, duration=duration, timed_out=True
            )

        # Reuse the subprocess parser logic for the JSON contract.
        return SubprocessIsolation._parse(self, proc.stdout, proc.stderr, proc.returncode, duration)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# In-process backend (gated; for controlled unit tests only).
# --------------------------------------------------------------------------- #
class InProcessExecutor:
    """Runs a sandbox+oracle in the current process. UNSAFE for untrusted code.

    This is not a real isolation backend and is only reached when config
    explicitly sets ``isolation.mode='inprocess'`` AND
    ``isolation.allow_in_process=True`` (both gates enforced in config). It
    exists so the oracle-correctness test can drive the toy sandbox directly.
    """

    name = "inprocess"

    def __init__(self, config: Config) -> None:
        self.config = config

    def available(self) -> tuple[bool, str]:
        return True, "in-process execution (UNSAFE; controlled tests only)"

    def run_callables(self, sandbox, oracle, payload_source: str) -> IsolationResult:
        # This mode is explicitly opted into by validated config. Adapt local
        # functions here without weakening the import requirement in OS workers.
        from .adapters import CallableOracle, CallableSandbox

        if not hasattr(sandbox, "runner_spec"):
            sandbox = CallableSandbox(func=sandbox)
        if not hasattr(oracle, "setup"):
            oracle = CallableOracle(func=oracle)
        workspace = Path(tempfile.mkdtemp(prefix="sbxef_inproc_"))
        start = time.monotonic()
        try:
            before = oracle.setup(workspace)
            outcome = sandbox(payload_source, {"workspace": str(workspace)})
            verdict = oracle.evaluate(workspace, before, getattr(sandbox, "last_result", outcome))
            duration = time.monotonic() - start
            return IsolationResult(
                backend=self.name,
                status=ISO_OK,
                duration=duration,
                outcome=outcome.to_dict(),
                verdict=verdict.to_dict(),
            )
        finally:
            shutil.rmtree(workspace, ignore_errors=True)


def make_backend(config: Config) -> IsolationBackend:
    """Select the single isolation backend named by config."""
    mode = config.isolation.mode
    if mode == "subprocess":
        return SubprocessIsolation(config)
    if mode == "docker":
        return DockerIsolation(config)
    if mode == "inprocess":
        # Returned as an InProcessExecutor; the prober handles it specially.
        return InProcessExecutor(config)  # type: ignore[return-value]
    raise ValueError(f"Unknown isolation mode: {mode}")
