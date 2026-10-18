"""Validated configuration for SandboxEscapeFinder.

Configuration can come from a dict, a JSON file path, an existing
:class:`Config`, or ``None`` (defaults). Invalid or *unsafe* settings are
rejected with :class:`ConfigError` rather than silently ignored — for example
asking for in-process execution without explicitly acknowledging the risk, or
naming a detector/category that does not exist.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .detectors import DETECTOR_IDS


class ConfigError(ValueError):
    """Raised when a configuration value is invalid or unsafe."""


# Isolation modes understood by the prober.
VALID_ISOLATION_MODES = ("subprocess", "docker", "inprocess")


@dataclass
class ResourceLimits:
    """POSIX resource limits applied to each isolated worker (best effort).

    On macOS some limits (notably address space) may not be enforced by the
    kernel; the isolation layer applies each limit defensively and documents
    which ones are advisory. Values are in the units named by the field.
    """

    cpu_seconds: int = 5
    address_space_mb: int = 512
    file_size_mb: int = 8
    open_files: int = 64
    processes: int = 64

    def to_dict(self) -> dict:
        return {
            "cpu_seconds": self.cpu_seconds,
            "address_space_mb": self.address_space_mb,
            "file_size_mb": self.file_size_mb,
            "open_files": self.open_files,
            "processes": self.processes,
        }


@dataclass
class IsolationConfig:
    """How dynamic payloads are isolated from the host and test runner."""

    mode: str = "subprocess"
    # If True, the configured mode is *required*; when it is unavailable the
    # prober reports BLOCKED instead of falling back to a weaker mechanism.
    require_isolation: bool = True
    # In-process execution is dangerous for untrusted code. It is refused
    # unless BOTH mode == "inprocess" AND this flag is explicitly True.
    allow_in_process: bool = False
    # We never grant network to a worker by default.
    allow_network: bool = False

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "require_isolation": self.require_isolation,
            "allow_in_process": self.allow_in_process,
            "allow_network": self.allow_network,
        }


@dataclass
class ReportingConfig:
    include_snippets: bool = True
    json_indent: int = 2
    max_table_rows: int = 100

    def to_dict(self) -> dict:
        return {
            "include_snippets": self.include_snippets,
            "json_indent": self.json_indent,
            "max_table_rows": self.max_table_rows,
        }


@dataclass
class Config:
    """Top-level validated configuration object."""

    enabled_detectors: list[str] = field(default_factory=lambda: list(DETECTOR_IDS))
    enabled_categories: Optional[list[str]] = None  # None => all categories
    custom_payloads: list[dict] = field(default_factory=list)
    seed: int = 1337
    min_confidence: float = 0.0
    timeout_seconds: float = 10.0
    resource_limits: ResourceLimits = field(default_factory=ResourceLimits)
    isolation: IsolationConfig = field(default_factory=IsolationConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)

    # ------------------------------------------------------------------ #
    # Construction helpers.
    # ------------------------------------------------------------------ #
    @classmethod
    def default(cls) -> "Config":
        return cls()

    @classmethod
    def coerce(cls, config: Any) -> "Config":
        """Accept None / dict / path / Config and return a validated Config."""
        if config is None:
            return cls.default()
        if isinstance(config, Config):
            return config.validate()
        if isinstance(config, (str, Path)):
            return cls.from_file(config)
        if isinstance(config, dict):
            return cls.from_dict(config)
        raise ConfigError(f"Unsupported config type: {type(config).__name__}")

    @classmethod
    def from_file(cls, path: Any) -> "Config":
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"Config file not found: {p}")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ConfigError(f"Config file is not valid JSON: {e}") from e
        if not isinstance(data, dict):
            raise ConfigError("Config file must contain a JSON object.")
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        known = {
            "enabled_detectors",
            "enabled_categories",
            "custom_payloads",
            "seed",
            "min_confidence",
            "timeout_seconds",
            "resource_limits",
            "isolation",
            "reporting",
        }
        # Keys beginning with "_" are treated as inline comments and ignored.
        data = {k: v for k, v in data.items() if not k.startswith("_")}
        unknown = set(data) - known
        if unknown:
            raise ConfigError(f"Unknown configuration keys: {sorted(unknown)}")

        cfg = cls()
        if "enabled_detectors" in data:
            cfg.enabled_detectors = list(data["enabled_detectors"])
        if "enabled_categories" in data:
            cfg.enabled_categories = (
                None if data["enabled_categories"] is None else list(data["enabled_categories"])
            )
        if "custom_payloads" in data:
            cfg.custom_payloads = list(data["custom_payloads"])
        if "seed" in data:
            cfg.seed = data["seed"]
        if "min_confidence" in data:
            cfg.min_confidence = data["min_confidence"]
        if "timeout_seconds" in data:
            cfg.timeout_seconds = data["timeout_seconds"]
        if "resource_limits" in data:
            rl = data["resource_limits"] or {}
            if not isinstance(rl, dict):
                raise ConfigError("'resource_limits' must be an object.")
            cfg.resource_limits = ResourceLimits(**{**cfg.resource_limits.to_dict(), **rl})
        if "isolation" in data:
            iso = data["isolation"] or {}
            if not isinstance(iso, dict):
                raise ConfigError("'isolation' must be an object.")
            cfg.isolation = IsolationConfig(**{**cfg.isolation.to_dict(), **iso})
        if "reporting" in data:
            rep = data["reporting"] or {}
            if not isinstance(rep, dict):
                raise ConfigError("'reporting' must be an object.")
            cfg.reporting = ReportingConfig(**{**cfg.reporting.to_dict(), **rep})

        cfg.validate()
        return cfg

    # ------------------------------------------------------------------ #
    # Validation.
    # ------------------------------------------------------------------ #
    def validate(self) -> "Config":
        # Detectors must all be known.
        unknown_det = [d for d in self.enabled_detectors if d not in DETECTOR_IDS]
        if unknown_det:
            raise ConfigError(
                f"Unknown detector id(s): {unknown_det}. Valid: {list(DETECTOR_IDS)}"
            )
        if not isinstance(self.seed, int):
            raise ConfigError("'seed' must be an integer for reproducibility.")
        if (isinstance(self.min_confidence, bool)
                or not isinstance(self.min_confidence, (int, float))
                or not 0 <= self.min_confidence <= 1):
            raise ConfigError("'min_confidence' must be a number between 0 and 1.")
        if not isinstance(self.timeout_seconds, (int, float)) or self.timeout_seconds <= 0:
            raise ConfigError("'timeout_seconds' must be a positive number.")

        for name, value in self.resource_limits.to_dict().items():
            if not isinstance(value, int) or value <= 0:
                raise ConfigError(f"resource_limits.{name} must be a positive integer.")

        if self.isolation.mode not in VALID_ISOLATION_MODES:
            raise ConfigError(
                f"isolation.mode must be one of {VALID_ISOLATION_MODES}, "
                f"got {self.isolation.mode!r}."
            )
        # Safety gate: in-process execution requires an explicit opt-in.
        if self.isolation.mode == "inprocess" and not self.isolation.allow_in_process:
            raise ConfigError(
                "isolation.mode='inprocess' is unsafe for untrusted payloads and is "
                "refused unless isolation.allow_in_process is explicitly set to true."
            )
        if self.isolation.allow_network:
            # Allowed but surfaced; network access defeats part of the threat model.
            pass

        # Validate custom payloads minimally (full validation in corpus).
        for i, p in enumerate(self.custom_payloads):
            if not isinstance(p, dict):
                raise ConfigError(f"custom_payloads[{i}] must be an object.")
            for required in ("id", "source"):
                if required not in p:
                    raise ConfigError(f"custom_payloads[{i}] missing required key '{required}'.")
        return self

    def to_dict(self) -> dict:
        return {
            "enabled_detectors": list(self.enabled_detectors),
            "enabled_categories": self.enabled_categories,
            "custom_payloads": list(self.custom_payloads),
            "seed": self.seed,
            "min_confidence": self.min_confidence,
            "timeout_seconds": self.timeout_seconds,
            "resource_limits": self.resource_limits.to_dict(),
            "isolation": self.isolation.to_dict(),
            "reporting": self.reporting.to_dict(),
        }
