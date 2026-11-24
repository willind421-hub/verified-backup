"""Loading and validation of backup rule files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .paths import is_safe_relative_path

RULES_SCHEMA_VERSION = "verified-backup-rules/v1"
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "default_rules.json"


class ConfigError(ValueError):
    """Raised when a backup rule file is invalid."""


def load_rules(path: str | Path | None = None) -> dict[str, Any]:
    """Load and validate a rules file (the packaged default rules when ``path`` is None)."""
    rules_path = Path(path) if path else DEFAULT_CONFIG_PATH
    with rules_path.open("r", encoding="utf-8") as f:
        rules = json.load(f)
    validate_rules(rules)
    return rules


def validate_rules(rules: dict[str, Any]) -> None:
    if rules.get("schema_version") != RULES_SCHEMA_VERSION:
        raise ConfigError("Unsupported or missing rules schema_version")
    targets = rules.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ConfigError("Rules must define at least one target")
    for target in targets:
        if not isinstance(target, dict):
            raise ConfigError("Each target must be an object")
        for key in ("name", "path", "include"):
            if key not in target:
                raise ConfigError(f"Target is missing required key: {key}")
        if not isinstance(target["path"], str) or not is_safe_relative_path(target["path"]):
            raise ConfigError(
                f"Target {target['name']} path must be relative to the source root "
                f"without '..': {target['path']!r}"
            )
        if not isinstance(target["include"], list) or not target["include"]:
            raise ConfigError(f"Target {target['name']} must define include patterns")
        if "exclude" in target and not isinstance(target["exclude"], list):
            raise ConfigError(f"Target {target['name']} exclude must be a list")

    exclude = rules.get("exclude", {})
    if not isinstance(exclude, dict):
        raise ConfigError("exclude must be an object")
    for key in ("path_patterns", "secret_name_patterns"):
        if key in exclude and not isinstance(exclude[key], list):
            raise ConfigError(f"exclude.{key} must be a list")


def resolve_source_root(root: str | Path) -> Path:
    source_root = Path(root).expanduser().resolve()
    if not source_root.exists():
        raise ConfigError(f"Source root does not exist: {source_root}")
    if not source_root.is_dir():
        raise ConfigError(f"Source root is not a directory: {source_root}")
    return source_root
