"""Target expansion, exclusion rules, SHA-256 hashing and backup manifest construction."""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from .paths import (
    first_link_component,
    is_link,
    is_relative_to,
    is_safe_relative_path,
    normalize_pattern,
    normalize_rel,
)

HASH_CHUNK_SIZE = 1024 * 1024
MANIFEST_SCHEMA_VERSION = "verified-backup-manifest/v1"


@dataclass(frozen=True)
class ScannedFile:
    abs_path: Path
    rel_path: str
    target_name: str
    size: int
    mtime_ns: int
    sha256: str


@dataclass(frozen=True)
class ExcludedPath:
    rel_path: str
    target_name: str
    reason: str


@dataclass(frozen=True)
class ScanResult:
    source_root: Path
    files: tuple[ScannedFile, ...]
    excluded: tuple[ExcludedPath, ...]
    missing_targets: tuple[dict[str, str], ...]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(HASH_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_stream(stream) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(HASH_CHUNK_SIZE), b""):
        digest.update(chunk)
    return digest.hexdigest()


def _zero_directory_variants(pattern: str) -> list[str]:
    """Return ``pattern`` plus every form with one or more ``**/`` segments removed.

    ``**/`` means "any number of directories, including none" (as in gitignore),
    but neither ``PurePosixPath.match`` nor ``fnmatch`` covers the "none" case:
    on its own, ``**/.git/**`` would miss a ``.git`` directory directly under the
    source root.
    """
    variants = [pattern]
    pending = [pattern]
    while pending:
        current = pending.pop()
        index = current.find("**/")
        while index != -1:
            if index == 0 or current[index - 1] == "/":
                shorter = current[:index] + current[index + 3:]
                if shorter and shorter not in variants:
                    variants.append(shorter)
                    pending.append(shorter)
            index = current.find("**/", index + 1)
    return variants


def matches_path(pattern: str, rel_path: str) -> bool:
    pattern = normalize_pattern(pattern).lower()
    rel_path = rel_path.replace("\\", "/").lstrip("/").lower()
    posix = PurePosixPath(rel_path)
    return any(
        posix.match(variant) or fnmatch.fnmatchcase(rel_path, variant)
        for variant in _zero_directory_variants(pattern)
    )


def matches_any(patterns: list[str], rel_path: str) -> bool:
    return any(matches_path(pattern, rel_path) for pattern in patterns)


def matches_secret_name(patterns: list[str], rel_path: str) -> bool:
    lowered_parts = [part.lower() for part in PurePosixPath(rel_path).parts]
    full = rel_path.replace("\\", "/").lower()
    for pattern in patterns:
        pattern = normalize_pattern(pattern).lower()
        if fnmatch.fnmatchcase(full, pattern):
            return True
        if any(fnmatch.fnmatchcase(part, pattern) for part in lowered_parts):
            return True
    return False


def scan_source(source_root: Path, rules: dict[str, Any]) -> ScanResult:
    """Expand rule targets under ``source_root`` and hash every included file.

    ``source_root`` should already be resolved (see ``config.resolve_source_root``).
    Candidate paths are kept unresolved until links have been classified, so a
    symlink or junction is never followed silently.
    """
    global_exclude = rules.get("exclude", {})
    path_patterns = [normalize_pattern(p) for p in global_exclude.get("path_patterns", [])]
    secret_patterns = [
        normalize_pattern(p) for p in global_exclude.get("secret_name_patterns", [])
    ]
    skip_symlinks = bool(global_exclude.get("skip_symlinks", True))

    included: dict[str, ScannedFile] = {}
    excluded: list[ExcludedPath] = []
    missing: list[dict[str, str]] = []

    for target in rules["targets"]:
        target_name = target["name"]
        if not is_safe_relative_path(str(target["path"])):
            raise ValueError(
                f"Target {target_name} path must stay inside the source root: {target['path']!r}"
            )
        # Lexical join on purpose: resolving here would follow a link at or above
        # the target base before it could be classified.
        target_base = source_root / target["path"]
        if not target_base.exists():
            missing.append({"name": target_name, "path": target["path"]})
            continue

        target_exclude = [normalize_pattern(p) for p in target.get("exclude", [])]
        candidates = _candidate_files(target_base, target["include"])
        for candidate in sorted(candidates, key=lambda p: p.as_posix().lower()):
            lexical_rel = candidate.relative_to(source_root).as_posix()
            target_rel = candidate.relative_to(target_base).as_posix()

            reason = classify_exclusion(
                abs_path=candidate,
                rel_path=lexical_rel,
                target_rel=target_rel,
                secret_patterns=secret_patterns,
                path_patterns=path_patterns,
                target_exclude=target_exclude,
                skip_symlinks=skip_symlinks,
                source_root=source_root,
            )
            if reason:
                excluded.append(
                    ExcludedPath(
                        rel_path=lexical_rel,
                        target_name=target_name,
                        reason=reason,
                    )
                )
                continue

            abs_path = candidate.resolve()
            rel_path = normalize_rel(abs_path, source_root)
            if rel_path in included:
                continue
            stat = abs_path.stat()
            included[rel_path] = ScannedFile(
                abs_path=abs_path,
                rel_path=rel_path,
                target_name=target_name,
                size=stat.st_size,
                mtime_ns=stat.st_mtime_ns,
                sha256=sha256_file(abs_path),
            )

    return ScanResult(
        source_root=source_root,
        files=tuple(included[path] for path in sorted(included)),
        excluded=tuple(sorted(excluded, key=lambda item: item.rel_path)),
        missing_targets=tuple(missing),
    )


def _candidate_files(base: Path, include_patterns: list[str]) -> set[Path]:
    # Paths are returned unresolved; link classification happens in classify_exclusion.
    files: set[Path] = set()
    if base.is_file():
        return {base}

    for pattern in include_patterns:
        normalized = normalize_pattern(pattern)
        for candidate in base.glob(normalized):
            try:
                if candidate.is_file():
                    files.add(candidate)
            except OSError:
                continue
    return files


def classify_exclusion(
    *,
    abs_path: Path,
    rel_path: str,
    target_rel: str,
    secret_patterns: list[str],
    path_patterns: list[str],
    target_exclude: list[str],
    skip_symlinks: bool,
    source_root: Path | None = None,
) -> str | None:
    """Return the exclusion reason for a candidate file, or ``None`` to include it.

    ``abs_path`` must be the *unresolved* candidate path. When ``source_root`` is
    given, every path component below the root is checked for symlinks/junctions
    before anything is resolved, and files whose real location is outside the
    root are rejected with reason ``outside_root`` (this applies even when
    ``skip_symlinks`` is false).
    """
    rel_paths = [rel_path]
    if source_root is not None:
        if skip_symlinks and first_link_component(abs_path, source_root) is not None:
            return "symlink"
        if not is_relative_to(abs_path, source_root):
            return "outside_root"
        real_rel = normalize_rel(abs_path, source_root)
        if real_rel != rel_path:
            rel_paths.append(real_rel)
    elif skip_symlinks and is_link(abs_path):
        return "symlink"
    if any(matches_secret_name(secret_patterns, path) for path in rel_paths):
        return "secret_name"
    if any(matches_any(path_patterns, path) for path in rel_paths):
        return "global_exclude"
    if matches_any(target_exclude, target_rel):
        return "target_exclude"
    return None


def build_backup_manifest(
    scan: ScanResult,
    rules: dict[str, Any],
    archive_format: str | None = None,
) -> dict[str, Any]:
    files = [
        {
            "path": item.rel_path,
            "size": item.size,
            "mtime_ns": item.mtime_ns,
            "sha256": item.sha256,
            "target": item.target_name,
        }
        for item in scan.files
    ]
    excluded = [
        {
            "path": item.rel_path,
            "target": item.target_name,
            "reason": item.reason,
        }
        for item in scan.excluded
    ]
    total_bytes = sum(item.size for item in scan.files)
    return {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_root": scan.source_root.as_posix(),
        "archive_format": archive_format,
        "rules": _manifest_rules_snapshot(rules),
        "summary": {
            "file_count": len(files),
            "total_bytes": total_bytes,
            "excluded_count": len(excluded),
            "missing_target_count": len(scan.missing_targets),
        },
        "missing_targets": list(scan.missing_targets),
        "excluded": excluded,
        "files": files,
    }


def manifest_bytes(manifest: dict[str, Any]) -> bytes:
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _manifest_rules_snapshot(rules: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": rules.get("schema_version"),
        "targets": rules.get("targets", []),
        "exclude": rules.get("exclude", {}),
    }
