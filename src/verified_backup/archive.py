"""Zip / tar.gz archive creation and manifest/checksum sidecar writing."""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
import os
import tarfile
import tempfile
import zipfile
import zlib
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from .paths import validate_file_path
from .scanner import ScannedFile, manifest_bytes, sha256_file

BACKUP_MANIFEST_NAME = "BACKUP_MANIFEST.json"
PAYLOAD_PREFIX = "payload/"
CHECKSUM_SCHEMA_VERSION = "verified-backup-checksums/v1"

# Exceptions that zipfile / tarfile / gzip / zlib raise when archive bytes are damaged
# or truncated. Readers convert them into ArchiveError so callers see one error type.
CORRUPT_ARCHIVE_ERRORS: tuple[type[BaseException], ...] = (
    zipfile.BadZipFile,
    tarfile.TarError,
    gzip.BadGzipFile,
    zlib.error,
    EOFError,
)


class ArchiveError(RuntimeError):
    """Raised when an archive cannot be created or read safely."""


def archive_extension(archive_format: str) -> str:
    if archive_format == "zip":
        return ".zip"
    if archive_format == "tar":
        return ".tar.gz"
    raise ArchiveError(f"Unsupported archive format: {archive_format}")


def make_archive_name(name: str | None, archive_format: str) -> str:
    safe_name = name or f"verified-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    validate_file_path(safe_name)
    if "/" in safe_name:
        raise ArchiveError("Archive name must be a single filename, not a path")
    return safe_name + archive_extension(archive_format)


def write_archive(
    *,
    archive_path: Path,
    archive_format: str,
    manifest: dict[str, Any],
    files: tuple[ScannedFile, ...],
) -> dict[str, Any]:
    """Write the payload and an embedded manifest; return the final manifest.

    The final manifest records size and SHA-256 of the bytes actually written to
    the archive, not the values seen during the scan.
    """
    if manifest.get("summary", {}).get("missing_target_count") or manifest.get("missing_targets"):
        raise ArchiveError("Refusing backup with missing configured targets")
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    if archive_path.exists():
        raise ArchiveError(f"Archive already exists: {archive_path}")

    # Build in a uniquely owned file, then publish without replacing a winner.
    # A hard link is an atomic no-clobber publication on supported filesystems.
    # Unsupported filesystems fail closed rather than fall back to replacement.
    with tempfile.NamedTemporaryFile(prefix=".verified-backup-", dir=archive_path.parent,
                                     delete=False) as staging:
        tmp_path = Path(staging.name)
    try:
        if archive_format == "zip":
            final_files = _write_zip(tmp_path, manifest, files)
        elif archive_format == "tar":
            final_files = _write_tar(tmp_path, manifest, files)
        else:
            raise ArchiveError(f"Unsupported archive format: {archive_format}")
        final_manifest = _finalize_manifest(manifest, final_files)
        # Import lazily because the reader imports archive constants. Publish only
        # manifests accepted by that same reader, including portable path rules.
        from .verify import validate_manifest
        validate_manifest(final_manifest)
        os.link(tmp_path, archive_path)
        return final_manifest
    finally:
        tmp_path.unlink()


def write_sidecar_manifests(
    *,
    archive_path: Path,
    manifest: dict[str, Any],
) -> tuple[Path, Path]:
    """Write ``<archive>.manifest.json`` and ``<archive>.checksums.json`` next to the archive."""
    manifest_path = archive_path.with_name(archive_path.name + ".manifest.json")
    checksum_path = archive_path.with_name(archive_path.name + ".checksums.json")
    if manifest_path.exists() or checksum_path.exists():
        raise ArchiveError("Manifest or checksum sidecar already exists")

    checksum_manifest = {
        "schema_version": CHECKSUM_SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "archive_path": archive_path.name,
        "archive_sha256": sha256_file(archive_path),
        "file_count": len(manifest.get("files", [])),
        "files": [
            {
                "path": item["path"],
                "sha256": item["sha256"],
                "size": item["size"],
            }
            for item in manifest.get("files", [])
        ],
    }
    created: list[Path] = []
    try:
        for path, data in ((manifest_path, manifest), (checksum_path, checksum_manifest)):
            with path.open("x", encoding="utf-8") as stream:
                created.append(path)
                stream.write(json.dumps(data, indent=2, sort_keys=True) + "\n")
    except BaseException:
        for path in reversed(created):
            path.unlink()
        raise
    return manifest_path, checksum_path


def _write_zip(
    archive_path: Path,
    manifest: dict[str, Any],
    files: tuple[ScannedFile, ...],
) -> list[dict[str, Any]]:
    archived_files: list[dict[str, Any]] = []
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for item in files:
            archived_files.append(_write_zip_payload(zf, item))
        zf.writestr(BACKUP_MANIFEST_NAME, manifest_bytes(_finalize_manifest(manifest, archived_files)))
    return archived_files


def _write_tar(
    archive_path: Path,
    manifest: dict[str, Any],
    files: tuple[ScannedFile, ...],
) -> list[dict[str, Any]]:
    archived_files: list[dict[str, Any]] = []
    with tarfile.open(archive_path, "w:gz") as tf:
        for item in files:
            archived_files.append(_write_tar_payload(tf, item))
        _write_tar_manifest(tf, _finalize_manifest(manifest, archived_files))
    return archived_files



def _write_zip_payload(zf: zipfile.ZipFile, item: ScannedFile) -> dict[str, Any]:
    info = zipfile.ZipInfo(PAYLOAD_PREFIX + item.rel_path)
    info.compress_type = zipfile.ZIP_DEFLATED
    digest = hashlib.sha256()
    size = 0
    stat = item.abs_path.stat()
    with item.abs_path.open("rb") as src, zf.open(info, "w") as dst:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
            dst.write(chunk)
    return {
        "path": item.rel_path,
        "size": size,
        "mtime_ns": stat.st_mtime_ns,
        "sha256": digest.hexdigest(),
        "target": item.target_name,
    }


def _write_tar_payload(
    tf: tarfile.TarFile,
    item: ScannedFile,
    expected: str | None = None,
) -> dict[str, Any]:
    if expected is not None and expected != item.rel_path:
        raise ArchiveError("Internal tar rebuild path mismatch")
    payload = item.abs_path.read_bytes()
    stat = item.abs_path.stat()
    info = tarfile.TarInfo(PAYLOAD_PREFIX + item.rel_path)
    info.size = len(payload)
    info.mtime = int(stat.st_mtime)
    tf.addfile(info, fileobj=BytesIO(payload))
    return {
        "path": item.rel_path,
        "size": len(payload),
        "mtime_ns": stat.st_mtime_ns,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "target": item.target_name,
    }


def _write_tar_manifest(tf: tarfile.TarFile, manifest: dict[str, Any]) -> None:
    manifest_payload = manifest_bytes(manifest)
    info = tarfile.TarInfo(BACKUP_MANIFEST_NAME)
    info.size = len(manifest_payload)
    info.mtime = int(datetime.now(timezone.utc).timestamp())
    tf.addfile(info, fileobj=BytesIO(manifest_payload))


def _finalize_manifest(
    manifest: dict[str, Any],
    files: list[dict[str, Any]],
) -> dict[str, Any]:
    final_manifest = copy.deepcopy(manifest)
    final_manifest["files"] = sorted(files, key=lambda item: item["path"])
    if final_manifest.get("private_metadata") is False:
        for item in final_manifest["files"]:
            item.pop("target", None)
    final_manifest["summary"]["file_count"] = len(files)
    final_manifest["summary"]["total_bytes"] = sum(item["size"] for item in files)
    return final_manifest
