"""Embedded manifest loading, payload checksum verification and sidecar validation."""

from __future__ import annotations

import hashlib
import json
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from .archive import (
    BACKUP_MANIFEST_NAME,
    CHECKSUM_SCHEMA_VERSION,
    CORRUPT_ARCHIVE_ERRORS,
    PAYLOAD_PREFIX,
    ArchiveError,
)
from .scanner import HASH_CHUNK_SIZE, sha256_file


def read_embedded_manifest(archive_path: Path) -> dict[str, Any]:
    """Return the ``BACKUP_MANIFEST.json`` stored inside the archive.

    Raises ArchiveError if the archive type is unsupported, the manifest is
    missing, or the archive is too damaged to read it.
    """
    if zipfile.is_zipfile(archive_path):
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                try:
                    with zf.open(BACKUP_MANIFEST_NAME, "r") as f:
                        return json.loads(f.read().decode("utf-8"))
                except KeyError as exc:
                    raise ArchiveError("Archive is missing BACKUP_MANIFEST.json") from exc
        except (*CORRUPT_ARCHIVE_ERRORS, ValueError) as exc:
            raise ArchiveError(f"Archive manifest is corrupt or unreadable: {exc}") from exc

    if tarfile.is_tarfile(archive_path):
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                try:
                    member = tf.getmember(BACKUP_MANIFEST_NAME)
                except KeyError as exc:
                    raise ArchiveError("Archive is missing BACKUP_MANIFEST.json") from exc
                extracted = tf.extractfile(member)
                if extracted is None:
                    raise ArchiveError("Archive manifest is not readable")
                with extracted:
                    return json.loads(extracted.read().decode("utf-8"))
        except (*CORRUPT_ARCHIVE_ERRORS, ValueError) as exc:
            raise ArchiveError(f"Archive manifest is corrupt or unreadable: {exc}") from exc

    raise ArchiveError(f"Unsupported archive type: {archive_path}")


def verify_archive(archive_path: Path, checksum_manifest_path: Path | None = None) -> dict[str, Any]:
    """Re-hash every payload member against the embedded manifest.

    Returns a result dict whose ``ok`` is False on any checksum mismatch, missing
    or unexpected member, unreadable (corrupt) member, or sidecar mismatch.
    """
    manifest = read_embedded_manifest(archive_path)
    expected = {item["path"]: item for item in manifest.get("files", [])}
    errors: list[str] = []
    checked = 0
    payload_paths: set[str] = set()

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or info.filename == BACKUP_MANIFEST_NAME:
                    continue
                rel_path = payload_rel(info.filename)
                payload_paths.add(rel_path)
                if rel_path not in expected:
                    errors.append(f"Unexpected payload file: {rel_path}")
                    continue
                try:
                    with zf.open(info, "r") as stream:
                        digest = sha256_readable(stream)
                except CORRUPT_ARCHIVE_ERRORS as exc:
                    errors.append(f"Corrupt archive member: {rel_path} ({exc})")
                    continue
                if digest != expected[rel_path]["sha256"]:
                    errors.append(f"Checksum mismatch: {rel_path}")
                checked += 1
    elif tarfile.is_tarfile(archive_path):
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                for member in tf.getmembers():
                    if member.name == BACKUP_MANIFEST_NAME:
                        continue
                    if member.isdir():
                        continue
                    if not member.isfile():
                        errors.append(f"Unsafe non-file archive member: {member.name}")
                        continue
                    rel_path = payload_rel(member.name)
                    payload_paths.add(rel_path)
                    if rel_path not in expected:
                        errors.append(f"Unexpected payload file: {rel_path}")
                        continue
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        errors.append(f"Unreadable archive member: {member.name}")
                        continue
                    with extracted:
                        digest = sha256_readable(extracted)
                    if digest != expected[rel_path]["sha256"]:
                        errors.append(f"Checksum mismatch: {rel_path}")
                    checked += 1
        except CORRUPT_ARCHIVE_ERRORS as exc:
            # A gzip stream is sequential: damage stops reading of all later members.
            errors.append(f"Archive is corrupt or unreadable: {exc}")
    else:
        raise ArchiveError(f"Unsupported archive type: {archive_path}")

    missing = set(expected) - payload_paths
    for rel_path in sorted(missing):
        errors.append(f"Missing payload file: {rel_path}")

    archive_hash = sha256_file(archive_path)
    if checksum_manifest_path:
        errors.extend(
            verify_checksum_sidecar(
                checksum_manifest_path=checksum_manifest_path,
                archive_name=archive_path.name,
                archive_hash=archive_hash,
                expected_files=expected,
            )
        )

    return {
        "ok": not errors,
        "archive": str(archive_path),
        "archive_sha256": archive_hash,
        "checked_files": checked,
        "manifest_file_count": len(expected),
        "errors": errors,
    }


def verify_checksum_sidecar(
    *,
    checksum_manifest_path: Path,
    archive_name: str,
    archive_hash: str,
    expected_files: dict[str, dict[str, Any]],
) -> list[str]:
    with checksum_manifest_path.open("r", encoding="utf-8") as f:
        sidecar = json.load(f)
    errors: list[str] = []
    if sidecar.get("schema_version") != CHECKSUM_SCHEMA_VERSION:
        errors.append("Checksum sidecar schema_version is invalid")
    if sidecar.get("archive_path") != archive_name:
        errors.append("Checksum sidecar archive_path does not match")
    if sidecar.get("archive_sha256") != archive_hash:
        errors.append("Checksum sidecar archive_sha256 does not match")
    sidecar_files = {item["path"]: item for item in sidecar.get("files", [])}
    if set(sidecar_files) != set(expected_files):
        errors.append("Checksum sidecar file set does not match manifest")
    for rel_path, expected in expected_files.items():
        sidecar_item = sidecar_files.get(rel_path)
        if not sidecar_item:
            continue
        if sidecar_item.get("sha256") != expected.get("sha256"):
            errors.append(f"Checksum sidecar mismatch: {rel_path}")
    return errors


def payload_rel(archive_name: str) -> str:
    name = archive_name.replace("\\", "/")
    if not name.startswith(PAYLOAD_PREFIX):
        raise ArchiveError(f"Archive member is outside payload prefix: {archive_name}")
    rel = name[len(PAYLOAD_PREFIX):]
    pure = PurePosixPath(rel)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ArchiveError(f"Unsafe archive payload path: {archive_name}")
    return pure.as_posix()


def sha256_readable(stream: BinaryIO) -> str:
    digest = hashlib.sha256()
    for chunk in iter(lambda: stream.read(HASH_CHUNK_SIZE), b""):
        digest.update(chunk)
    return digest.hexdigest()
