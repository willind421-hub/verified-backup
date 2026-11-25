"""Embedded manifest loading, payload checksum verification and sidecar validation."""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path
from typing import Any, BinaryIO

from .archive import (
    BACKUP_MANIFEST_NAME,
    CHECKSUM_SCHEMA_VERSION,
    CORRUPT_ARCHIVE_ERRORS,
    PAYLOAD_PREFIX,
    ArchiveError,
)
from .scanner import HASH_CHUNK_SIZE, sha256_file
from .paths import validate_file_path


def read_embedded_manifest(archive_path: Path) -> dict[str, Any]:
    """Return the ``BACKUP_MANIFEST.json`` stored inside the archive.

    Raises ArchiveError if the archive type is unsupported, the manifest is
    missing, or the archive is too damaged to read it.
    """
    if zipfile.is_zipfile(archive_path):
        try:
            with zipfile.ZipFile(archive_path, "r") as zf:
                names = [info.filename for info in zf.infolist()]
                if any(info.is_dir() for info in zf.infolist()):
                    raise ArchiveError("Only regular file archive members are supported")
                try:
                    with zf.open(BACKUP_MANIFEST_NAME, "r") as f:
                        manifest = validate_manifest(json.loads(f.read().decode("utf-8")))
                    validate_inventory(names, manifest)
                    return manifest
                except KeyError as exc:
                    raise ArchiveError("Archive is missing BACKUP_MANIFEST.json") from exc
        except (*CORRUPT_ARCHIVE_ERRORS, ValueError) as exc:
            raise ArchiveError(f"Archive manifest is corrupt or unreadable: {exc}") from exc

    if tarfile.is_tarfile(archive_path):
        try:
            with tarfile.open(archive_path, "r:*") as tf:
                members = tf.getmembers()
                if any(not member.isfile() for member in members):
                    raise ArchiveError("Only regular file archive members are supported")
                try:
                    member = tf.getmember(BACKUP_MANIFEST_NAME)
                except KeyError as exc:
                    raise ArchiveError("Archive is missing BACKUP_MANIFEST.json") from exc
                extracted = tf.extractfile(member)
                if extracted is None:
                    raise ArchiveError("Archive manifest is not readable")
                with extracted:
                    manifest = validate_manifest(json.loads(extracted.read().decode("utf-8")))
                validate_inventory([member.name for member in members], manifest)
                return manifest
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
                        digest, size = _hash_and_size(stream)
                except CORRUPT_ARCHIVE_ERRORS as exc:
                    errors.append(f"Corrupt archive member: {rel_path} ({exc})")
                    continue
                if digest != expected[rel_path]["sha256"]:
                    errors.append(f"Checksum mismatch: {rel_path}")
                if size != expected[rel_path]["size"]:
                    errors.append(f"Size mismatch: {rel_path}")
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
                        digest, size = _hash_and_size(extracted)
                    if digest != expected[rel_path]["sha256"]:
                        errors.append(f"Checksum mismatch: {rel_path}")
                    if size != expected[rel_path]["size"]:
                        errors.append(f"Size mismatch: {rel_path}")
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
        if sidecar_item.get("size") != expected.get("size"):
            errors.append(f"Checksum sidecar size mismatch: {rel_path}")
    return errors


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "verified-backup-manifest/v1":
        raise ArchiveError("Invalid manifest schema_version or object")
    if not isinstance(manifest.get("files"), list):
        raise ArchiveError("Manifest files must be a list")
    paths: set[str] = set()
    for item in manifest["files"]:
        if not isinstance(item, dict):
            raise ArchiveError("Manifest file entry must be an object")
        path = item.get("path")
        if not isinstance(path, str):
            raise ArchiveError("Manifest file path must be a string")
        try:
            validate_file_path(path)
        except ValueError as exc:
            raise ArchiveError(str(exc)) from exc
        if type(item.get("size")) is not int or item["size"] < 0:
            raise ArchiveError("Manifest file size must be a nonnegative integer")
        if not isinstance(item.get("sha256"), str) or not re.fullmatch("[0-9a-f]{64}", item["sha256"]):
            raise ArchiveError("Manifest file sha256 must be 64 lowercase hex characters")
        folded = item["path"].casefold()
        if folded in paths:
            raise ArchiveError("Duplicate or case-colliding manifest path")
        paths.add(folded)
    for path in paths:
        parts = path.split("/")
        if any("/".join(parts[:index]) in paths for index in range(1, len(parts))):
            raise ArchiveError("Manifest file path is also a parent directory")
    return manifest


def validate_inventory(names: list[str], manifest: dict[str, Any]) -> None:
    """Check the same complete member inventory before verify or restore writes."""
    if names.count(BACKUP_MANIFEST_NAME) != 1:
        raise ArchiveError("Archive must contain exactly one BACKUP_MANIFEST.json")
    payloads = [payload_rel(name) for name in names if name != BACKUP_MANIFEST_NAME]
    if len(payloads) != len(set(payloads)):
        raise ArchiveError("Duplicate archive payload path")
    if set(payloads) != {item["path"] for item in manifest["files"]}:
        raise ArchiveError("Archive payload file set does not match manifest")


def payload_rel(archive_name: str) -> str:
    if not archive_name.startswith(PAYLOAD_PREFIX):
        raise ArchiveError(f"Archive member is outside payload prefix: {archive_name}")
    try:
        return validate_file_path(archive_name[len(PAYLOAD_PREFIX):])
    except ValueError as exc:
        raise ArchiveError(f"Unsafe archive payload path: {archive_name!r}") from exc


def sha256_readable(stream: BinaryIO) -> str:
    return _hash_and_size(stream)[0]


def _hash_and_size(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: stream.read(HASH_CHUNK_SIZE), b""):
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size
