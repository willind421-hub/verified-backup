"""Dry-run planning, no-overwrite restore, rollback on failure and temp restore verification."""

from __future__ import annotations

import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, BinaryIO, Iterator

from .archive import CORRUPT_ARCHIVE_ERRORS, ArchiveError
from .paths import safe_join
from .scanner import sha256_file
from .verify import payload_rel, read_embedded_manifest, sha256_readable, verify_archive


class RestoreSafetyError(RuntimeError):
    """Raised when restore would violate no-overwrite or path safety rules."""


def restore_archive(
    *,
    archive_path: Path,
    dest: Path,
    execute: bool = False,
    verify_first: bool = False,
) -> dict[str, Any]:
    """Restore ``archive_path`` into ``dest``; a dry run unless ``execute`` is True.

    Existing files are never overwritten. If the restore fails part-way (corrupt
    archive, checksum mismatch, I/O error), every file and directory created by
    this call is removed again, so the destination is left as it was.
    """
    manifest = read_embedded_manifest(archive_path)
    dest = dest.expanduser().resolve()

    if verify_first:
        verification = verify_archive(archive_path)
        if not verification["ok"]:
            raise RestoreSafetyError("Archive verification failed before restore")

    source_root = manifest.get("source_root")
    if execute and source_root and dest == Path(source_root).resolve():
        raise RestoreSafetyError("Refusing to restore directly over the source root")

    planned = plan_restore(manifest, dest)
    if not execute:
        return {
            "ok": not planned["conflicts"],
            "mode": "dry-run",
            "destination": str(dest),
            **planned,
        }
    if planned["conflicts"]:
        raise RestoreSafetyError("Refusing to overwrite existing files")

    created_files: list[Path] = []
    created_dirs: list[Path] = []
    restored = 0
    expected_by_path = {item["path"]: item for item in manifest.get("files", [])}
    try:
        _make_dirs(dest, created_dirs)
        for rel_path, stream in iter_payload_streams(archive_path):
            if rel_path not in expected_by_path:
                raise RestoreSafetyError(f"Unexpected payload file during restore: {rel_path}")
            out_path = safe_join(dest, rel_path)
            _make_dirs(out_path.parent, created_dirs)
            expected_sha = expected_by_path[rel_path]["sha256"]
            with stream:
                digest = write_new_file_with_hash(stream, out_path)
            created_files.append(out_path)
            if digest != expected_sha:
                raise ArchiveError(f"Restored checksum mismatch: {rel_path}")
            restored += 1
    except CORRUPT_ARCHIVE_ERRORS as exc:
        _rollback(created_files, created_dirs)
        raise ArchiveError(f"Archive is corrupt or unreadable: {exc}") from exc
    except BaseException:
        _rollback(created_files, created_dirs)
        raise

    verification = verify_restored_tree(manifest, dest)
    return {
        "ok": verification["ok"],
        "mode": "execute",
        "destination": str(dest),
        "restored_files": restored,
        "verification": verification,
    }


def plan_restore(manifest: dict[str, Any], dest: Path) -> dict[str, Any]:
    files = manifest.get("files", [])
    conflicts: list[str] = []
    would_create: list[str] = []
    for item in files:
        rel_path = item["path"]
        out_path = safe_join(dest, rel_path)
        if out_path.exists():
            conflicts.append(rel_path)
        else:
            would_create.append(rel_path)
    return {
        "would_create_count": len(would_create),
        "conflict_count": len(conflicts),
        "conflicts": conflicts,
    }


def restore_to_temp(
    *,
    archive_path: Path,
    temp_root: Path | None = None,
    verify_first: bool = True,
) -> dict[str, Any]:
    """Restore into a fresh ``tempfile.mkdtemp`` directory and verify the result."""
    temp_parent = None
    if temp_root:
        temp_root.mkdir(parents=True, exist_ok=True)
        temp_parent = str(temp_root.resolve())
    dest = Path(tempfile.mkdtemp(prefix="verified-restore-", dir=temp_parent)).resolve()
    try:
        result = restore_archive(
            archive_path=archive_path,
            dest=dest,
            execute=True,
            verify_first=verify_first,
        )
    except BaseException:
        # restore_archive already removed what it wrote; drop the empty temp dir too.
        try:
            dest.rmdir()
        except OSError:
            pass
        raise
    result["mode"] = "restore-temp"
    result["temp_destination"] = str(dest)
    return result


def verify_restored_tree(manifest: dict[str, Any], dest: Path) -> dict[str, Any]:
    errors: list[str] = []
    checked = 0
    for item in manifest.get("files", []):
        rel_path = item["path"]
        out_path = safe_join(dest, rel_path)
        if not out_path.exists():
            errors.append(f"Missing restored file: {rel_path}")
            continue
        if not out_path.is_file():
            errors.append(f"Restored path is not a file: {rel_path}")
            continue
        if out_path.stat().st_size != item["size"]:
            errors.append(f"Restored size mismatch: {rel_path}")
            continue
        digest = sha256_file(out_path)
        if digest != item["sha256"]:
            errors.append(f"Restored checksum mismatch: {rel_path}")
            continue
        checked += 1
    return {
        "ok": not errors,
        "checked_files": checked,
        "errors": errors,
    }


def iter_payload_streams(archive_path: Path) -> Iterator[tuple[str, BinaryIO]]:
    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.startswith("payload/"):
                    continue
                rel_path = payload_rel(info.filename)
                with zf.open(info, "r") as stream:
                    yield rel_path, _BufferedPayload(stream.read())
        return

    if tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, "r:*") as tf:
            for member in tf.getmembers():
                if member.isdir() or not member.name.startswith("payload/"):
                    continue
                if not member.isfile():
                    raise RestoreSafetyError(f"Unsafe non-file archive member: {member.name}")
                rel_path = payload_rel(member.name)
                extracted = tf.extractfile(member)
                if extracted is None:
                    raise ArchiveError(f"Unreadable archive member: {member.name}")
                with extracted:
                    yield rel_path, _BufferedPayload(extracted.read())
        return

    raise ArchiveError(f"Unsupported archive type: {archive_path}")


def write_new_file_with_hash(stream: BinaryIO, out_path: Path) -> str:
    if out_path.exists():
        raise RestoreSafetyError(f"Refusing to overwrite existing file: {out_path}")
    with out_path.open("xb") as f:
        try:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
        except BaseException:
            # The file was created exclusively above, so removing it is safe.
            f.close()
            out_path.unlink()
            raise
    with out_path.open("rb") as f:
        return sha256_readable(f)


def _make_dirs(path: Path, created: list[Path]) -> None:
    """Create ``path`` and missing parents, recording each directory this call created."""
    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    for directory in reversed(missing):
        try:
            directory.mkdir()
        except FileExistsError:
            continue
        created.append(directory)


def _rollback(created_files: list[Path], created_dirs: list[Path]) -> None:
    """Remove files and (empty) directories created by a failed restore."""
    for path in reversed(created_files):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
    for directory in reversed(created_dirs):
        try:
            directory.rmdir()
        except OSError:
            # Not empty: something else wrote here; leave it alone.
            pass


class _BufferedPayload:
    def __init__(self, payload: bytes) -> None:
        self._payload = payload
        self._offset = 0

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = len(self._payload) - self._offset
        start = self._offset
        end = min(len(self._payload), self._offset + size)
        self._offset = end
        return self._payload[start:end]

    def __enter__(self) -> "_BufferedPayload":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None
