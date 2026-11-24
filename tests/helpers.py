"""Shared helpers for tests (archive creation, tampering, link creation)."""

from __future__ import annotations

import gzip
import io
import os
import subprocess
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from verified_backup.archive import make_archive_name, write_archive, write_sidecar_manifests
from verified_backup.scanner import build_backup_manifest, scan_source

MULTI_TARGET_RULES = Path(__file__).parent / "data" / "multi_target_rules.json"


def create_archive(
    *,
    tmp_path: Path,
    root: Path,
    rules: dict[str, Any],
    archive_format: str,
    name: str | None = None,
) -> tuple[Path, Path, dict]:
    scan = scan_source(root.resolve(), rules)
    manifest = build_backup_manifest(scan, rules, archive_format=archive_format)
    archive_path = tmp_path / make_archive_name(name or f"test-backup-{archive_format}", archive_format)
    final_manifest = write_archive(
        archive_path=archive_path,
        archive_format=archive_format,
        manifest=manifest,
        files=scan.files,
    )
    _manifest_path, checksum_path = write_sidecar_manifests(
        archive_path=archive_path,
        manifest=final_manifest,
    )
    return archive_path, checksum_path, final_manifest


def tamper_last_payload(archive: Path, archive_format: str, out: Path) -> str:
    """Copy ``archive`` to ``out`` with the last payload member's bytes changed.

    The container stays structurally valid (fresh CRCs), and the embedded manifest
    is kept, so only hash verification can notice. Returns the tampered rel path.
    """
    if archive_format == "zip":
        with zipfile.ZipFile(archive) as src, zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
            payload = [i.filename for i in src.infolist() if i.filename.startswith("payload/")]
            victim = payload[-1]
            for info in src.infolist():
                data = src.read(info.filename)
                if info.filename == victim:
                    data = data + b"tampered"
                dst.writestr(info, data)
    else:
        with tarfile.open(archive, "r:gz") as src, tarfile.open(out, "w:gz") as dst:
            members = src.getmembers()
            payload = [m.name for m in members if m.name.startswith("payload/")]
            victim = payload[-1]
            for member in members:
                extracted = src.extractfile(member)
                assert extracted is not None
                data = extracted.read()
                if member.name == victim:
                    data = data + b"tampered"
                info = tarfile.TarInfo(member.name)
                info.size = len(data)
                info.mtime = member.mtime
                dst.addfile(info, io.BytesIO(data))
    return victim[len("payload/"):]


def flip_byte_in_last_payload(archive: Path, archive_format: str, out: Path) -> None:
    """Copy ``archive`` to ``out`` with one byte flipped inside the last payload member.

    zip: the byte is flipped in the compressed member data on disk (container-level
    damage, caught by zlib/CRC checks). tar.gz: the byte is flipped in the member's
    data inside the decompressed tar stream and re-gzipped, so only the SHA-256
    comparison can notice.
    """
    if archive_format == "zip":
        with zipfile.ZipFile(archive) as zf:
            payload = [i for i in zf.infolist() if i.filename.startswith("payload/")]
            info = payload[-1]
        raw = bytearray(archive.read_bytes())
        # Local file header: 30 fixed bytes + file name + extra field, then data.
        name_len = int.from_bytes(raw[info.header_offset + 26:info.header_offset + 28], "little")
        extra_len = int.from_bytes(raw[info.header_offset + 28:info.header_offset + 30], "little")
        data_start = info.header_offset + 30 + name_len + extra_len
        raw[data_start + info.compress_size // 2] ^= 0xFF
        out.write_bytes(bytes(raw))
    else:
        tar_bytes = bytearray(gzip.decompress(archive.read_bytes()))
        with tarfile.open(fileobj=io.BytesIO(bytes(tar_bytes)), mode="r:") as tf:
            payload = [m for m in tf.getmembers() if m.name.startswith("payload/")]
            member = payload[-1]
        tar_bytes[member.offset_data + member.size // 2] ^= 0xFF
        out.write_bytes(gzip.compress(bytes(tar_bytes)))


def truncate_archive(archive: Path, out: Path, keep_fraction: float = 0.6) -> None:
    raw = archive.read_bytes()
    out.write_bytes(raw[: int(len(raw) * keep_fraction)])


def snapshot_tree(root: Path) -> dict[str, Any]:
    """Return {relpath: bytes-or-'<dir>'} for everything under ``root``."""
    state: dict[str, Any] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        state[rel] = "<dir>" if path.is_dir() else path.read_bytes()
    return state


def make_dir_link(link: Path, target: Path) -> str:
    """Create a directory link: a symlink if allowed, otherwise a Windows junction.

    Returns "symlink" or "junction"; skips the test if neither can be created.
    """
    try:
        os.symlink(target, link, target_is_directory=True)
        return "symlink"
    except (OSError, NotImplementedError):
        pass
    if os.name == "nt":
        make_junction(link, target)
        return "junction"
    pytest.skip("cannot create directory symlinks on this system")


def make_junction(link: Path, target: Path) -> None:
    if os.name != "nt":
        pytest.skip("junctions exist only on Windows")
    try:
        import _winapi

        _winapi.CreateJunction(str(target), str(link))
    except (ImportError, AttributeError, OSError):
        result = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            pytest.skip(f"cannot create junction: {result.stderr.strip()}")


def make_file_symlink(link: Path, target: Path) -> None:
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create file symlinks on this system: {exc}")
