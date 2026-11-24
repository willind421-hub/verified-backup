"""A damaged backup must be rejected and an existing restore target left untouched."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import pytest

from helpers import (
    create_archive,
    flip_byte_in_last_payload,
    snapshot_tree,
    tamper_last_payload,
    truncate_archive,
)
from verified_backup.archive import ArchiveError
from verified_backup.cli import main
from verified_backup.restore import RestoreSafetyError, restore_archive, restore_to_temp
from verified_backup.verify import verify_archive


def _tampered(archive: Path, fmt: str, out: Path) -> None:
    tamper_last_payload(archive, fmt, out)


def _flipped(archive: Path, fmt: str, out: Path) -> None:
    flip_byte_in_last_payload(archive, fmt, out)


def _truncated(archive: Path, fmt: str, out: Path) -> None:
    truncate_archive(archive, out)


CORRUPTIONS: dict[str, Callable[[Path, str, Path], None]] = {
    "tampered": _tampered,
    "flipped": _flipped,
    "truncated": _truncated,
}
CASES = [(kind, fmt) for kind in CORRUPTIONS for fmt in ("zip", "tar")]


def make_corrupt_archive(tmp_path: Path, root: Path, rules: dict, kind: str, fmt: str) -> Path:
    archive, _checksums, _manifest = create_archive(
        tmp_path=tmp_path, root=root, rules=rules, archive_format=fmt
    )
    bad = tmp_path / f"corrupt-{kind}{'.zip' if fmt == 'zip' else '.tar.gz'}"
    CORRUPTIONS[kind](archive, fmt, bad)
    assert bad.read_bytes() != archive.read_bytes()
    return bad


def assert_rejected_by_verify(archive: Path) -> None:
    try:
        result = verify_archive(archive)
    except ArchiveError:
        return
    assert result["ok"] is False
    assert result["errors"]


@pytest.mark.parametrize(("kind", "fmt"), CASES)
def test_verify_rejects_corrupt_archive(
    tmp_path: Path, sample_tree: Path, multi_target_rules: dict, kind: str, fmt: str
) -> None:
    bad = make_corrupt_archive(tmp_path, sample_tree, multi_target_rules, kind, fmt)
    assert_rejected_by_verify(bad)


@pytest.mark.parametrize("fmt", ["zip", "tar"])
def test_verify_reports_checksum_mismatch_for_tampered_payload(
    tmp_path: Path, sample_tree: Path, multi_target_rules: dict, fmt: str
) -> None:
    archive, _c, _m = create_archive(
        tmp_path=tmp_path, root=sample_tree, rules=multi_target_rules, archive_format=fmt
    )
    bad = tmp_path / ("bad.zip" if fmt == "zip" else "bad.tar.gz")
    victim = tamper_last_payload(archive, fmt, bad)
    result = verify_archive(bad)
    assert result["ok"] is False
    assert f"Checksum mismatch: {victim}" in result["errors"]


@pytest.mark.parametrize("verify_first", [False, True])
@pytest.mark.parametrize(("kind", "fmt"), CASES)
def test_restore_rejects_corrupt_archive_and_preserves_existing_target(
    tmp_path: Path,
    sample_tree: Path,
    multi_target_rules: dict,
    kind: str,
    fmt: str,
    verify_first: bool,
) -> None:
    bad = make_corrupt_archive(tmp_path, sample_tree, multi_target_rules, kind, fmt)
    dest = tmp_path / "existing-target"
    (dest / "projects").mkdir(parents=True)
    (dest / "keep.txt").write_text("keep me\n", encoding="utf-8")
    (dest / "projects" / "notes.md").write_text("existing notes\n", encoding="utf-8")
    before = snapshot_tree(dest)

    with pytest.raises((RestoreSafetyError, ArchiveError)):
        restore_archive(archive_path=bad, dest=dest, execute=True, verify_first=verify_first)

    assert snapshot_tree(dest) == before


@pytest.mark.parametrize(("kind", "fmt"), CASES)
def test_restore_into_new_folder_leaves_nothing_behind(
    tmp_path: Path, sample_tree: Path, multi_target_rules: dict, kind: str, fmt: str
) -> None:
    bad = make_corrupt_archive(tmp_path, sample_tree, multi_target_rules, kind, fmt)
    dest = tmp_path / "new-target"

    with pytest.raises((RestoreSafetyError, ArchiveError)):
        restore_archive(archive_path=bad, dest=dest, execute=True)

    assert not dest.exists()


@pytest.mark.parametrize("fmt", ["zip", "tar"])
def test_restore_to_temp_rejects_corrupt_archive_without_leftovers(
    tmp_path: Path, sample_tree: Path, multi_target_rules: dict, fmt: str
) -> None:
    bad = make_corrupt_archive(tmp_path, sample_tree, multi_target_rules, "tampered", fmt)
    temp_root = tmp_path / "temp-root"

    with pytest.raises((RestoreSafetyError, ArchiveError)):
        restore_to_temp(archive_path=bad, temp_root=temp_root)

    assert list(temp_root.iterdir()) == []


@pytest.mark.parametrize(("kind", "fmt"), CASES)
def test_cli_rejects_corrupt_archive_without_traceback(
    tmp_path: Path, sample_tree: Path, multi_target_rules: dict, kind: str, fmt: str, capsys
) -> None:
    bad = make_corrupt_archive(tmp_path, sample_tree, multi_target_rules, kind, fmt)
    dest = tmp_path / "cli-target"
    dest.mkdir()
    (dest / "keep.txt").write_text("keep me\n", encoding="utf-8")
    before = snapshot_tree(dest)

    assert main(["verify", str(bad)]) in (1, 2)
    captured = capsys.readouterr()
    assert json.loads(captured.out or captured.err)["ok"] is False

    assert main(["restore", str(bad), "--dest", str(dest), "--execute"]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["ok"] is False
    assert snapshot_tree(dest) == before
