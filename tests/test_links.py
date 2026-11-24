"""Symlinks and Windows junctions are classified before any path is resolved."""

from __future__ import annotations

import json
import os
import zipfile
from pathlib import Path

import pytest

from helpers import make_dir_link, make_file_symlink, make_junction
from verified_backup.cli import main
from verified_backup.paths import first_link_component, is_link
from verified_backup.scanner import scan_source

OUTSIDE_TEXT = "outside the source root\n"


def rules_for(path: str, *, skip_symlinks: bool = True) -> dict:
    return {
        "schema_version": "verified-backup-rules/v1",
        "targets": [{"name": "target", "path": path, "include": ["**/*"], "exclude": []}],
        "exclude": {"skip_symlinks": skip_symlinks, "path_patterns": [], "secret_name_patterns": []},
    }


@pytest.fixture
def layout(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    (root / "data").mkdir(parents=True)
    (root / "data" / "a.txt").write_text("inside\n", encoding="utf-8")
    outside.mkdir()
    (outside / "private.txt").write_text(OUTSIDE_TEXT, encoding="utf-8")
    return root.resolve(), outside.resolve()


def test_linked_directory_to_outside_is_not_followed(layout: tuple[Path, Path]) -> None:
    root, outside = layout
    make_dir_link(root / "data" / "linked", outside)

    scan = scan_source(root, rules_for("data"))

    assert [f.rel_path for f in scan.files] == ["data/a.txt"]
    # Whether glob enumerates files behind the link depends on platform/link type
    # (Windows junctions are traversed); anything it does enumerate must be excluded.
    assert all(e.reason == "symlink" for e in scan.excluded)


def test_target_base_that_is_a_link_is_excluded(layout: tuple[Path, Path]) -> None:
    root, outside = layout
    make_dir_link(root / "data" / "linked", outside)

    scan = scan_source(root, rules_for("data/linked"))

    assert scan.files == ()
    assert [(e.rel_path, e.reason) for e in scan.excluded] == [("data/linked/private.txt", "symlink")]


def test_link_to_outside_is_rejected_even_when_following_links(layout: tuple[Path, Path]) -> None:
    root, outside = layout
    make_dir_link(root / "data" / "linked", outside)

    scan = scan_source(root, rules_for("data/linked", skip_symlinks=False))

    assert scan.files == ()
    assert [(e.rel_path, e.reason) for e in scan.excluded] == [("data/linked/private.txt", "outside_root")]


def test_link_inside_root_is_followed_only_when_allowed(layout: tuple[Path, Path]) -> None:
    root, _outside = layout
    (root / "real").mkdir()
    (root / "real" / "x.txt").write_text("x\n", encoding="utf-8")
    make_dir_link(root / "data" / "alias", root / "real")

    skipped = scan_source(root, rules_for("data/alias"))
    assert skipped.files == ()
    assert [(e.rel_path, e.reason) for e in skipped.excluded] == [("data/alias/x.txt", "symlink")]

    followed = scan_source(root, rules_for("data/alias", skip_symlinks=False))
    # Followed links are recorded under their real location, as before.
    assert [f.rel_path for f in followed.files] == ["real/x.txt"]


def test_file_symlink_to_outside_is_excluded(layout: tuple[Path, Path]) -> None:
    root, outside = layout
    make_file_symlink(root / "data" / "link.txt", outside / "private.txt")

    scan = scan_source(root, rules_for("data"))
    assert [f.rel_path for f in scan.files] == ["data/a.txt"]
    assert [(e.rel_path, e.reason) for e in scan.excluded] == [("data/link.txt", "symlink")]

    scan = scan_source(root, rules_for("data", skip_symlinks=False))
    assert [f.rel_path for f in scan.files] == ["data/a.txt"]
    assert [(e.rel_path, e.reason) for e in scan.excluded] == [("data/link.txt", "outside_root")]


def test_backup_with_outside_link_contains_no_outside_bytes(
    layout: tuple[Path, Path], tmp_path: Path, capsys
) -> None:
    root, outside = layout
    make_dir_link(root / "data" / "linked", outside)
    out_dir = tmp_path / "out"

    assert main(["backup", "--root", str(root), "--output-dir", str(out_dir), "--name", "b"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["file_count"] == 1

    with zipfile.ZipFile(result["archive"]) as zf:
        names = zf.namelist()
        payloads = [zf.read(n) for n in names if n.startswith("payload/")]
    assert names == ["payload/data/a.txt", "BACKUP_MANIFEST.json"]
    assert all(OUTSIDE_TEXT.encode() not in p for p in payloads)


@pytest.mark.skipif(os.name != "nt", reason="junctions exist only on Windows")
def test_junction_is_detected_as_link(layout: tuple[Path, Path]) -> None:
    root, outside = layout
    junction = root / "data" / "junction"
    make_junction(junction, outside)

    assert junction.is_symlink() is False  # why Path.is_symlink() alone is not enough
    assert is_link(junction) is True
    assert first_link_component(junction / "private.txt", root) == junction
    assert first_link_component(root / "data" / "a.txt", root) is None

    scan = scan_source(root, rules_for("data"))
    assert [f.rel_path for f in scan.files] == ["data/a.txt"]
    assert [(e.rel_path, e.reason) for e in scan.excluded] == [("data/junction/private.txt", "symlink")]
