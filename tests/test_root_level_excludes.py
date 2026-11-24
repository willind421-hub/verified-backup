"""Exclusion patterns must also apply directly under the source root.

``**/`` stands for "any number of directories, including none". A pattern such as
``**/.git/**`` therefore has to exclude ``.git/config`` at the top of the source
root, not only ``sub/.git/config``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from verified_backup.config import load_rules
from verified_backup.scanner import matches_path, scan_source

# One file for every kind of entry the packaged default rules promise to leave out.
NOISE = [
    ".git/config",
    ".hg/store",
    ".svn/entries",
    "__pycache__/mod.pyc",
    ".pytest_cache/v/cache",
    "node_modules/pkg/index.js",
    ".venv/lib/site.py",
    ".venv-tools/site.py",
    "venv/lib/site.py",
    ".mypy_cache/x.json",
    ".ruff_cache/x",
    "scratch.tmp",
    "scratch.temp",
    "data.cache",
    "server.pid",
    "state.lock",
]


def _write(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x\n", encoding="utf-8")


@pytest.mark.parametrize(
    ("pattern", "rel_path"),
    [
        ("**/.git/**", ".git/config"),
        ("**/__pycache__/**", "__pycache__/pkg/mod.pyc"),
        ("**/*.tmp", "scratch.tmp"),
        ("**/~$*", "~$report.docx"),
        ("docs/**/draft.md", "docs/draft.md"),
    ],
)
def test_double_star_slash_also_matches_no_directory(pattern: str, rel_path: str) -> None:
    assert matches_path(pattern, rel_path)


@pytest.mark.parametrize(
    ("pattern", "rel_path"),
    [
        ("**/.git/**", "x.git/config"),
        ("**/.git/**", ".gitignore"),
        ("**/build/**", "mybuild/out.py"),
        ("**/*.tmp", "scratch.tmp.md"),
        ("docs/**/draft.md", "other/draft.md"),
    ],
)
def test_double_star_slash_does_not_match_similar_names(pattern: str, rel_path: str) -> None:
    assert not matches_path(pattern, rel_path)


@pytest.mark.parametrize("prefix", ["", "nested/", "a/b/"])
def test_default_rules_exclude_noise_at_any_depth(tmp_path: Path, prefix: str) -> None:
    root = tmp_path / "source"
    for rel in NOISE:
        _write(root / prefix / rel)
    _write(root / prefix / "keep.txt")
    _write(root / prefix / ".gitignore")

    scan = scan_source(root.resolve(), load_rules())

    assert [f.rel_path for f in scan.files] == [f"{prefix}.gitignore", f"{prefix}keep.txt"]
    reasons = {item.rel_path: item.reason for item in scan.excluded}
    assert reasons == {f"{prefix}{rel}": "global_exclude" for rel in NOISE}
