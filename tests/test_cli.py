from __future__ import annotations

import json
from pathlib import Path

import pytest

from helpers import MULTI_TARGET_RULES
from verified_backup.cli import main


def test_cli_backup_verify_restore_temp(tmp_path: Path, sample_tree: Path, capsys) -> None:
    out_dir = tmp_path / "out"
    assert main(
        [
            "backup",
            "--root",
            str(sample_tree),
            "--config",
            str(MULTI_TARGET_RULES),
            "--output-dir",
            str(out_dir),
            "--format",
            "zip",
            "--name",
            "cli-sample",
        ]
    ) == 0
    backup_result = json.loads(capsys.readouterr().out)
    archive = Path(backup_result["archive"])
    checksums = Path(backup_result["checksums"])
    assert archive.exists()
    assert checksums.exists()

    assert main(["verify", str(archive), "--checksums", str(checksums)]) == 0
    verify_result = json.loads(capsys.readouterr().out)
    assert verify_result["ok"] is True

    dry_dest = tmp_path / "dry"
    assert main(["restore", str(archive), "--dest", str(dry_dest)]) == 0
    dry_result = json.loads(capsys.readouterr().out)
    assert dry_result["mode"] == "dry-run"
    assert not dry_dest.exists()

    assert main(["restore-temp", str(archive), "--temp-root", str(tmp_path / "temp")]) == 0
    temp_result = json.loads(capsys.readouterr().out)
    assert temp_result["ok"] is True


def test_cli_default_rules_back_up_whole_root(tmp_path: Path, sample_tree: Path, capsys) -> None:
    assert main(["scan", "--root", str(sample_tree), "--output", str(tmp_path / "manifest.json"),
                 "--include-private-metadata"]) == 0
    capsys.readouterr()
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    included = {item["path"] for item in manifest["files"]}
    excluded = {item["path"]: item["reason"] for item in manifest["excluded"]}

    assert "docs/notes/README.md" in included
    assert "projects/dashboard/backend/model_weights.pt" in included  # no target filter by default
    assert excluded["docs/notes/.env"] == "secret_name"
    assert excluded["projects/dashboard/backend/credentials.json"] == "secret_name"
    assert excluded["projects/dashboard/backend/logs/backend-source.pid"] == "global_exclude"
    assert excluded["projects/dashboard/backend/.venv/site-packages/ignored.db"] == "global_exclude"


def test_cli_requires_explicit_root(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["backup"])
    assert excinfo.value.code == 2
    assert "--root" in capsys.readouterr().err


def test_cli_missing_root_is_a_clean_error(tmp_path: Path, capsys) -> None:
    assert main(["scan", "--root", str(tmp_path / "does-not-exist")]) == 2
    error = json.loads(capsys.readouterr().err)
    assert error["ok"] is False
    assert "does not exist" in error["error"]
