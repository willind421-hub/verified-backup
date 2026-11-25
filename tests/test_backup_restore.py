from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from helpers import create_archive
from verified_backup.restore import RestoreSafetyError, restore_archive, restore_to_temp
from verified_backup.scanner import build_backup_manifest, scan_source
from verified_backup.verify import verify_archive


def test_scan_includes_targets_and_excludes_secrets(sample_tree: Path, multi_target_rules: dict) -> None:
    rules = multi_target_rules
    scan = scan_source(sample_tree.resolve(), rules)
    manifest = build_backup_manifest(scan, rules, include_private_metadata=True)
    included = {item["path"] for item in manifest["files"]}
    excluded = {item["path"]: item["reason"] for item in manifest["excluded"]}

    assert "docs/notes/README.md" in included
    assert "projects/notes-app/data/memory.db" in included
    assert "projects/feed-reader/data/feed_store.db" in included
    assert "projects/task-runner/data/task_store.db" in included
    assert "projects/sync-service/data/sync.db" in included
    assert "projects/model-builder/artifacts/art_001/model.glb" in included
    assert "projects/chat-server/app.db" in included
    assert "projects/chat-server/app.db-wal" in included
    assert "projects/chat-server/app.db-shm" in included
    assert "projects/dashboard/backend/memos.db" in included
    assert "projects/dashboard/backend/backend-start.out.log" in included
    assert "projects/dashboard/backend/logs/server.log" in included

    assert "projects/chat-server/.env" not in included
    assert "projects/chat-server/calendar_token.json" not in included
    assert "projects/notes-app/data/token.json" not in included
    assert excluded["projects/notes-app/data/token.json"] == "secret_name"
    assert "projects/dashboard/backend/credentials.json" not in included
    assert "projects/dashboard/backend/.tokens.json" not in included
    assert "projects/dashboard/backend/calendar_token.json" not in included
    assert "projects/dashboard/backend/client.session" not in included
    assert "projects/sync-service/data/compile_cache/cache.bin" not in included
    assert "projects/sync-service/data/test_dbs/test.db" not in included
    assert "projects/dashboard/backend/model_weights.pt" not in included


@pytest.mark.parametrize("archive_format", ["zip", "tar"])
def test_backup_verify_and_restore_temp(
    tmp_path: Path,
    sample_tree: Path,
    multi_target_rules: dict,
    archive_format: str,
) -> None:
    archive_path, checksum_path, manifest = create_archive(
        tmp_path=tmp_path,
        root=sample_tree,
        rules=multi_target_rules,
        archive_format=archive_format,
    )

    verification = verify_archive(archive_path, checksum_path)
    assert verification["ok"] is True
    assert verification["checked_files"] == manifest["summary"]["file_count"]

    dry_dest = tmp_path / "dry-run-dest"
    dry_run = restore_archive(archive_path=archive_path, dest=dry_dest, execute=False)
    assert dry_run["mode"] == "dry-run"
    assert dry_run["would_create_count"] == manifest["summary"]["file_count"]
    assert not dry_dest.exists()

    temp_result = restore_to_temp(archive_path=archive_path, temp_root=tmp_path / "restore-temp")
    assert temp_result["ok"] is True
    assert temp_result["verification"]["checked_files"] == manifest["summary"]["file_count"]
    restored_root = Path(temp_result["temp_destination"])
    assert (restored_root / "projects/dashboard/backend/memos.db").exists()
    assert (restored_root / "projects/chat-server/app.db").exists()
    assert not (restored_root / "projects/dashboard/backend/credentials.json").exists()
    assert not (restored_root / "projects/chat-server/calendar_token.json").exists()


def test_restored_sqlite_db_keeps_expected_counts(
    tmp_path: Path,
    sample_tree: Path,
    multi_target_rules: dict,
) -> None:
    archive_path, _checksum_path, _manifest = create_archive(
        tmp_path=tmp_path,
        root=sample_tree,
        rules=multi_target_rules,
        archive_format="zip",
    )

    temp_result = restore_to_temp(archive_path=archive_path, temp_root=tmp_path / "restore-temp")
    restored_root = Path(temp_result["temp_destination"])
    restored_db = restored_root / "projects/chat-server/app.db"

    con = sqlite3.connect(restored_db)
    try:
        interactions = con.execute("select count(*) from interactions").fetchone()[0]
        messages = con.execute("select count(*) from messages").fetchone()[0]
    finally:
        con.close()

    assert interactions == 3
    assert messages == 2


def test_restore_never_overwrites_existing_file(
    tmp_path: Path,
    sample_tree: Path,
    multi_target_rules: dict,
) -> None:
    archive_path, _checksum_path, _manifest = create_archive(
        tmp_path=tmp_path,
        root=sample_tree,
        rules=multi_target_rules,
        archive_format="zip",
    )
    dest = tmp_path / "restore"
    conflict = dest / "docs/notes/README.md"
    conflict.parent.mkdir(parents=True, exist_ok=True)
    conflict.write_text("existing\n", encoding="utf-8")

    dry_run = restore_archive(archive_path=archive_path, dest=dest, execute=False)
    assert dry_run["ok"] is False
    assert dry_run["conflict_count"] == 1

    with pytest.raises(RestoreSafetyError):
        restore_archive(archive_path=archive_path, dest=dest, execute=True)
    assert conflict.read_text(encoding="utf-8") == "existing\n"


def test_checksum_sidecar_detects_tampering(
    tmp_path: Path,
    sample_tree: Path,
    multi_target_rules: dict,
) -> None:
    archive_path, checksum_path, _manifest = create_archive(
        tmp_path=tmp_path,
        root=sample_tree,
        rules=multi_target_rules,
        archive_format="zip",
    )
    data = json.loads(checksum_path.read_text(encoding="utf-8"))
    data["archive_sha256"] = "0" * 64
    checksum_path.write_text(json.dumps(data), encoding="utf-8")

    verification = verify_archive(archive_path, checksum_path)
    assert verification["ok"] is False
    assert any("archive_sha256" in error for error in verification["errors"])


def test_restore_refuses_source_root(
    tmp_path: Path,
    sample_tree: Path,
    multi_target_rules: dict,
) -> None:
    archive_path, _checksum_path, _manifest = create_archive(
        tmp_path=tmp_path,
        root=sample_tree,
        rules=multi_target_rules,
        archive_format="zip",
    )
    with pytest.raises(RestoreSafetyError, match="source root"):
        restore_archive(archive_path=archive_path, dest=sample_tree, execute=True)


def test_restore_execute_into_new_folder_verifies_tree(
    tmp_path: Path,
    sample_tree: Path,
    multi_target_rules: dict,
) -> None:
    archive_path, _checksum_path, manifest = create_archive(
        tmp_path=tmp_path,
        root=sample_tree,
        rules=multi_target_rules,
        archive_format="tar",
    )
    dest = tmp_path / "new-restore"
    result = restore_archive(archive_path=archive_path, dest=dest, execute=True, verify_first=True)
    assert result["ok"] is True
    assert result["restored_files"] == manifest["summary"]["file_count"]
    assert result["verification"]["errors"] == []
    for item in manifest["files"]:
        assert (dest / item["path"]).read_bytes() == (sample_tree / item["path"]).read_bytes()
