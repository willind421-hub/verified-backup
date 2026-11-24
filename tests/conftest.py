from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from helpers import MULTI_TARGET_RULES
from verified_backup.config import load_rules


@pytest.fixture
def multi_target_rules() -> dict[str, Any]:
    return load_rules(MULTI_TARGET_RULES)


@pytest.fixture
def sample_tree(tmp_path: Path) -> Path:
    """A synthetic source tree with documents, data stores, logs and secret-like files."""
    root = tmp_path / "source"

    write(root / "docs/notes/README.md", "ops docs\n")
    write(root / "docs/notes/research-images/diagram.txt", "diagram\n")
    write(root / "docs/notes/.env", "SECRET=must-not-backup\n")

    write(root / "projects/notes-app/data/memory.db", "memory\n")
    write(root / "projects/notes-app/data/runtime/state.json", "{}\n")
    write(root / "projects/notes-app/data/token.json", "fake token\n")

    write(root / "projects/feed-reader/data/feed_store.db", "feed\n")
    write(root / "projects/feed-reader/data/api.out.log", "feed log\n")

    write(root / "projects/task-runner/data/task_store.db", "task\n")
    write(root / "projects/task-runner/data/task_store.db-wal", "wal\n")

    write(root / "projects/sync-service/data/sync.db", "sync\n")
    write(root / "projects/sync-service/data/compile_cache/cache.bin", "skip\n")
    write(root / "projects/sync-service/data/test_dbs/test.db", "skip\n")

    write(root / "projects/model-builder/artifacts/art_001/model.glb", "glb\n")
    write(root / "projects/model-builder/artifacts/art_001/manifest.json", "{}\n")

    chat = root / "projects/chat-server"
    create_sqlite(chat / "app.db")
    write(chat / "app.db-wal", "wal\n")
    write(chat / "app.db-shm", "shm\n")
    write(chat / ".env", "SECRET=must-not-backup\n")
    write(chat / "calendar_token.json", "fake token\n")

    backend = root / "projects/dashboard/backend"
    write(backend / "memos.db", "memos\n")
    write(backend / "events.db-wal", "wal\n")
    write(backend / "backend-start.out.log", "backend log\n")
    write(backend / "logs/backend-source.pid", "123\n")
    write(backend / "logs/server.log", "log\n")
    write(backend / "data/probe.db-journal", "journal\n")
    write(backend / "memory_db/index/header.bin", "header\n")
    write(backend / "credentials.json", "fake credential\n")
    write(backend / ".tokens.json", "fake token\n")
    write(backend / "calendar_token.json", "fake token\n")
    write(backend / "client.session", "session\n")
    write(backend / "model_weights.pt", "large model should not be selected\n")
    write(backend / ".venv/site-packages/ignored.db", "skip\n")

    return root


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def create_sqlite(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    try:
        con.execute("create table interactions(id integer primary key, text text)")
        con.execute("create table messages(id integer primary key, text text)")
        con.executemany(
            "insert into interactions(text) values (?)",
            [("hello",), ("coding mode",), ("briefing",)],
        )
        con.executemany(
            "insert into messages(text) values (?)",
            [("message one",), ("message two",)],
        )
        con.commit()
    finally:
        con.close()
