"""End-to-end demo on synthetic data: backup, verify, restore, conflict refusal, tamper detection.

Everything happens inside a temporary directory that is deleted afterwards.
Run from anywhere after installing the package:  python examples/end_to_end_demo.py
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

RULES = Path(__file__).resolve().parent / "rules.example.json"


def run_cli(*args: str, expect: int = 0) -> dict:
    proc = subprocess.run(
        [sys.executable, "-m", "verified_backup", *args],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != expect:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"unexpected exit code {proc.returncode} for: {' '.join(args)}")
    return json.loads(proc.stdout or proc.stderr)


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def create_source(root: Path) -> None:
    write(root / "documents/report.md", "# Quarterly report\n\nAll numbers are made up.\n")
    write(root / "documents/drafts/outline.txt", "1. intro\n2. method\n3. results\n")
    write(root / "code/app/main.py", "print('hello')\n")
    write(root / "code/pyproject.toml", "[project]\nname = 'demo'\n")
    write(root / "code/build/generated.py", "# build output, excluded by target rule\n")
    write(root / "documents/.env", "DEMO_SETTING=not-a-real-value\n")  # excluded: secret-like name
    write(root / "evidence/run-001/results.csv", "case,passed\na,1\nb,1\n")
    write(root / "evidence/run-001/notes.tmp", "scratch\n")  # excluded: global pattern
    db = root / "evidence/run-001/measurements.db"
    con = sqlite3.connect(db)
    try:
        con.execute("create table m(id integer primary key, value real)")
        con.executemany("insert into m(value) values (?)", [(1.5,), (2.5,), (3.5,)])
        con.commit()
    finally:
        con.close()  # a closed database: no live-SQLite consistency issue


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="verified-backup-demo-") as tmp:
        tmp_path = Path(tmp).resolve()
        source = tmp_path / "source"
        out = tmp_path / "backups"
        create_source(source)

        scan_path = tmp_path / "scan.json"
        scan = run_cli("scan", "--root", str(source), "--config", str(RULES), "--output", str(scan_path))
        print(f"scan: {scan['summary']['file_count']} files, "
              f"{scan['summary']['excluded_count']} excluded")
        scan_manifest = json.loads(scan_path.read_text(encoding="utf-8"))
        assert "source_root" not in scan_manifest and "rules" not in scan_manifest
        assert scan_manifest["excluded"] == [] and scan_manifest["excluded_counts"]["secret_name"] == 1
        assert all("target" not in item for item in scan_manifest["files"])
        print("metadata redacted: exclusion counts only; local paths and rules omitted")
        private_path = tmp_path / "private-scan.json"
        run_cli("scan", "--root", str(source), "--config", str(RULES),
                "--include-private-metadata", "--output", str(private_path))
        private = json.loads(private_path.read_text(encoding="utf-8"))
        assert private["source_root"] == source.as_posix() and private["excluded"]
        print("private scan: local-only opt-in includes excluded paths and rules")

        nested = run_cli("backup", "--root", str(source), "--output-dir", str(source / "backups"), expect=2)
        assert "outside" in nested["error"].lower() and not (source / "backups").exists()
        print("nested output refused: no self-inclusion")
        missing_rules = json.loads(RULES.read_text(encoding="utf-8"))
        missing_rules["targets"].append({"name": "required", "path": "absent", "include": ["**/*"]})
        missing_config = tmp_path / "missing-rules.json"
        missing_config.write_text(json.dumps(missing_rules), encoding="utf-8")
        missing_scan = run_cli("scan", "--root", str(source), "--config", str(missing_config), expect=1)
        assert missing_scan["summary"]["missing_target_count"] == 1
        missing = run_cli("backup", "--root", str(source), "--config", str(missing_config),
                          "--output-dir", str(tmp_path / "missing-output"), expect=2)
        assert "missing" in missing["error"] and not (tmp_path / "missing-output").exists()
        print("missing target refused: scan exit 1, backup exit 2, no output")

        results = {}
        for fmt in ("zip", "tar"):
            backup = run_cli(
                "backup", "--root", str(source), "--config", str(RULES),
                "--output-dir", str(out), "--format", fmt, "--name", f"demo-{fmt}",
            )
            results[fmt] = backup
            verify = run_cli("verify", backup["archive"], "--checksums", backup["checksums"])
            print(f"{fmt}: archived {backup['summary']['file_count']} files, "
                  f"verify ok={verify['ok']} checked={verify['checked_files']}")
            before = Path(backup["archive"]).read_bytes()
            repeat = run_cli("backup", "--root", str(source), "--config", str(RULES),
                             "--output-dir", str(out), "--format", fmt, "--name", f"demo-{fmt}", expect=2)
            assert "already exists" in repeat["error"] and Path(backup["archive"]).read_bytes() == before
            print(f"{fmt}: repeat backup refused; existing archive unchanged")

        archive = results["zip"]["archive"]
        manifest = json.loads(Path(results["zip"]["manifest"]).read_text(encoding="utf-8"))
        assert manifest["excluded"] == []
        print(f"  excluded counts: {manifest['excluded_counts']}")

        dest = tmp_path / "restored"
        dry = run_cli("restore", archive, "--dest", str(dest))
        print(f"dry-run: would create {dry['would_create_count']} files, destination exists={dest.exists()}")

        done = run_cli("restore", archive, "--dest", str(dest), "--execute", "--verify-first")
        print(f"restore: {done['restored_files']} files, tree verified={done['verification']['ok']}")
        con = sqlite3.connect(dest / "evidence/run-001/measurements.db")
        try:
            rows = con.execute("select count(*) from m").fetchone()[0]
        finally:
            con.close()
        print(f"restored SQLite rows: {rows}")

        again = run_cli("restore", archive, "--dest", str(dest), "--execute", expect=2)
        print(f"second restore into same folder refused: {again['error']}")

        temp = run_cli("restore-temp", results["tar"]["archive"], "--temp-root", str(tmp_path / "temp"))
        print(f"restore-temp (tar): ok={temp['ok']} checked={temp['verification']['checked_files']}")

        tampered = out / "demo-tampered.zip"
        with zipfile.ZipFile(archive) as src, zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as dst:
            for info in src.infolist():
                data = src.read(info.filename)
                if info.filename == "payload/documents/report.md":
                    data = data.replace(b"made up", b"made-up")
                dst.writestr(info, data)
        bad = run_cli("verify", str(tampered), expect=1)
        print(f"tampered archive: ok={bad['ok']} errors={bad['errors']}")
        refused = run_cli("restore", str(tampered), "--dest", str(tmp_path / "never"),
                          "--execute", "--verify-first", expect=2)
        print(f"restore of tampered archive refused: {refused['error']}; "
              f"target created={ (tmp_path / 'never').exists() }")

    print("DEMO PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
