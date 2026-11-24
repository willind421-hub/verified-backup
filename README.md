# Verified Backup

**English** | [한국어](README.ko.md) | [日本語](README.ja.md)

Hash-verified zip / tar.gz backups of documents, code and evidence folders, and a
restore path that refuses to overwrite anything and re-verifies every file it writes.
Pure Python standard library, no runtime dependencies.

## The problem

Ad-hoc copies of important folders tend to fail silently: an archive gets damaged in
storage, a credentials file is swept into the backup, a "restore" overwrites newer
work, or a symlink quietly pulls in files from somewhere else on the disk. You usually
find out only when you need the backup.

Verified Backup makes each step checkable:

1. **scan** the source root with explicit include/exclude rules,
2. **backup** into an archive whose embedded manifest records the SHA-256 and size of
   every file *as written into the archive*,
3. **verify** an archive at any time (optionally against a separate checksum sidecar),
4. **restore** into a new folder, dry-run first, with per-file hash checks.

## What it guarantees

- **Content integrity.** Every payload file has a SHA-256 and size recorded in
  `BACKUP_MANIFEST.json` inside the archive, computed from the exact bytes archived.
  `verify` re-hashes every member and reports checksum mismatches, missing members,
  unexpected members and unreadable (corrupt) members.
- **Archive integrity.** `<archive>.checksums.json` stores the SHA-256 of the archive
  file itself plus per-file hashes; `verify --checksums` checks both.
- **Safe restore.**
  - Dry-run by default; nothing is written without `--execute`.
  - Files are created with exclusive-create mode: an existing file is never overwritten.
    Any conflict aborts the restore before anything is written.
  - Restoring directly over the source root recorded in the manifest is refused.
  - Each restored file is hashed and compared to the manifest, and the whole restored
    tree is verified again at the end.
  - If a restore fails part-way (corrupt archive, checksum mismatch, I/O error), every
    file and directory created by that run is removed. Files that already existed in the
    destination are left exactly as they were.
- **Path safety.** Archive members must live under `payload/`, absolute paths and `..`
  are rejected, non-file tar members (links, devices) are rejected, and rule target paths
  may not escape the source root.
- **Links are never followed silently.** Symlinks and Windows junctions are detected
  on the unresolved path, component by component, before anything is resolved. By
  default (`skip_symlinks: true`) linked files are skipped and listed in the manifest
  with reason `symlink`. With `skip_symlinks: false`, a link is followed only if its real
  location is inside the source root; otherwise the file is listed with reason
  `outside_root`.
- **Secret-like file names are excluded** (`.env`, `*token*`, `*.pem`, `id_rsa*`, ...)
  before anything is hashed or archived. Every exclusion is listed in the manifest
  together with its reason.

## Design

```
rules.json ──► scan_source ──► build_backup_manifest ──► write_archive ──► write_sidecar_manifests
                 (classify, hash)                          (zip | tar.gz)      (.manifest.json, .checksums.json)

archive ──► verify_archive            archive ──► restore_archive (dry-run | execute) ──► verify_restored_tree
```

Archive layout:

```
BACKUP_MANIFEST.json        full manifest: source root, rules snapshot, files, exclusions
payload/<relative/path>     file contents, relative to the source root
```

Sidecars written next to the archive:

- `<archive>.manifest.json` – copy of the full manifest
- `<archive>.checksums.json` – archive SHA-256 and per-file SHA-256/size

| Module | Responsibility |
| --- | --- |
| `config.py` | Load and validate rule files; resolve the source root |
| `scanner.py` | Expand targets, classify exclusions (links first), hash files, build the manifest |
| `archive.py` | Write zip / tar.gz archives and sidecars |
| `verify.py` | Read the embedded manifest, re-hash payloads, check sidecars and member paths |
| `restore.py` | Dry-run planning, no-overwrite restore with rollback, temp restore |
| `paths.py` | Relative-path normalisation, containment checks, symlink/junction detection |
| `cli.py` | `verified-backup` command |

### Rules

Rules are JSON. Target paths are relative to the source root; patterns use `/` and are
matched case-insensitively. `**/` also matches no directory at all, so `**/.git/**`
excludes a `.git` folder at any depth, including one directly under the source root.

```json
{
  "schema_version": "verified-backup-rules/v1",
  "targets": [
    {"name": "documents", "path": "documents", "include": ["**/*"], "exclude": ["**/~$*"]},
    {"name": "code", "path": "code", "include": ["**/*.py", "**/*.toml", "**/*.md"]},
    {"name": "evidence", "path": "evidence", "include": ["**/*"]}
  ],
  "exclude": {
    "skip_symlinks": true,
    "path_patterns": ["**/.git/**", "**/__pycache__/**", "**/*.tmp"],
    "secret_name_patterns": [".env", "*token*", "*.pem"]
  }
}
```

Exclusion reasons recorded in the manifest, in the order they are checked:
`symlink`, `outside_root`, `secret_name`, `global_exclude`, `target_exclude`.

The packaged default rules (`verified-backup rules` prints them) back up **everything**
under the source root except VCS metadata, caches, virtual environments, temp/lock files,
links and secret-like names. See [`examples/rules.example.json`](examples/rules.example.json)
for a multi-target example.

## Quick start

```bash
pip install .            # or: pip install -e ".[test]" for development

# Preview what would be backed up
verified-backup scan --root ./my-folder --output manifest.json

# Create an archive (zip or tar) plus sidecars
verified-backup backup --root ./my-folder --output-dir backups --format zip --name my-folder-2026-01-01

# Verify the archive and its sidecar
verified-backup verify backups/my-folder-2026-01-01.zip --checksums backups/my-folder-2026-01-01.zip.checksums.json

# Restore: dry-run first, then execute into a new folder
verified-backup restore backups/my-folder-2026-01-01.zip --dest ./restore-check
verified-backup restore backups/my-folder-2026-01-01.zip --dest ./restore-check --execute --verify-first

# Restore into a fresh temporary folder and verify (verifies the archive first by default)
verified-backup restore-temp backups/my-folder-2026-01-01.zip --temp-root ./restore-tmp

# Use custom rules
verified-backup backup --root ./my-folder --config my_rules.json
```

`--root` is always required; there is no implicit default source. `python -m verified_backup`
works as well. Every command prints JSON. Exit codes: `0` success, `1` the result reports
`"ok": false` (failed verification, dry-run conflicts), `2` error (invalid rules, missing
root, corrupt archive, refused restore).

## Python API

```python
from pathlib import Path

from verified_backup.archive import write_archive, write_sidecar_manifests
from verified_backup.config import load_rules, resolve_source_root
from verified_backup.restore import restore_archive, restore_to_temp
from verified_backup.scanner import build_backup_manifest, scan_source
from verified_backup.verify import verify_archive

rules = load_rules()                                  # or load_rules("my_rules.json")
root = resolve_source_root("my-folder")
scan = scan_source(root, rules)
manifest = build_backup_manifest(scan, rules, archive_format="zip")

archive = Path("backups/my-folder.zip")
final_manifest = write_archive(archive_path=archive, archive_format="zip",
                               manifest=manifest, files=scan.files)
_, checksums = write_sidecar_manifests(archive_path=archive, manifest=final_manifest)

assert verify_archive(archive, checksums)["ok"]
plan = restore_archive(archive_path=archive, dest=Path("restore-check"))               # dry-run
done = restore_archive(archive_path=archive, dest=Path("restore-check"), execute=True,
                       verify_first=True)
```

Errors: `ConfigError` (rules / source root), `ArchiveError` (unsupported, corrupt or
inconsistent archive), `RestoreSafetyError` (conflict, source-root restore, failed
pre-verification).

## Example

[`examples/end_to_end_demo.py`](examples/end_to_end_demo.py) builds a small synthetic tree
in a temporary directory and walks through backup, verify, dry-run, restore, conflict
refusal and tamper detection using the CLI:

```bash
python examples/end_to_end_demo.py
```

## Running tests

```bash
pip install -e ".[test]"
pytest -q
```

Tests that need to create symlinks are skipped where the OS does not allow it (for
example Windows without Developer Mode); the Windows junction tests do not need extra
privileges.

## Limitations and non-goals

- **Live SQLite databases are copied byte-for-byte, not snapshotted.** If a database is
  being written during the backup, the archived `.db` / `-wal` / `-shm` files can be
  mutually inconsistent (in WAL mode recent commits live in the `-wal` file). The hashes
  will faithfully describe the inconsistent copy. Stop the writer first, or back up a
  snapshot made with SQLite's backup API, for example
  `sqlite3.connect("live.db").backup(sqlite3.connect("snapshot.db"))` or
  `sqlite3 live.db ".backup snapshot.db"`.
- **No filesystem snapshot.** Files are read one by one. The manifest records the bytes
  that were actually archived, but a file modified *while* it is being read can be
  captured in a torn state.
- **Secret detection is name-based only.** File contents are not scanned. The default
  patterns are deliberately broad and can over-exclude (e.g. `tokenizer.py` matches
  `*token*`); review the `excluded` list in the manifest and adjust the rules.
- **Integrity, not authenticity.** Checksums detect accidental damage. They do not stop
  someone who can rewrite both the archive and its sidecar; store the sidecar or its hash
  separately if that matters. Archives are not encrypted.
- **Content only.** Restored files get fresh timestamps; permissions, ownership, ACLs,
  extended attributes and empty directories are not preserved.
- **Memory use.** tar payloads and restored members are read fully into memory, so very
  large single files need a matching amount of RAM.
- **Junction traversal.** Python's `glob` descends into Windows junctions; files found
  behind them are excluded, but the directories are still enumerated, so a junction loop
  makes scans slow.
- Not a backup scheduler: no incremental/deduplicated backups, retention policy or remote
  storage.

## Origin

Originally developed as part of willind, a personal AI assistant project, where it
backed up the assistant's documents, data stores and logs. This repository is a
standalone extraction: project-specific rules and paths were removed, and the source root
is now always given explicitly.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
