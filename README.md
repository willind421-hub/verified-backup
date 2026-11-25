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

These checks assume trusted, stable source/output/destination directories. They are
not protection against an attacker concurrently replacing filesystem paths; see limitations.

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
  - Restoring directly over the source root is refused using its recorded path or root fingerprint.
  - Each restored file is hashed and compared to the manifest, and the whole restored
    tree is verified again at the end.
  - If a restore fails part-way or its final verification fails, rollback attempts to
    remove files/directories created by that run, including a partially written file.
    Existing destination files are not selected for deletion. Cleanup needs filesystem
    permission and is not guaranteed after process termination or power loss.
- **Path safety.** Archive members must live under `payload/`, absolute paths and `..`
  are rejected, non-file tar members (links, devices) are rejected, and rule target paths
  may not escape the source root.
- **Links are never followed silently.** Symlinks and Windows junctions are detected
  on the unresolved path, component by component, before anything is resolved. By
  default (`skip_symlinks: true`) linked files are skipped and counted with reason
  `symlink`. With `skip_symlinks: false`, a link is followed only if its real
  location is inside the source root; otherwise the file is counted with reason
  `outside_root`.
- **Secret-like file names are excluded** (`.env`, `*token*`, `*.pem`, `id_rsa*`, ...)
  before anything is hashed or archived. The default manifest counts exclusions by
  reason; detailed paths require the explicit private-metadata option below.

## Design

```
rules.json ──► scan_source ──► build_backup_manifest ──► write_archive ──► write_sidecar_manifests
                 (classify, hash)                          (zip | tar.gz)      (.manifest.json, .checksums.json)

archive ──► verify_archive            archive ──► restore_archive (dry-run | execute) ──► verify_restored_tree
```

Archive layout:

```
BACKUP_MANIFEST.json        file hashes/sizes, root fingerprint, exclusion counts
payload/<relative/path>     file contents, relative to the source root
```

Sidecars written next to the archive:

- `<archive>.manifest.json` – copy of the embedded manifest (same privacy setting)
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
verified-backup backup --root ./my-folder --config my_rules.json --output-dir backups
```

`--root` is required only for `scan` and `backup`; these have no implicit default
source. `verify`, `restore`, `restore-temp` and `rules` do not accept it.
`python -m verified_backup` works as well. Operation results/errors are JSON;
`--help` and argument-parser errors are text. Exit codes: `0` success, `1` a result
with `"ok": false` (failed verification, dry-run conflicts, missing scan targets),
`2` an error (invalid rules/root/archive, refused backup or restore).

### Safety defaults and sharing

- Every configured target path is required. `scan` reports missing-target counts and
  exits `1`; `backup` exits `2` before creating an archive. There is no optional-target
  flag. An existing but empty target, or an include pattern matching nothing, is not a
  missing path: inspect `summary.file_count` if you require nonempty backups.
- Keep `--output-dir` **outside** `--root`. The CLI rejects output equal to or inside
  the source rather than silently excluding it. From inside a source folder use
  `verified-backup backup --root . --output-dir ../backups`. The default `backups`
  directory is relative to the working directory, not to `--root`. `--name` is one
  filename stem, never a path; separators, ADS colons and Windows reserved names fail.
- Archive staging uses a unique exclusively created neighbor, then no-replace hard-link
  publication. Filesystems without hard-link support fail closed. Existing archives,
  sidecars and `scan --output` files are refused, not replaced; choose a fresh name.
  A failed sidecar write can leave the already completed archive; the three files are
  **not** one crash-atomic transaction. Check the exit status, then inspect/verify it.
- By default manifests omit the absolute source path, rule snapshot, excluded/missing
  names and target labels. They keep per-reason `excluded_counts`, summary counts,
  included relative names, hashes, sizes, timestamps and `source_root_sha256`.
  The root fingerprint is a comparison identifier, **not anonymization**: a guessed
  root can be tested. Included names/content can still be private; archives are not encrypted.
- For a **local-only** detailed scan, explicitly opt in:

  ```bash
  verified-backup scan --root ./my-folder --output local-private.json --include-private-metadata
  ```

  `backup --include-private-metadata` also embeds those details in the archive and its
  manifest sidecar: do not share them. Python callers use
  `build_backup_manifest(scan, rules, include_private_metadata=True)`.
- Defaults exclude `.netrc`, `.pgpass`, `.npmrc`, `.pypirc`, `auth.json`, `*.ppk`,
  `*.jks`, `*.keystore`, `wallet.dat`, `.git-credentials` and the `.ssh`, `.gnupg`,
  `.aws`, `.kube`, `.docker` trees at every depth, in addition to the older patterns.
  A custom rules file **replaces**, not merges with, defaults. Review a local private
  scan before relying on it. Credentials in a neutral `settings.json`, browser
  `Login Data`, or a renamed key can still be included; content is never secret-scanned.
- Readers reject invalid manifest fields, duplicate members/paths (including case-only
  collisions), missing/extra payloads, traversal, backslashes, ADS `:`, Windows devices,
  trailing dots/spaces, and file/directory collisions. Size and SHA-256 must both match.
  This deliberately rejects some names legal on POSIX for portable restores.
  Backup creation validates the final manifest against the same rules before publishing
  the archive, so unsupported names or collisions fail instead of producing an unrestorable backup.

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
if scan.missing_targets:
    raise RuntimeError("Missing configured targets")
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
The low-level writer does not choose safe source/output placement for you: keep
`archive` outside `root`, and use a fresh path for each run.

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
  `*token*`); review `excluded_counts`, or opt into a local private scan to review
  the detailed `excluded` list, and adjust the rules.
- **Integrity, not authenticity.** Checksums detect accidental damage. They do not stop
  someone who can rewrite both the archive and its sidecar; store the sidecar or its hash
  separately if that matters. Archives are not encrypted.
- **Content only.** Restored files get fresh timestamps; permissions, ownership, ACLs,
  extended attributes and empty directories are not preserved.
- **Memory use.** tar payloads and restored members are read fully into memory, so very
  large single files need a matching amount of RAM. There are no member-count or
  decompressed-size quotas; do not treat this as an untrusted-archive sandbox.
- **Filesystem races and durability.** Name/path checks and file opens are separate;
  exclusive creation and no-replace publication do not prevent malicious concurrent
  ancestor, symlink/junction, staging-file or hard-link/8.3-alias replacement. Use
  directories writable only by trusted users, stop concurrent writers, and do not
  rely on the root fingerprint as filesystem identity proof. There is no directory
  fsync, recovery journal or tested power-loss guarantee. Rollback is best effort
  if cleanup itself fails; inspect the destination after such an error.
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
