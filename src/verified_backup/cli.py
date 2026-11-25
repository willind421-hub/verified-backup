"""Command-line interface: scan, backup, verify, restore, restore-temp, rules."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .archive import CORRUPT_ARCHIVE_ERRORS, make_archive_name, write_archive, write_sidecar_manifests
from .config import DEFAULT_CONFIG_PATH, ConfigError, load_rules, resolve_source_root
from .restore import RestoreSafetyError, restore_archive, restore_to_temp
from .paths import is_relative_to
from .scanner import build_backup_manifest, scan_source
from .verify import verify_archive


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Exit codes: 0 ok, 1 result reported ``ok: false``, 2 error."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = args.func(args)
    except (
        ConfigError,
        RestoreSafetyError,
        RuntimeError,
        OSError,
        ValueError,
        *CORRUPT_ARCHIVE_ERRORS,
    ) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        return 2
    if result is not None:
        print(json.dumps(result, indent=2, sort_keys=True))
        if isinstance(result, dict) and result.get("ok") is False:
            return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="verified-backup",
        description="Create hash-verified backups and restore them safely into a new folder.",
    )
    parser.set_defaults(func=lambda _args: parser.print_help() or None)
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Create a backup manifest without an archive")
    add_root_config(scan)
    scan.add_argument("--output", type=Path, help="Optional manifest output path")
    scan.set_defaults(func=cmd_scan)

    backup = sub.add_parser("backup", help="Create a zip or tar.gz backup archive")
    add_root_config(backup)
    backup.add_argument("--output-dir", type=Path, default=Path("backups"))
    backup.add_argument("--format", choices=("zip", "tar"), default="zip")
    backup.add_argument("--name", help="Archive base name without extension")
    backup.set_defaults(func=cmd_backup)

    verify = sub.add_parser("verify", help="Verify archive payload checksums")
    verify.add_argument("archive", type=Path)
    verify.add_argument("--checksums", type=Path, help="Optional checksum sidecar JSON")
    verify.set_defaults(func=cmd_verify)

    restore = sub.add_parser("restore", help="Restore archive to a destination; dry-run by default")
    restore.add_argument("archive", type=Path)
    restore.add_argument("--dest", type=Path, required=True)
    restore.add_argument("--execute", action="store_true", help="Actually write files")
    restore.add_argument("--verify-first", action="store_true", help="Verify archive before restore")
    restore.set_defaults(func=cmd_restore)

    restore_temp = sub.add_parser("restore-temp", help="Restore to a new temp directory and verify")
    restore_temp.add_argument("archive", type=Path)
    restore_temp.add_argument("--temp-root", type=Path, help="Directory that will hold the temp restore")
    restore_temp.add_argument("--skip-verify-first", action="store_true")
    restore_temp.set_defaults(func=cmd_restore_temp)

    rules = sub.add_parser("rules", help="Print the active backup rules")
    rules.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    rules.set_defaults(func=cmd_rules)
    return parser


def add_root_config(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--include-private-metadata", action="store_true",
                        help="Include absolute source path, rules and excluded names; do not share")
    parser.add_argument(
        "--root",
        type=Path,
        required=True,
        help="Source root directory; rule target paths are relative to it",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=DEFAULT_CONFIG_PATH,
        help="Rules JSON file (default: packaged rules that cover the whole root)",
    )


def cmd_scan(args: argparse.Namespace) -> dict[str, Any]:
    rules = load_rules(args.config)
    source_root = resolve_source_root(args.root)
    scan = scan_source(source_root, rules)
    manifest = build_backup_manifest(scan, rules, archive_format=None,
                                     include_private_metadata=args.include_private_metadata)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {
        "ok": not scan.missing_targets,
        "manifest_path": str(args.output.resolve()) if args.output else None,
        "summary": manifest["summary"],
    }


def cmd_backup(args: argparse.Namespace) -> dict[str, Any]:
    rules = load_rules(args.config)
    source_root = resolve_source_root(args.root)
    if is_relative_to(args.output_dir, source_root):
        raise ConfigError("Backup output directory must be outside the source root")
    scan = scan_source(source_root, rules)
    if scan.missing_targets:
        raise ConfigError("Refusing backup with missing configured targets")
    manifest = build_backup_manifest(scan, rules, archive_format=args.format,
                                     include_private_metadata=args.include_private_metadata)
    archive_path = args.output_dir / make_archive_name(args.name, args.format)
    final_manifest = write_archive(
        archive_path=archive_path,
        archive_format=args.format,
        manifest=manifest,
        files=scan.files,
    )
    manifest_path, checksum_path = write_sidecar_manifests(
        archive_path=archive_path,
        manifest=final_manifest,
    )
    return {
        "ok": True,
        "archive": str(archive_path.resolve()),
        "manifest": str(manifest_path.resolve()),
        "checksums": str(checksum_path.resolve()),
        "summary": final_manifest["summary"],
    }


def cmd_verify(args: argparse.Namespace) -> dict[str, Any]:
    result = verify_archive(args.archive.resolve(), args.checksums.resolve() if args.checksums else None)
    return result


def cmd_restore(args: argparse.Namespace) -> dict[str, Any]:
    return restore_archive(
        archive_path=args.archive.resolve(),
        dest=args.dest,
        execute=args.execute,
        verify_first=args.verify_first,
    )


def cmd_restore_temp(args: argparse.Namespace) -> dict[str, Any]:
    return restore_to_temp(
        archive_path=args.archive.resolve(),
        temp_root=args.temp_root,
        verify_first=not args.skip_verify_first,
    )


def cmd_rules(args: argparse.Namespace) -> dict[str, Any]:
    return load_rules(args.config)
