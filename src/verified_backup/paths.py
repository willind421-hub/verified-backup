"""Path helpers: relative-path normalisation, containment checks and link detection."""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath, PureWindowsPath

# Reparse tag of a Windows directory junction ("mount point"). ``stat`` exposes the
# constant on every platform since Python 3.8; the fallback is the documented value.
_IO_REPARSE_TAG_MOUNT_POINT = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)


def normalize_rel(path: Path, root: Path) -> str:
    rel = path.resolve().relative_to(root.resolve())
    return rel.as_posix()


def normalize_pattern(pattern: str) -> str:
    return pattern.replace("\\", "/").lstrip("/")


def is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def is_safe_relative_path(value: str) -> bool:
    """Return True if ``value`` is a relative path that cannot escape its base.

    Absolute paths, drive-qualified paths (``C:x``), rooted paths (``/x``) and any
    ``..`` component are rejected on every platform.
    """
    normalized = value.replace("\\", "/")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or ".." in pure.parts:
        return False
    if PureWindowsPath(value).anchor or Path(value).anchor:
        return False
    return True


def is_link(path: Path) -> bool:
    """Return True if ``path`` itself is a symbolic link or a Windows junction.

    ``os.lstat`` is used so the link is never followed. Junctions are not reported
    by ``Path.is_symlink()``, so the Windows reparse tag is checked as well.
    """
    try:
        st = os.lstat(path)
    except OSError:
        return False
    if stat.S_ISLNK(st.st_mode):
        return True
    return getattr(st, "st_reparse_tag", 0) == _IO_REPARSE_TAG_MOUNT_POINT


def first_link_component(path: Path, root: Path) -> Path | None:
    """Return the first symlink/junction between ``root`` (exclusive) and ``path``.

    The walk is lexical: ``path`` must be spelled below ``root`` and nothing is
    resolved, so a link is detected before anything follows it. Returns ``None``
    when no component is a link.
    """
    rel = path.relative_to(root)
    current = root
    for part in rel.parts:
        current = current / part
        if is_link(current):
            return current
    return None


def validate_file_path(rel_path: str) -> str:
    """Accept only canonical, portable relative file paths; never normalize input.

    Reject NTFS alternate streams, Windows device names and aliases on every OS.
    This same spelling is used for manifest, payload and restored paths.
    """
    if not isinstance(rel_path, str) or not rel_path or "\\" in rel_path:
        raise ValueError(f"Unsafe relative path: {rel_path!r}")
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    reserved.update(prefix + digit for prefix in ("COM", "LPT") for digit in "123456789¹²³")
    for part in rel_path.split("/"):
        if (not part or part in (".", "..") or part[-1] in ". "
                or any(ord(c) < 32 or c in '<>:"|?*' for c in part)
                or part.split(".", 1)[0].upper() in reserved):
            raise ValueError(f"Unsafe relative path: {rel_path!r}")
    return rel_path


def safe_join(root: Path, rel_path: str) -> Path:
    validate_file_path(rel_path)
    rel = PurePosixPath(rel_path)
    if rel.is_absolute() or not rel.parts:
        raise ValueError(f"Unsafe relative path: {rel_path}")
    candidate = root.joinpath(*rel.parts).resolve()
    if not is_relative_to(candidate, root):
        raise ValueError(f"Path escapes destination root: {rel_path}")
    return candidate
