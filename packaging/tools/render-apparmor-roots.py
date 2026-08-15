#!/usr/bin/python3
"""Render administrator-approved source roots into fixed AppArmor include."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, "/usr/lib/astral-project/python")

from astral_project.broker.apparmor import render_source_roots
from astral_project.broker.config import load_broker_authority

AUTHORITY = Path("/etc/astral-project/authority.toml")
OUTPUT = Path("/etc/apparmor.d/local/astral-project-source-roots")


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("source-root renderer requires root")
    authority = load_broker_authority(AUTHORITY)
    roots = tuple(item.canonical_root for item in authority.server_ceiling.source_roots)
    content = render_source_roots(roots).encode("utf-8")
    _atomic_write(OUTPUT, content)
    return 0


def _atomic_write(path: Path, content: bytes) -> None:
    parent = path.parent
    details = parent.stat()
    if details.st_uid != 0 or details.st_mode & 0o022:
        raise RuntimeError("AppArmor include directory is unsafe")
    if path.is_symlink():
        raise RuntimeError("AppArmor include is a symlink")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    result = path.lstat()
    if result.st_uid != 0 or stat.S_IMODE(result.st_mode) != 0o644:
        raise RuntimeError("AppArmor include has unsafe ownership or mode")


if __name__ == "__main__":
    main()
