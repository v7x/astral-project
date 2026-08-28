#!/usr/bin/env python3
"""Real-kernel Landlock second-wall acceptance probe."""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path

from astral_project.sandbox.hardening import HardeningPolicy, RootRole, enforce


def _attempt(action: str, operation: Callable[[], object]) -> dict[str, object]:
    try:
        operation()
    except OSError as error:
        return {"action": action, "result": "denied", "errno": error.errno}
    return {"action": action, "result": "succeeded"}


def _read_fd(descriptor: int) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    return os.read(descriptor, 4096).decode("utf-8")


def main() -> int:
    parent = Path.home() / ".local" / "state" / "astral-project" / "landlock-acceptance"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(parent, 0o700)
    root = Path(tempfile.mkdtemp(prefix="probe-", dir=parent))
    allowed = root / "allowed"
    outside = root / "outside"
    allowed.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    outside_file = outside / "existing"
    outside_file.write_text("untouched", encoding="utf-8")
    os.chmod(outside_file, 0o600)
    outside_fd = os.open(outside_file, os.O_RDONLY | os.O_CLOEXEC)
    outside_dir_fd = os.open(outside, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    policy = HardeningPolicy(
        allowed_roots=((allowed, RootRole.REGULAR_WRITABLE),),
        max_open_files=128,
        max_processes=32,
    )
    status = enforce(policy)
    allowed_file = allowed / "created"

    def create_write_truncate() -> None:
        with allowed_file.open("x", encoding="utf-8") as stream:
            stream.write("one")
        with allowed_file.open("w", encoding="utf-8") as stream:
            stream.write("two")
        os.truncate(allowed_file, 3)

    allowed_file_result = _attempt("allowed_create_write_truncate", create_write_truncate)
    outside_create = _attempt(
        "outside_create", lambda: (outside / "created").write_text("bad", encoding="utf-8")
    )
    outside_mkdir = _attempt("outside_mkdir", lambda: (outside / "newdir").mkdir())
    outside_symlink = _attempt(
        "outside_symlink", lambda: os.symlink(outside_file, outside / "link")
    )
    outside_truncate = _attempt("outside_truncate", lambda: os.truncate(outside_file, 0))
    outside_refer = _attempt("outside_refer", lambda: os.rename(allowed_file, outside / "renamed"))
    outside_link = _attempt("outside_link", lambda: os.link(outside_file, outside / "hardlink"))
    negative_controls = [
        outside_create,
        outside_mkdir,
        outside_symlink,
        outside_truncate,
        outside_refer,
        outside_link,
    ]
    output = {
        "hardening": status.to_dict(),
        "allowed": allowed_file_result,
        "allowed_content": allowed_file.read_text(encoding="utf-8")
        if allowed_file.exists()
        else None,
        "negative_controls": negative_controls,
        "outside_content": _read_fd(outside_fd),
        "outside_size": os.fstat(outside_fd).st_size,
        "outside_entries": sorted(os.listdir(outside_dir_fd)),
    }
    os.close(outside_fd)
    os.close(outside_dir_fd)
    (allowed / "result.json").write_text(json.dumps(output, sort_keys=True), encoding="utf-8")
    passed = (
        status.enforced
        and allowed_file_result["result"] == "succeeded"
        and output["allowed_content"] == "two"
        and all(item["result"] == "denied" for item in negative_controls)
        and output["outside_content"] == "untouched"
        and output["outside_size"] == len("untouched")
        and output["outside_entries"] == ["existing"]
    )
    print(json.dumps(output, sort_keys=True))
    return 0 if passed else 70


if __name__ == "__main__":
    raise SystemExit(main())
