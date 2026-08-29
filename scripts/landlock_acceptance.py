#!/usr/bin/env python3
"""Real-kernel Landlock acceptance for every fixed root role and denied operation."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
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


def _run_role(role: RootRole) -> tuple[dict[str, object], bool]:
    parent = Path.home() / ".local" / "state" / "astral-project" / "landlock-acceptance"
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(parent, 0o700)
    root_parent = Path("/run") if role is RootRole.SOCKET_RUNTIME else parent
    root = Path(tempfile.mkdtemp(prefix=f"probe-{role.value}-", dir=root_parent))
    allowed = root / "allowed"
    outside = root / "outside"
    allowed.mkdir(mode=0o700)
    outside.mkdir(mode=0o700)
    existing = allowed / "existing"
    existing.write_text("untouched", encoding="utf-8")
    os.chmod(existing, 0o600)
    executable = allowed / "executable"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(executable, 0o700)
    outside_file = outside / "existing"
    outside_file.write_text("untouched", encoding="utf-8")
    os.chmod(outside_file, 0o600)
    outside_fd = os.open(outside_file, os.O_RDONLY | os.O_CLOEXEC)
    outside_dir_fd = os.open(outside, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    policy = HardeningPolicy.for_plan(((allowed, role),), writable_tmp=False)
    status = enforce(policy)

    def allowed_read() -> None:
        existing.read_text(encoding="utf-8")

    def allowed_execute() -> None:
        subprocess.run(["/usr/bin/true"], capture_output=True, check=True, timeout=5)

    def allowed_write() -> None:
        descriptor = os.open(existing, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
        try:
            os.write(descriptor, b"rewritten")
        finally:
            os.close(descriptor)

    def allowed_truncate() -> None:
        os.truncate(existing, 3)

    def allowed_make_reg() -> None:
        (allowed / "created").write_text("created", encoding="utf-8")

    def allowed_make_dir() -> None:
        (allowed / "newdir").mkdir()

    def allowed_make_sym() -> None:
        link = allowed / "link"
        os.symlink(existing, link)
        link.unlink()

    def allowed_make_sock() -> None:
        endpoint = allowed / "socket"
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(endpoint))

    def allowed_remove_file() -> None:
        victim = allowed / "remove-me"
        victim.write_text("x", encoding="utf-8")
        victim.unlink()

    def allowed_remove_dir() -> None:
        victim = allowed / "remove-dir"
        victim.mkdir()
        victim.rmdir()

    def allowed_refer() -> None:
        source = allowed / "rename-me"
        renamed = allowed / "renamed"
        source.write_text("x", encoding="utf-8")
        source.rename(renamed)
        renamed.rename(source)

    allowed_operations: dict[str, Callable[[], object]] = {
        "read_file": allowed_read,
        "execute": allowed_execute,
        "write_file": allowed_write,
        "truncate": allowed_truncate,
        "make_reg": allowed_make_reg,
        "make_dir": allowed_make_dir,
        "make_sym": allowed_make_sym,
        "make_sock": allowed_make_sock,
        "remove_file": allowed_remove_file,
        "remove_dir": allowed_remove_dir,
        "refer": allowed_refer,
    }
    expected_allowed = {
        "read_file": True,
        "execute": True,
        "write_file": role in {RootRole.REGULAR_WRITABLE, RootRole.DEVICE_RUNTIME},
        "truncate": role is RootRole.REGULAR_WRITABLE,
        "make_reg": role is RootRole.REGULAR_WRITABLE,
        "make_dir": role is RootRole.REGULAR_WRITABLE,
        "make_sym": role is RootRole.REGULAR_WRITABLE,
        "make_sock": role is RootRole.SOCKET_RUNTIME,
        "remove_file": role is RootRole.REGULAR_WRITABLE,
        "remove_dir": role is RootRole.REGULAR_WRITABLE,
        "refer": role is RootRole.REGULAR_WRITABLE,
    }
    allowed_results = [
        _attempt(f"{role.value}.allowed.{name}", operation)
        for name, operation in allowed_operations.items()
    ]
    outside_results = [
        _attempt(
            f"{role.value}.denied.outside_create",
            lambda: (outside / "created").write_text("bad", encoding="utf-8"),
        ),
        _attempt(f"{role.value}.denied.outside_mkdir", lambda: (outside / "newdir").mkdir()),
        _attempt(
            f"{role.value}.denied.outside_symlink",
            lambda: os.symlink(outside_file, outside / "link"),
        ),
        _attempt(f"{role.value}.denied.outside_truncate", lambda: os.truncate(outside_file, 0)),
        _attempt(
            f"{role.value}.denied.outside_refer", lambda: os.rename(existing, outside / "renamed")
        ),
        _attempt(
            f"{role.value}.denied.outside_link", lambda: os.link(outside_file, outside / "hardlink")
        ),
    ]
    output: dict[str, object] = {
        "role": role.value,
        "hardening": status.to_dict(),
        "allowed_operations": allowed_results,
        "denied_outside_operations": outside_results,
        "outside_content": _read_fd(outside_fd),
        "outside_size": os.fstat(outside_fd).st_size,
        "outside_entries": sorted(os.listdir(outside_dir_fd)),
    }
    os.close(outside_fd)
    os.close(outside_dir_fd)
    actual_allowed = {
        str(item["action"]).rsplit(".", 1)[-1]: item["result"] == "succeeded"
        for item in allowed_results
    }
    passed = (
        status.enforced
        and actual_allowed == expected_allowed
        and all(item["result"] == "denied" for item in outside_results)
        and output["outside_content"] == "untouched"
        and output["outside_size"] == len("untouched")
        and output["outside_entries"] == ["existing"]
    )
    return output, passed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=[role.value for role in RootRole], required=True)
    args = parser.parse_args()
    output, passed = _run_role(RootRole(args.role))
    print(json.dumps(output, sort_keys=True))
    return 0 if passed else 70


if __name__ == "__main__":
    raise SystemExit(main())
