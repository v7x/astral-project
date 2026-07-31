"""Packet 15B/15D native descriptor mount and fixed-workload contract."""

from __future__ import annotations

import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
SOURCE = PROJECT_ROOT / "packaging" / "native" / "aspr-mount-worker.c"


def test_native_mount_worker_compiles_and_rejects_arguments(tmp_path: Path) -> None:
    executable = tmp_path / "aspr-mount-worker"
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(SOURCE), "-o", str(executable)],
        check=True,
        capture_output=True,
        text=True,
    )
    result = subprocess.run([str(executable), "bad"], check=False, capture_output=True)

    assert result.returncode == 64


def test_mount_worker_uses_only_fixed_fd_abi_and_descriptor_syscalls() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    for required in (
        "PLAN 5",
        "SOURCE_BASE 10",
        "F_GET_SEALS",
        "SYS_statx",
        "SYS_open_tree",
        "SYS_mount_setattr",
        "SYS_move_mount",
        "SYS_pivot_root",
        "SYS_capset",
        "PR_SET_NO_NEW_PRIVS",
        "SYS_close_range",
        'APPARMOR_PROFILE "aspr-sftp-v1"',
        '"/.astral-project-runtime/ld.so"',
        '"--library-path"',
        '"/.astral-project-runtime/sftp-server"',
    ):
        assert required in source
    assert "system(" not in source
    assert "execlp" not in source
    assert "caller-controlled" not in source
