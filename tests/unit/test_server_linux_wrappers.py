"""Typed Linux syscall wrapper success and failure behavior."""

from __future__ import annotations

import ctypes
import errno
from typing import Any, cast

import pytest

from astral_project.server import linux


class _Libc:
    def __init__(self, result: int = 3) -> None:
        self.result = result

    def syscall(self, number: int, *args: object) -> int:
        if number == 2 and self.result != -1:
            result = ctypes.cast(cast(Any, args[-1]), ctypes.POINTER(linux._Statx)).contents
            result.mask = linux.STATX_MNT_ID
            result.dev_major = 8
            result.dev_minor = 1
            result.inode = 42
            result.mode = 0o100644
            result.mount_id = 7
        return self.result

    def mount(self, *_args: object) -> int:
        return self.result

    def umount2(self, *_args: object) -> int:
        return self.result

    def fstatfs(self, _fd: int, pointer: object) -> int:
        if self.result != -1:
            ctypes.cast(
                cast(Any, pointer), ctypes.POINTER(linux._StatFs)
            ).contents.filesystem_type = 0x1234
        return self.result


def test_syscall_wrappers_return_success(monkeypatch: pytest.MonkeyPatch) -> None:
    libc = _Libc()
    monkeypatch.setattr("astral_project.server.linux._libc", libc)
    monkeypatch.setattr(linux, "_syscalls", lambda: (1, 2, 3, 4, 5))
    assert linux.openat2(3, b"x", 1, 2) == 3
    result = linux.statx_descriptor(3)
    assert result == linux.StatxResult(device=2049, inode=42, mode=0o100644, mount_id=7)
    assert linux.clone_mount(3) == 3
    assert linux.clone_mount(3, recursive=True) == 3
    linux.make_mount_read_only(3)
    linux.attach_mount(3, b"/target")
    linux.make_private_mount_namespace()
    linux.mount_tmpfs(b"/target")
    linux.detach_mount(b"/target")
    assert linux.filesystem_magic(3) == 0x1234
    assert linux.is_autofs(0x0187)
    assert not linux.is_autofs(0)


def test_syscall_wrappers_translate_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    libc = _Libc(-1)
    monkeypatch.setattr("astral_project.server.linux._libc", libc)
    monkeypatch.setattr(linux, "_syscalls", lambda: (1, 2, 3, 4, 5))
    ctypes.set_errno(errno.EPERM)
    calls = (
        lambda: linux.openat2(3, b"x", 1, 2),
        lambda: linux.statx_descriptor(3),
        lambda: linux.clone_mount(3),
        lambda: linux.make_mount_read_only(3),
        lambda: linux.attach_mount(3, b"/target"),
        linux.make_private_mount_namespace,
        lambda: linux.mount_tmpfs(b"/target"),
        lambda: linux.detach_mount(b"/target"),
        lambda: linux.filesystem_magic(3),
    )
    for call in calls:
        with pytest.raises(linux.LinuxSyscallError):
            call()


def test_syscalls_reject_unknown_architecture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "astral_project.server.linux.os.uname", lambda: type("Uname", (), {"machine": "unknown"})()
    )
    with pytest.raises(OSError, match="unsupported CPU"):
        linux._syscalls()
