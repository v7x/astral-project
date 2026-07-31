"""Small policy-free Linux syscall boundary for remote path pinning.

Only typed syscall wrappers live here. Path policy belongs in ``path_resolver``.
"""

from __future__ import annotations

import ctypes
import errno
import os
from dataclasses import dataclass

# linux/openat2.h
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08

# linux/mount.h, linux/stat.h, and fcntl.h
AT_EMPTY_PATH = 0x1000
OPEN_TREE_CLONE = 0x00000001
OPEN_TREE_CLOEXEC = 0x00080000
MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
MOUNT_ATTR_RDONLY = 0x00000001
MS_REC = 0x00004000
MS_PRIVATE = 0x00040000
MNT_DETACH = 0x00000002
STATX_BASIC_STATS = 0x07FF
STATX_MNT_ID = 0x1000

_AUTOFS_SUPER_MAGIC = 0x0187

_SYSCALLS: dict[str, tuple[int, int, int, int, int]] = {
    "x86_64": (437, 332, 428, 429, 442),
    "amd64": (437, 332, 428, 429, 442),
    "aarch64": (437, 291, 428, 429, 442),
}


class LinuxSyscallError(OSError):
    """Linux syscall failure with reviewable operation and flag evidence."""

    def __init__(self, syscall: str, flags: str, error_number: int) -> None:
        super().__init__(error_number, f"{syscall}({flags}): {os.strerror(error_number)}")
        self.syscall = syscall
        self.flags = flags

    def evidence(self) -> dict[str, object]:
        return {"errno": self.errno, "flags": self.flags, "syscall": self.syscall}


def _raise_syscall(syscall: str, flags: str) -> None:
    raise LinuxSyscallError(syscall, flags, ctypes.get_errno())


class _OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_ulonglong),
        ("mode", ctypes.c_ulonglong),
        ("resolve", ctypes.c_ulonglong),
    ]


class _MountAttr(ctypes.Structure):
    _fields_ = [
        ("attr_set", ctypes.c_ulonglong),
        ("attr_clr", ctypes.c_ulonglong),
        ("propagation", ctypes.c_ulonglong),
        ("userns_fd", ctypes.c_ulonglong),
    ]


class _StatxTimestamp(ctypes.Structure):
    _fields_ = [
        ("seconds", ctypes.c_longlong),
        ("nanoseconds", ctypes.c_uint),
        ("reserved", ctypes.c_int),
    ]


class _Statx(ctypes.Structure):
    """Linux's 256-byte statx ABI through the stable mount-ID fields."""

    _fields_ = [
        ("mask", ctypes.c_uint),
        ("block_size", ctypes.c_uint),
        ("attributes", ctypes.c_ulonglong),
        ("link_count", ctypes.c_uint),
        ("uid", ctypes.c_uint),
        ("gid", ctypes.c_uint),
        ("mode", ctypes.c_ushort),
        ("spare0", ctypes.c_ushort),
        ("inode", ctypes.c_ulonglong),
        ("size", ctypes.c_ulonglong),
        ("blocks", ctypes.c_ulonglong),
        ("attributes_mask", ctypes.c_ulonglong),
        ("access_time", _StatxTimestamp),
        ("birth_time", _StatxTimestamp),
        ("change_time", _StatxTimestamp),
        ("modify_time", _StatxTimestamp),
        ("rdev_major", ctypes.c_uint),
        ("rdev_minor", ctypes.c_uint),
        ("dev_major", ctypes.c_uint),
        ("dev_minor", ctypes.c_uint),
        ("mount_id", ctypes.c_ulonglong),
        ("dio_mem_align", ctypes.c_uint),
        ("dio_offset_align", ctypes.c_uint),
        ("spare3", ctypes.c_ulonglong * 12),
    ]


class _StatFs(ctypes.Structure):
    _fields_ = [
        ("filesystem_type", ctypes.c_long),
        ("block_size", ctypes.c_long),
        ("blocks", ctypes.c_ulong),
        ("blocks_free", ctypes.c_ulong),
        ("blocks_available", ctypes.c_ulong),
        ("files", ctypes.c_ulong),
        ("files_free", ctypes.c_ulong),
        ("filesystem_id", ctypes.c_int * 2),
        ("name_length", ctypes.c_long),
        ("fragment_size", ctypes.c_long),
        ("mount_flags", ctypes.c_long),
        ("spare", ctypes.c_long * 4),
    ]


@dataclass(frozen=True, slots=True)
class StatxResult:
    device: int
    inode: int
    mode: int
    mount_id: int


_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_StatFs)]
_libc.fstatfs.restype = ctypes.c_int
_libc.mount.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_ulong,
    ctypes.c_void_p,
]
_libc.mount.restype = ctypes.c_int
_libc.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]
_libc.umount2.restype = ctypes.c_int


def _syscalls() -> tuple[int, int, int, int, int]:
    try:
        return _SYSCALLS[os.uname().machine.lower()]
    except KeyError as error:
        raise OSError(errno.ENOSYS, "unsupported CPU architecture for reviewed syscalls") from error


def openat2(dirfd: int, path: bytes, flags: int, resolve: int) -> int:
    """Open a path relative to pinned directory with Linux openat2 semantics."""
    openat2_number, _, _, _, _ = _syscalls()
    how = _OpenHow(flags=flags, mode=0, resolve=resolve)
    result = _libc.syscall(
        openat2_number,
        ctypes.c_int(dirfd),
        ctypes.c_char_p(path),
        ctypes.byref(how),
        ctypes.sizeof(how),
    )
    if result == -1:
        _raise_syscall("openat2", f"flags=0x{flags:x},resolve=0x{resolve:x}")
    return int(result)


def statx_descriptor(fd: int) -> StatxResult:
    """Read object identity from descriptor, never a mutable pathname."""
    _, statx_number, _, _, _ = _syscalls()
    result = _Statx()
    status = _libc.syscall(
        statx_number,
        ctypes.c_int(fd),
        ctypes.c_char_p(b""),
        ctypes.c_int(AT_EMPTY_PATH),
        ctypes.c_uint(STATX_BASIC_STATS | STATX_MNT_ID),
        ctypes.byref(result),
    )
    if status == -1:
        _raise_syscall(
            "statx", f"flags=0x{AT_EMPTY_PATH:x},mask=0x{STATX_BASIC_STATS | STATX_MNT_ID:x}"
        )
    if result.mask & STATX_MNT_ID == 0:
        raise OSError(errno.EOPNOTSUPP, "filesystem did not report mount ID")
    return StatxResult(
        device=os.makedev(result.dev_major, result.dev_minor),
        inode=int(result.inode),
        mode=int(result.mode),
        mount_id=int(result.mount_id),
    )


def clone_mount(source_fd: int, *, recursive: bool = False) -> int:
    """Clone exact pinned object into detached mount object; no pathname source."""
    _, _, open_tree_number, _, _ = _syscalls()
    flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH
    if recursive:
        flags |= getattr(os, "AT_RECURSIVE", 0x8000)
    result = _libc.syscall(
        open_tree_number,
        ctypes.c_int(source_fd),
        ctypes.c_char_p(b""),
        ctypes.c_uint(flags),
    )
    if result == -1:
        _raise_syscall("open_tree", f"flags=0x{flags:x}")
    return int(result)


def make_mount_read_only(mount_fd: int) -> None:
    """Set MOUNT_ATTR_RDONLY on detached mount before attaching it."""
    _, _, _, _, mount_setattr_number = _syscalls()
    attributes = _MountAttr(attr_set=MOUNT_ATTR_RDONLY, attr_clr=0, propagation=0, userns_fd=0)
    result = _libc.syscall(
        mount_setattr_number,
        ctypes.c_int(mount_fd),
        ctypes.c_char_p(b""),
        ctypes.c_uint(AT_EMPTY_PATH),
        ctypes.byref(attributes),
        ctypes.sizeof(attributes),
    )
    if result == -1:
        _raise_syscall(
            "mount_setattr", f"flags=0x{AT_EMPTY_PATH:x},attr_set=0x{MOUNT_ATTR_RDONLY:x}"
        )


def attach_mount(mount_fd: int, target: bytes) -> None:
    """Attach detached mount to trusted staging target. Source stays descriptor-only."""
    _, _, _, move_mount_number, _ = _syscalls()
    result = _libc.syscall(
        move_mount_number,
        ctypes.c_int(mount_fd),
        ctypes.c_char_p(b""),
        ctypes.c_int(-100),
        ctypes.c_char_p(target),
        ctypes.c_uint(MOVE_MOUNT_F_EMPTY_PATH),
    )
    if result == -1:
        _raise_syscall("move_mount", f"flags=0x{MOVE_MOUNT_F_EMPTY_PATH:x}")


def make_private_mount_namespace() -> None:
    """Stop propagation from test namespace before creating staging mounts."""
    if _libc.mount(None, ctypes.c_char_p(b"/"), None, MS_REC | MS_PRIVATE, None) == -1:
        _raise_syscall("mount", f"flags=0x{MS_REC | MS_PRIVATE:x}")


def mount_tmpfs(target: bytes) -> None:
    """Create private staging filesystem in current private mount namespace."""
    if (
        _libc.mount(
            ctypes.c_char_p(b"tmpfs"),
            ctypes.c_char_p(target),
            ctypes.c_char_p(b"tmpfs"),
            0,
            ctypes.c_char_p(b"mode=0700"),
        )
        == -1
    ):
        _raise_syscall("mount", "flags=0x0,fstype=tmpfs")


def detach_mount(target: bytes) -> None:
    if _libc.umount2(ctypes.c_char_p(target), MNT_DETACH) == -1:
        _raise_syscall("umount2", f"flags=0x{MNT_DETACH:x}")


def filesystem_magic(fd: int) -> int:
    """Return f_type for descriptor's mounted filesystem."""
    result = _StatFs()
    if _libc.fstatfs(fd, ctypes.byref(result)) == -1:
        _raise_syscall("fstatfs", "flags=0x0")
    return int(result.filesystem_type) & 0xFFFFFFFF


def is_autofs(filesystem_type: int) -> bool:
    return filesystem_type == _AUTOFS_SUPER_MAGIC
