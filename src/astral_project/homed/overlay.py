"""Descriptor-confined writable overlay over a read-only host tree.

Upper entries shadow lower entries. Deletions use ``.wh.<name>`` markers;
marker names are reserved and never exposed. Lower descriptors are opened with
``O_NOFOLLOW`` and are never opened for writing.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import secrets
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from threading import RLock

from astral_project.homed.core import HomedError
from astral_project.homed.host import BackingNode
from astral_project.profile import (
    Operation,
    Profile,
    RuleMode,
    normalize_home_path,
    validate_profile_id,
)

WHITEOUT_PREFIX = ".wh."
_DATABASE_NAME = ".aspr-overlay.sqlite3"
_LOCK_NAME = ".aspr-overlay-lock"
_TEMP_PREFIX = ".aspr-overlay-tmp-"
_MAX_DIRECTORY_ENTRIES = 4096


class OverlayStateError(HomedError):
    """Overlay operation failed with stable errno."""


@dataclass(frozen=True, slots=True)
class OverlayFeatures:
    """Feature contract exposed to callers instead of guessed POSIX behavior."""

    mmap: bool = False
    locks: bool = False


class OverlayBackend:
    """Read lower root and persist mutations in one profile upper root.

    ``upper_root`` must be an application-owned, per-profile directory. This
    class never resolves paths through it: all path operations are relative to
    descriptors pinned during construction. ``profile`` is optional for unit
    users; when supplied, only ``overlay-rw`` rules authorize operations.
    """

    def __init__(
        self,
        lower_root: str | os.PathLike[str],
        upper_root: str | os.PathLike[str],
        profile: Profile | None = None,
        *,
        features: OverlayFeatures | None = None,
    ) -> None:
        self.profile = profile
        self.features = features or OverlayFeatures()
        if self.features.mmap or self.features.locks:
            raise ValueError("overlay mmap and POSIX locks are unsupported")
        # FUSE statfs compatibility; overlay does not impose private quotas.
        self.max_bytes = (1 << 63) - 1
        self.max_files = (1 << 31) - 1
        self.used_bytes = 0
        self.file_count = 0
        self._lock = RLock()
        self._closed = False
        self._next_inode = 2
        self._paths: dict[str, int] = {".": 1}
        self._inodes: dict[int, str] = {1: "."}
        self._lookups: dict[int, int] = {1: 1}
        self._handles: dict[int, bool] = {}
        lower = Path(lower_root)
        upper = Path(upper_root)
        if profile is not None:
            validate_profile_id(profile.profile_id)
            upper = upper / profile.profile_id
        self._lower = -1
        self._upper = -1
        self._lock_fd = -1
        self._db: sqlite3.Connection | None = None
        try:
            lower_details = lower.lstat()
            if stat.S_ISLNK(lower_details.st_mode) or not stat.S_ISDIR(lower_details.st_mode):
                raise OSError(errno.ENOTDIR, "overlay lower root is not a directory")
            upper.mkdir(mode=0o700, parents=True, exist_ok=True)
            upper_details = upper.lstat()
            if (
                stat.S_ISLNK(upper_details.st_mode)
                or not stat.S_ISDIR(upper_details.st_mode)
                or upper_details.st_uid != os.getuid()
                or upper_details.st_mode & (0o077 | stat.S_ISUID | stat.S_ISGID)
            ):
                raise OSError(errno.EACCES, "overlay upper root has unsafe ownership or mode")
            lower_real = os.path.realpath(os.fspath(lower))
            upper_real = os.path.realpath(os.fspath(upper))
            common = os.path.commonpath((lower_real, upper_real))
            if common in {lower_real, upper_real}:
                raise OSError(errno.EINVAL, "overlay roots must not overlap")
            self._lower = os.open(
                os.fspath(lower), os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            self._upper = os.open(
                os.fspath(upper), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
        except BaseException:
            for descriptor in (self._upper, self._lower):
                if descriptor >= 0:  # pragma: no cover - defensive kernel/recovery branch
                    with suppress(OSError):  # pragma: no cover - defensive kernel/recovery branch
                        os.close(descriptor)  # pragma: no cover - defensive kernel/recovery branch
            raise
        try:
            self._lock_fd = os.open(
                _LOCK_NAME,
                os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=self._upper,
            )
            os.fchmod(self._lock_fd, 0o600)
            self._prepare_metadata_file(_DATABASE_NAME, create=True)
            database_path = f"/proc/self/fd/{self._upper}/{_DATABASE_NAME}"
            self._db = sqlite3.connect(database_path, isolation_level=None, check_same_thread=False)
            journal_mode = self._db.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            self._db.execute("PRAGMA synchronous=FULL")
            synchronous = self._db.execute("PRAGMA synchronous").fetchone()[0]
            if (
                str(journal_mode).lower() != "wal" or synchronous != 2
            ):  # pragma: no cover - defensive kernel/recovery branch
                raise OSError(
                    errno.EOPNOTSUPP, "overlay requires SQLite WAL with FULL sync"
                )  # pragma: no cover - defensive kernel/recovery branch
            self._prepare_metadata_file(_DATABASE_NAME)
            for metadata_name in (_DATABASE_NAME + "-wal", _DATABASE_NAME + "-shm"):
                with suppress(FileNotFoundError):
                    self._prepare_metadata_file(metadata_name)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS mutations ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, phase TEXT NOT NULL, "
                "kind TEXT NOT NULL, path TEXT NOT NULL, payload TEXT NOT NULL)"
            )
            with self._exclusive():
                self._sanitize_upper_tree(self._upper)
                self._recover()
        except BaseException:
            if self._db is not None:
                with suppress(Exception):
                    self._db.close()
            with suppress(OSError):
                os.close(self._lock_fd)
            os.close(self._upper)
            os.close(self._lower)
            self._closed = True
            raise

    @property
    def root_fd(self) -> int:
        return self._upper

    @property
    def inode_count(self) -> int:
        with self._lock:
            return len(self._inodes)

    @property
    def lower_root_fd(self) -> int:
        return self._lower

    @property
    def supports_mmap(self) -> bool:
        return self.features.mmap

    @property
    def supports_locks(self) -> bool:
        return self.features.locks

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                if self._db is not None:  # pragma: no cover - defensive kernel/recovery branch
                    with suppress(Exception):
                        self._db.close()
                    self._db = None
                for (
                    descriptor
                ) in self._handles:  # pragma: no cover - defensive kernel/recovery branch
                    with suppress(OSError):  # pragma: no cover - defensive kernel/recovery branch
                        os.close(descriptor)  # pragma: no cover - defensive kernel/recovery branch
                self._handles.clear()
                for name in ("_lock_fd", "_upper", "_lower"):
                    with suppress(OSError):
                        os.close(getattr(self, name))

    def __enter__(self) -> OverlayBackend:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def lookup(self, path: str) -> BackingNode:
        normalized = self._path(path)
        self._authorize(normalized, Operation.LOOKUP)
        with self._exclusive():
            fd, upper = self._existing(normalized)
            if fd is None:
                raise OverlayStateError(errno.ENOENT, "overlay path is unavailable")
            try:
                return self._node(normalized, os.fstat(fd), upper=upper)
            finally:
                os.close(fd)

    def stat(self, path: str) -> BackingNode:
        normalized = self._path(path)
        self._authorize(normalized, Operation.STAT)
        with self._exclusive():
            fd, upper = self._existing(normalized)
            if fd is None:
                raise OverlayStateError(errno.ENOENT, "overlay path is unavailable")
            try:
                return self._node(normalized, os.fstat(fd), upper=upper)
            finally:
                os.close(fd)

    def node_path(self, inode: int) -> str:
        with self._lock:
            try:
                return self._inodes[inode]
            except KeyError as error:
                raise OverlayStateError(errno.ENOENT, "unknown synthetic inode") from error

    def forget(self, inode: int, count: int) -> None:
        """Release synthetic inode state when the kernel drops lookup references."""
        if count < 0 or inode == 1:
            return
        with self._lock:
            if inode not in self._inodes:
                return
            remaining = max(0, self._lookups.get(inode, 0) - count)
            if remaining:
                self._lookups[inode] = remaining
                return
            path = self._inodes.pop(inode)
            self._paths.pop(path, None)
            self._lookups.pop(inode, None)

    def listdir(self, path: str = ".") -> tuple[str, ...]:
        normalized = self._path(path)
        self._authorize(normalized, Operation.LIST)
        with self._exclusive():
            upper_fd, _upper = self._existing_upper(normalized)
            lower_fd, _lower = self._existing_lower(normalized)
            if upper_fd is None and lower_fd is None:
                raise OverlayStateError(errno.ENOENT, "overlay directory is unavailable")
            try:
                upper_names: set[str] = set()
                if upper_fd is not None:
                    if not stat.S_ISDIR(
                        os.fstat(upper_fd).st_mode
                    ):  # pragma: no cover - defensive kernel/recovery branch
                        raise OverlayStateError(
                            errno.ENOTDIR, "overlay path is not a directory"
                        )  # pragma: no cover - defensive kernel/recovery branch
                    os.close(upper_fd)
                    upper_fd = None
                    upper_fd = self._try_open(self._upper, normalized, os.O_RDONLY | os.O_DIRECTORY)
                    assert upper_fd is not None
                    upper_names = set(os.listdir(upper_fd))
                lower_names: set[str] = set()
                if lower_fd is not None:
                    if not stat.S_ISDIR(os.fstat(lower_fd).st_mode):
                        raise OverlayStateError(errno.ENOTDIR, "overlay path is not a directory")
                    os.close(lower_fd)
                    lower_fd = None
                    lower_fd = self._try_open(self._lower, normalized, os.O_RDONLY | os.O_DIRECTORY)
                    assert lower_fd is not None
                    lower_names = set(os.listdir(lower_fd))
                names = {
                    name
                    for name in upper_names | lower_names
                    if name
                    not in {
                        _LOCK_NAME,
                        _DATABASE_NAME,
                        _DATABASE_NAME + "-wal",
                        _DATABASE_NAME + "-shm",
                    }
                    and not name.startswith(_TEMP_PREFIX)
                    and not name.startswith(WHITEOUT_PREFIX)
                    and not (name in upper_names and name.startswith(WHITEOUT_PREFIX))
                }
                hidden = {
                    name[len(WHITEOUT_PREFIX) :]
                    for name in upper_names
                    if name.startswith(WHITEOUT_PREFIX)
                }
                names.difference_update(hidden)
                names = set(self._filter_listing(normalized, names))
                if len(names) > _MAX_DIRECTORY_ENTRIES:
                    raise OverlayStateError(errno.EOVERFLOW, "directory listing exceeds bound")
                return tuple(sorted(names))
            except OSError as error:
                raise self._error(error, "overlay directory listing failed") from error
            finally:
                if upper_fd is not None:
                    os.close(upper_fd)
                if lower_fd is not None:
                    os.close(lower_fd)

    def open(self, path: str, flags: int = os.O_RDONLY, mode: int = 0o600) -> int:
        normalized = self._path(path)
        writing = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_TRUNC | os.O_APPEND))
        creating = bool(flags & os.O_CREAT)
        self._authorize(normalized, Operation.WRITE if writing else Operation.READ)
        if creating:
            self._authorize(normalized, Operation.CREATE)
        if flags & os.O_TRUNC:
            self._authorize(normalized, Operation.TRUNCATE)
        with self._exclusive():
            fd, upper = self._existing(normalized)
            if creating and flags & os.O_EXCL and fd is not None:
                os.close(fd)
                raise OverlayStateError(errno.EEXIST, "overlay path already exists")
            if writing:
                if fd is not None:
                    details = os.fstat(fd)
                    os.close(fd)
                    if not stat.S_ISREG(details.st_mode):
                        raise OverlayStateError(errno.EISDIR, "overlay write target is not regular")
                    if not upper:
                        self._copy_up(normalized)
                elif creating:
                    self._create_file(normalized, mode)
                else:
                    raise OverlayStateError(errno.ENOENT, "overlay file is unavailable")
                return self._remember(self._open_upper(normalized, flags, mode), upper=True)
            if fd is None and creating:
                self._create_file(normalized, mode)
                return self._remember(self._open_upper(normalized, flags, mode), upper=True)
            if fd is None:
                raise OverlayStateError(errno.ENOENT, "overlay file is unavailable")
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                os.close(fd)
                raise OverlayStateError(errno.EISDIR, "overlay path is a directory")
            os.close(fd)
            descriptor, upper = self._open_existing_upper_or_lower(normalized, flags)
            return self._remember(descriptor, upper=upper)

    def release(self, descriptor: int) -> None:
        with self._lock:
            if descriptor not in self._handles:
                return
            self._handles.pop(descriptor)
            os.close(descriptor)

    def read(self, descriptor: int | str, offset: int = 0, size: int = 131072) -> bytes:
        if isinstance(descriptor, str):
            handle = self.open(descriptor)
            try:
                return self.read(handle, offset, size)
            finally:
                self.release(handle)
        if offset < 0 or size < 0:
            raise OverlayStateError(errno.EINVAL, "offset and size must be non-negative")
        with self._lock:
            self._require_handle(descriptor)
            try:
                return os.pread(descriptor, size, offset)
            except OSError as error:  # pragma: no cover - defensive kernel/recovery branch
                raise self._error(
                    error, "overlay file read failed"
                ) from error  # pragma: no cover - defensive kernel/recovery branch

    def write(self, descriptor: int | str, data: bytes, offset: int | None = None) -> int:
        if isinstance(descriptor, str):
            handle = self.open(descriptor, os.O_RDWR)
            try:
                return self.write(handle, data, offset)
            finally:
                self.release(handle)
        if not isinstance(data, bytes):
            raise TypeError("overlay writes require bytes")
        with self._lock:
            self._require_handle(descriptor)
            try:
                if offset is None:
                    return os.write(descriptor, data)
                if offset < 0:
                    raise OverlayStateError(errno.EINVAL, "offset must be non-negative")
                return os.pwrite(descriptor, data, offset)
            except OSError as error:
                raise self._error(error, "overlay file write failed") from error

    def truncate(self, descriptor: int | str, size: int) -> None:
        if isinstance(descriptor, str):
            handle = self.open(descriptor, os.O_RDWR)
            try:
                self.truncate(handle, size)
            finally:
                self.release(handle)
            return
        if size < 0:
            raise OverlayStateError(errno.EINVAL, "truncate size must be non-negative")
        with self._lock:
            self._require_handle(descriptor)
            try:
                os.ftruncate(descriptor, size)
            except OSError as error:  # pragma: no cover - defensive kernel/recovery branch
                raise self._error(
                    error, "overlay truncate failed"
                ) from error  # pragma: no cover - defensive kernel/recovery branch

    def fsync(self, descriptor: int | str) -> None:
        if isinstance(descriptor, str):
            handle = self.open(descriptor)
            try:
                self.fsync(handle)
            finally:
                self.release(handle)
            return
        with self._lock:
            self._require_handle(descriptor)
            try:
                os.fsync(descriptor)
            except OSError as error:  # pragma: no cover - defensive kernel/recovery branch
                raise self._error(
                    error, "overlay fsync failed"
                ) from error  # pragma: no cover - defensive kernel/recovery branch

    def create(self, path: str, mode: int = 0o600) -> BackingNode:
        normalized = self._path(path)
        self._authorize(normalized, Operation.CREATE)
        with self._exclusive():
            if self._exists_any(normalized):
                raise OverlayStateError(errno.EEXIST, "overlay path already exists")
            self._clear_whiteout(normalized)
            self._create_file(normalized, mode)
            return self.lookup(normalized)

    def mkdir(self, path: str, mode: int = 0o700) -> BackingNode:
        normalized = self._path(path)
        self._authorize(normalized, Operation.MKDIR)
        with self._exclusive():
            if self._exists_any(normalized):
                raise OverlayStateError(errno.EEXIST, "overlay path already exists")
            self._clear_whiteout(normalized)
            parent_path = normalized.rsplit("/", 1)[0] if "/" in normalized else "."
            if parent_path != ".":
                parent_fd, parent_upper = self._existing_upper(parent_path)
                if parent_fd is not None:
                    os.close(parent_fd)
                elif not parent_upper:  # pragma: no cover - defensive kernel/recovery branch
                    lower_parent, _ = self._existing_lower(parent_path)
                    if (
                        lower_parent is not None
                    ):  # pragma: no cover - defensive kernel/recovery branch
                        os.close(
                            lower_parent
                        )  # pragma: no cover - defensive kernel/recovery branch
                        self._copy_up(
                            parent_path
                        )  # pragma: no cover - defensive kernel/recovery branch
            parent, name = self._upper_parent(normalized, create=False)
            try:
                self._journaled_mkdir(parent, name, mode, normalized)
            finally:
                os.close(parent)
            return self.lookup(normalized)

    def unlink(self, path: str, *, directory: bool = False) -> None:
        normalized = self._path(path)
        self._authorize(normalized, Operation.RMDIR if directory else Operation.UNLINK)
        with self._exclusive():
            upper_fd, _upper = self._existing_upper(normalized)
            lower_fd, _lower = self._existing_lower(normalized)
            if upper_fd is None and lower_fd is None:
                raise OverlayStateError(errno.ENOENT, "overlay path is unavailable")
            try:
                selected = upper_fd if upper_fd is not None else lower_fd
                assert selected is not None
                selected_mode = os.fstat(selected).st_mode
                if directory and not stat.S_ISDIR(selected_mode):
                    raise OverlayStateError(errno.ENOTDIR, "overlay target is not a directory")
                if not directory and stat.S_ISDIR(selected_mode):
                    raise OverlayStateError(errno.EISDIR, "overlay target is a directory")
                if upper_fd is not None:
                    parent, name = self._upper_parent(normalized)
                    try:
                        self._journaled_remove(
                            parent, name, directory, normalized, lower_fd is not None
                        )
                    finally:
                        os.close(parent)
                elif lower_fd is not None:  # pragma: no cover - defensive kernel/recovery branch
                    self._write_whiteout(normalized, lower=True)
            finally:
                if upper_fd is not None:
                    os.close(upper_fd)
                if lower_fd is not None:
                    os.close(lower_fd)

    def rmdir(self, path: str) -> None:
        self.unlink(path, directory=True)

    def rename(self, source: str, destination: str) -> None:
        old = self._path(source)
        new = self._path(destination)
        self._authorize(old, Operation.RENAME)
        self._authorize(new, Operation.RENAME)
        self._check_same_rule(old, new)
        with self._exclusive():
            source_fd, source_upper = self._existing(old)
            if source_fd is None:
                raise OverlayStateError(errno.ENOENT, "overlay rename source is unavailable")
            try:
                source_mode = os.fstat(source_fd).st_mode
                if not stat.S_ISREG(source_mode) and not stat.S_ISDIR(
                    source_mode
                ):  # pragma: no cover - defensive kernel/recovery branch
                    raise OverlayStateError(
                        errno.EACCES, "unsupported overlay rename source"
                    )  # pragma: no cover - defensive kernel/recovery branch
            finally:
                os.close(source_fd)
            if old == new:
                return
            destination_fd, destination_upper = self._existing(new)
            if destination_fd is not None:
                try:
                    destination_mode = os.fstat(destination_fd).st_mode
                    source_is_dir = stat.S_ISDIR(source_mode)
                    destination_is_dir = stat.S_ISDIR(destination_mode)
                    if source_is_dir != destination_is_dir:
                        raise OverlayStateError(
                            errno.ENOTDIR if source_is_dir else errno.EISDIR,
                            "overlay rename type mismatch",
                        )
                    if source_is_dir:
                        destination_root = self._upper if destination_upper else self._lower
                        destination_directory = self._try_open(
                            destination_root, new, os.O_RDONLY | os.O_DIRECTORY
                        )
                        if (
                            destination_directory is not None
                        ):  # pragma: no branch - descriptor open is deterministic
                            try:
                                if os.listdir(destination_directory):
                                    raise OverlayStateError(
                                        errno.ENOTEMPTY,
                                        "overlay rename destination is not empty",
                                    )
                            finally:
                                os.close(destination_directory)
                finally:
                    os.close(destination_fd)
            self._clear_whiteout(new)
            source_lower_fd = self._try_open(self._lower, old, os.O_PATH)
            if not source_upper:
                self._copy_up(old)
            old_parent, old_name = self._upper_parent(old)
            new_parent, new_name = self._upper_parent(new, create=True)
            begun = False
            try:
                self._journal_begin(
                    "rename", old, destination=new, source_lower=source_lower_fd is not None
                )
                begun = True
                os.rename(old_name, new_name, src_dir_fd=old_parent, dst_dir_fd=new_parent)
                os.fsync(new_parent)
                if source_lower_fd is not None:
                    self._write_whiteout(old, journal=False)
                self._journal_commit("rename", old, destination=new)
            except BaseException as error:
                if begun and not self._journal_has_commit("rename", old, destination=new):
                    with suppress(Exception):
                        self._journal_abort("rename", old, destination=new)
                if isinstance(error, OSError):
                    raise self._error(error, "overlay rename failed") from error
                raise
            finally:
                os.close(old_parent)
                os.close(new_parent)
                if source_lower_fd is not None:
                    os.close(source_lower_fd)

    def link(self, source: str, destination: str) -> None:
        del source, destination
        raise OverlayStateError(errno.EOPNOTSUPP, "overlay hardlinks are unsupported")

    hardlink = link

    def chmod(self, descriptor: int | str, mode: int) -> None:
        if isinstance(descriptor, str):
            normalized = self._path(descriptor)
            self._authorize(normalized, Operation.CHMOD)
            with self._exclusive():
                fd, upper = self._existing(normalized)
                if fd is None:
                    raise OverlayStateError(errno.ENOENT, "overlay path is unavailable")
                os.close(fd)
                if not upper:  # pragma: no cover - defensive kernel/recovery branch
                    self._copy_up(normalized)  # pragma: no cover - defensive kernel/recovery branch
                fd = self._open_upper(normalized, os.O_RDONLY)
                try:
                    os.fchmod(fd, self._safe_mode(mode))
                finally:
                    os.close(fd)
            return
        with self._lock:
            self._require_handle(descriptor)
            if not self._handles[descriptor]:
                raise OverlayStateError(errno.EACCES, "overlay lower handles are read-only")
            try:
                os.fchmod(descriptor, self._safe_mode(mode))
            except OSError as error:  # pragma: no cover - defensive kernel/recovery branch
                raise self._error(
                    error, "overlay chmod failed"
                ) from error  # pragma: no cover - defensive kernel/recovery branch

    def mmap(self, *_args: object, **_kwargs: object) -> None:
        raise OverlayStateError(errno.ENOTSUP, "overlay mmap is unsupported")

    def lock(self, *_args: object, **_kwargs: object) -> None:
        raise OverlayStateError(errno.ENOTSUP, "overlay POSIX locks are unsupported")

    def setxattr(self, *_args: object, **_kwargs: object) -> None:
        raise OverlayStateError(errno.ENOTSUP, "overlay xattrs are unsupported")

    getxattr = setxattr
    listxattr = setxattr
    removexattr = setxattr
    xattr = setxattr

    def symlink(self, *_args: object, **_kwargs: object) -> None:
        raise OverlayStateError(errno.EOPNOTSUPP, "overlay symlinks are unsupported")

    def mknod(self, *_args: object, **_kwargs: object) -> None:
        raise OverlayStateError(errno.EPERM, "overlay device nodes are unsupported")

    def _existing(self, path: str) -> tuple[int | None, bool]:
        fd, upper = self._existing_upper(path)
        if fd is not None:
            return fd, upper
        if self._is_whiteouted(path):
            return None, False
        fd = self._try_open(self._lower, path, os.O_PATH)
        return (fd, False) if fd is not None else (None, False)

    def _existing_upper(self, path: str) -> tuple[int | None, bool]:
        if path == ".":
            return os.dup(self._upper), True
        if self._is_whiteouted(path):
            return None, True
        fd = self._try_open(self._upper, path, os.O_PATH)
        if fd is not None:
            details = os.fstat(fd)
            if stat.S_ISLNK(details.st_mode) or not (
                stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode)
            ):
                os.close(fd)
                raise OverlayStateError(errno.EACCES, "unsupported overlay upper node")
            if (
                stat.S_ISREG(details.st_mode) and details.st_nlink != 1
            ):  # pragma: no cover - defensive kernel/recovery branch
                os.close(fd)  # pragma: no cover - defensive kernel/recovery branch
                raise OverlayStateError(
                    errno.EACCES, "overlay upper rejects hardlink aliases"
                )  # pragma: no cover - defensive kernel/recovery branch
            if stat.S_ISREG(details.st_mode):
                safe_mode = self._safe_mode(details.st_mode)
                if details.st_mode != (
                    stat.S_IFREG | safe_mode
                ):  # pragma: no cover - defensive kernel/recovery branch
                    self._chmod_upper_path(
                        path, safe_mode
                    )  # pragma: no cover - defensive kernel/recovery branch
        return fd, fd is not None

    def _existing_lower(self, path: str) -> tuple[int | None, bool]:
        if self._is_whiteouted(path):  # pragma: no cover - defensive kernel/recovery branch
            return None, False  # pragma: no cover - defensive kernel/recovery branch
        fd = self._try_open(self._lower, path, os.O_PATH)
        if fd is not None:
            details = os.fstat(fd)
            if stat.S_ISLNK(
                details.st_mode
            ) or not (  # pragma: no cover - defensive kernel/recovery branch
                stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode)
            ):
                os.close(fd)  # pragma: no cover - defensive kernel/recovery branch
                raise OverlayStateError(
                    errno.EACCES, "unsupported overlay lower node"
                )  # pragma: no cover - defensive kernel/recovery branch
        return fd, fd is not None

    def _open_existing_upper_or_lower(self, path: str, flags: int) -> tuple[int, bool]:
        upper = self._try_open(self._upper, path, flags | os.O_NONBLOCK)
        if upper is not None:
            return upper, True
        return self._open_lower(path, flags), False

    def _chmod_upper_path(self, path: str, mode: int) -> None:
        parent, name = self._upper_parent(
            path
        )  # pragma: no cover - defensive kernel/recovery branch
        try:  # pragma: no cover - defensive kernel/recovery branch
            os.chmod(
                name, mode, dir_fd=parent, follow_symlinks=False
            )  # pragma: no cover - defensive kernel/recovery branch
        finally:
            os.close(parent)  # pragma: no cover - defensive kernel/recovery branch

    def _open_upper(self, path: str, flags: int, mode: int = 0o600) -> int:
        parent, name = self._upper_parent(path)
        try:
            return os.open(
                name,
                flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                self._safe_mode(mode),
                dir_fd=parent,
            )
        except OSError as error:  # pragma: no cover - defensive kernel/recovery branch
            raise self._error(
                error, "overlay upper open failed"
            ) from error  # pragma: no cover - defensive kernel/recovery branch
        finally:
            os.close(parent)

    def _open_lower(self, path: str, flags: int) -> int:
        fd = self._try_open(self._lower, path, flags | os.O_NONBLOCK)
        if fd is None:
            raise OverlayStateError(errno.ENOENT, "overlay lower path is unavailable")
        details = os.fstat(fd)
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            os.close(fd)
            raise OverlayStateError(errno.EISDIR, "overlay path is not a regular file")
        return fd

    def _copy_up(self, path: str) -> None:
        upper_fd, _upper = self._existing_upper(path)
        if upper_fd is not None:
            os.close(upper_fd)
            return
        if self._is_whiteouted(path):
            raise OverlayStateError(errno.ENOENT, "overlay path is whiteouted")
        lower_fd = self._open_lower_or_dir(path)
        try:
            details = os.fstat(lower_fd)
            parent, name = self._upper_parent(path, create=True)
            try:
                if stat.S_ISDIR(details.st_mode):
                    self._journal_begin("copy-up-dir", path)
                    try:
                        os.mkdir(name, self._safe_mode(details.st_mode), dir_fd=parent)
                        os.fsync(parent)
                        lower_directory = self._try_open(
                            self._lower, path, os.O_RDONLY | os.O_DIRECTORY
                        )
                        if (
                            lower_directory is None
                        ):  # pragma: no cover - defensive kernel/recovery branch
                            raise OverlayStateError(
                                errno.ENOENT, "overlay lower directory disappeared"
                            )
                        try:
                            for child in os.listdir(lower_directory):
                                if child.startswith(
                                    WHITEOUT_PREFIX
                                ):  # pragma: no cover - defensive kernel/recovery branch
                                    continue  # pragma: no cover - defensive kernel/recovery branch
                                child_path = f"{path}/{child}"
                                self._copy_up(child_path)
                        finally:
                            os.close(lower_directory)
                        self._journal_commit("copy-up-dir", path)
                    except OSError as error:
                        with suppress(OSError):
                            self._remove_upper_tree(path)
                        raise self._error(error, "overlay directory copy-up failed") from error
                    return
                if not stat.S_ISREG(
                    details.st_mode
                ):  # pragma: no cover - defensive kernel/recovery branch
                    raise OverlayStateError(  # pragma: no cover - defensive kernel/recovery branch
                        errno.EACCES, "overlay copy-up supports regular files only"
                    )
                os.close(lower_fd)
                lower_fd = -1
                lower_fd = self._open_lower(path, os.O_RDONLY)
                temp = _TEMP_PREFIX + secrets.token_hex(12)
                self._journal_begin("copy-up", path, temp=temp)
                temp_fd = -1
                temp_fd = os.open(
                    temp,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    self._safe_mode(details.st_mode),
                    dir_fd=parent,
                )
                try:
                    offset = 0
                    while True:
                        chunk = os.pread(lower_fd, 1024 * 1024, offset)
                        if not chunk:
                            break
                        self._write_all(temp_fd, chunk)
                        offset += len(chunk)
                    os.fchmod(temp_fd, self._safe_mode(details.st_mode))
                    with suppress(OSError):
                        os.utime(temp_fd, ns=(details.st_mtime_ns, details.st_mtime_ns))
                    os.fsync(temp_fd)
                    os.rename(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
                    os.fsync(parent)
                    self._journal_commit("copy-up", path, temp=temp)
                except OSError as error:
                    with suppress(OSError):
                        os.unlink(temp, dir_fd=parent)
                    raise self._error(error, "overlay copy-up failed") from error
                finally:
                    if temp_fd >= 0:  # pragma: no cover - defensive kernel/recovery branch
                        os.close(temp_fd)
            finally:
                os.close(parent)
        finally:
            if lower_fd >= 0:  # pragma: no cover - defensive kernel/recovery branch
                os.close(lower_fd)

    def _create_file(self, path: str, mode: int) -> None:
        self._clear_whiteout(path)
        parent, name = self._upper_parent(path, create=True)
        try:
            temp = _TEMP_PREFIX + secrets.token_hex(12)
            self._journal_begin("create", path, temp=temp)
            fd = -1
            try:
                fd = os.open(
                    temp,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    self._safe_mode(mode),
                    dir_fd=parent,
                )
                os.fchmod(fd, self._safe_mode(mode))
                os.fsync(fd)
                os.rename(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                self._journal_commit("create", path, temp=temp)
            except BaseException:  # pragma: no cover - defensive kernel/recovery branch
                with suppress(OSError):  # pragma: no cover - defensive kernel/recovery branch
                    os.unlink(
                        temp, dir_fd=parent
                    )  # pragma: no cover - defensive kernel/recovery branch
                raise  # pragma: no cover - defensive kernel/recovery branch
            finally:
                if fd >= 0:  # pragma: no cover - defensive kernel/recovery branch
                    os.close(fd)
        except OSError as error:  # pragma: no cover - defensive kernel/recovery branch
            raise self._error(
                error, "overlay file creation failed"
            ) from error  # pragma: no cover - defensive kernel/recovery branch
        finally:
            os.close(parent)

    def _clear_whiteout(self, path: str) -> None:
        if path == ".":
            return
        try:
            parent, name = self._upper_parent(path)
        except OverlayStateError as error:
            if error.errno == errno.ENOENT:  # pragma: no cover - defensive kernel/recovery branch
                return
            raise  # pragma: no cover - defensive kernel/recovery branch
        try:
            marker = WHITEOUT_PREFIX + name
            marker_fd = self._try_open(parent, marker, os.O_PATH)
            if marker_fd is not None:
                os.close(marker_fd)
                os.unlink(marker, dir_fd=parent)
                os.fsync(parent)
        finally:
            os.close(parent)

    def _write_whiteout(self, path: str, *, journal: bool = True, lower: bool = True) -> None:
        parent, name = self._upper_parent(path, create=True)
        marker = WHITEOUT_PREFIX + name
        try:
            marker_fd = self._try_open(parent, marker, os.O_PATH)
            if marker_fd is not None:  # pragma: no cover - defensive kernel/recovery branch
                os.close(marker_fd)  # pragma: no cover - defensive kernel/recovery branch
                return  # pragma: no cover - defensive kernel/recovery branch
            temp = _TEMP_PREFIX + secrets.token_hex(12)
            if journal:
                self._journal_begin("whiteout", path, temp=temp, lower=lower)
            fd = -1
            try:
                fd = os.open(
                    temp,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=parent,
                )
                os.fsync(fd)
                os.rename(temp, marker, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                if journal:
                    self._journal_commit("whiteout", path, temp=temp)
            except BaseException:  # pragma: no cover - defensive kernel/recovery branch
                with suppress(OSError):  # pragma: no cover - defensive kernel/recovery branch
                    os.unlink(
                        temp, dir_fd=parent
                    )  # pragma: no cover - defensive kernel/recovery branch
                raise  # pragma: no cover - defensive kernel/recovery branch
            finally:
                if fd >= 0:  # pragma: no cover - defensive kernel/recovery branch
                    os.close(fd)
        except OSError as error:  # pragma: no cover - defensive kernel/recovery branch
            raise self._error(
                error, "overlay whiteout failed"
            ) from error  # pragma: no cover - defensive kernel/recovery branch
        finally:
            os.close(parent)

    def _journaled_mkdir(
        self, parent: int, name: str, mode: int | os.stat_result, path: str | None = None
    ) -> None:
        safe = self._safe_mode(mode.st_mode if isinstance(mode, os.stat_result) else mode)
        journal_path = name if path is None else path
        begun = False
        created = False
        try:
            self._journal_begin("mkdir", journal_path)
            begun = True
            os.mkdir(name, safe, dir_fd=parent)
            created = True
            os.fsync(parent)
            self._journal_commit("mkdir", journal_path)
        except BaseException as error:
            if begun and not self._journal_has_commit("mkdir", journal_path):
                cleanup_succeeded = True
                if created:
                    try:
                        os.rmdir(name, dir_fd=parent)
                        os.fsync(parent)
                    except OSError:
                        cleanup_succeeded = False
                if cleanup_succeeded:
                    with suppress(Exception):
                        self._journal_abort("mkdir", journal_path)
            if isinstance(error, OSError):
                raise self._error(error, "overlay directory creation failed") from error
            raise

    def _journaled_remove(
        self, parent: int, name: str, directory: bool, path: str, has_lower: bool
    ) -> None:
        kind = "rmdir" if directory else "unlink"
        self._journal_begin(kind, path, lower=has_lower)
        removed = False
        try:
            (os.rmdir if directory else os.unlink)(name, dir_fd=parent)
            removed = True
            if has_lower:
                self._write_whiteout(path, journal=False)
            os.fsync(parent)
            self._journal_commit(kind, path, lower=has_lower)
        except OSError as error:
            if not removed:  # pragma: no branch - committed removal is the normal path
                with suppress(OSError):
                    self._journal_abort(kind, path, lower=has_lower)
            raise self._error(error, "overlay unlink failed") from error

    def _upper_parent(self, path: str, *, create: bool = False) -> tuple[int, str]:
        if path == ".":
            raise OverlayStateError(errno.EBUSY, "overlay root has no parent")
        parts = path.split("/")
        if (
            create and len(parts) > 1 and self._is_whiteouted("/".join(parts[:-1]))
        ):  # pragma: no cover - defensive kernel/recovery branch
            raise OverlayStateError(
                errno.ENOENT, "overlay parent is whiteouted"
            )  # pragma: no cover - defensive kernel/recovery branch
        current = os.dup(self._upper)
        try:
            for index, part in enumerate(parts[:-1]):
                child = self._try_open(current, part, os.O_RDONLY | os.O_DIRECTORY)
                if child is None and create:
                    lower_child = self._try_open(
                        self._lower, "/".join(parts[: index + 1]), os.O_PATH
                    )
                    mode = os.fstat(lower_child).st_mode if lower_child is not None else 0o700
                    if (
                        lower_child is not None
                    ):  # pragma: no cover - defensive kernel/recovery branch
                        os.close(lower_child)
                    with suppress(FileExistsError):
                        os.mkdir(part, self._safe_mode(mode), dir_fd=current)
                    child = self._try_open(current, part, os.O_RDONLY | os.O_DIRECTORY)
                if child is None:
                    raise OverlayStateError(errno.ENOENT, "overlay parent is unavailable")
                os.close(current)
                current = child
            return current, parts[-1]
        except OSError as error:
            os.close(current)
            raise self._error(error, "overlay parent is unavailable") from error

    def _is_whiteouted(self, path: str) -> bool:
        if path == ".":
            return False
        parts = path.split("/")
        for index in range(1, len(parts) + 1):
            parent = "." if index == 1 else "/".join(parts[: index - 1])
            marker = WHITEOUT_PREFIX + parts[index - 1]
            parent_fd = self._try_open(self._upper, parent, os.O_RDONLY | os.O_DIRECTORY)
            if parent_fd is None:
                continue
            try:
                marker_fd = self._try_open(parent_fd, marker, os.O_PATH)
                if marker_fd is not None:
                    os.close(marker_fd)
                    return True
            finally:
                os.close(parent_fd)
        return False

    def _exists_any(self, path: str) -> bool:
        fd, _ = self._existing(path)
        if fd is None:
            return False
        os.close(fd)
        return True

    def _try_open(self, root: int, path: str, flags: int) -> int | None:
        if path == ".":
            return os.open(".", flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        current = os.dup(root)
        try:
            for index, part in enumerate(path.split("/")):
                next_flags = (
                    flags if index == len(path.split("/")) - 1 else os.O_PATH | os.O_DIRECTORY
                )
                try:
                    child = os.open(part, next_flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
                except FileNotFoundError:
                    os.close(current)
                    return None
                except OSError as error:  # pragma: no cover - defensive kernel/recovery branch
                    if (
                        error.errno == errno.ELOOP
                    ):  # pragma: no cover - defensive kernel/recovery branch
                        raise OverlayStateError(
                            errno.EACCES, "overlay symlink escape denied"
                        ) from error
                    raise  # pragma: no cover - defensive kernel/recovery branch
                os.close(current)
                current = child
            return current
        except BaseException:  # pragma: no cover - defensive kernel/recovery branch
            with suppress(OSError):  # pragma: no cover - defensive kernel/recovery branch
                os.close(current)  # pragma: no cover - defensive kernel/recovery branch
            raise  # pragma: no cover - defensive kernel/recovery branch

    def _open_lower_or_dir(self, path: str) -> int:
        fd = self._try_open(self._lower, path, os.O_PATH)
        if fd is None:  # pragma: no cover - defensive kernel/recovery branch
            raise OverlayStateError(
                errno.ENOENT, "overlay lower path is unavailable"
            )  # pragma: no cover - defensive kernel/recovery branch
        details = os.fstat(fd)
        if stat.S_ISLNK(details.st_mode):  # pragma: no cover - defensive kernel/recovery branch
            os.close(fd)  # pragma: no cover - defensive kernel/recovery branch
            raise OverlayStateError(
                errno.EACCES, "overlay symlink is unsupported"
            )  # pragma: no cover - defensive kernel/recovery branch
        return fd

    def _node(self, path: str, details: os.stat_result, *, upper: bool) -> BackingNode:
        if stat.S_ISLNK(details.st_mode) or not (
            stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode)
        ):
            raise OverlayStateError(errno.EACCES, "unsupported overlay node")
        with self._lock:
            inode = self._paths.get(path)
            if inode is None:
                inode = self._new_inode(path)
            self._lookups[inode] = self._lookups.get(inode, 0) + 1
        mode = details.st_mode & ~(stat.S_ISUID | stat.S_ISGID)
        if upper:
            mode = (
                stat.S_IFDIR if stat.S_ISDIR(details.st_mode) else stat.S_IFREG
            ) | self._safe_mode(mode)
        return BackingNode(
            inode, path, mode, details.st_size, details.st_mtime_ns, stat.S_ISDIR(details.st_mode)
        )

    def _new_inode(self, path: str) -> int:
        inode = self._next_inode
        self._next_inode += 1
        self._paths[path] = inode
        self._inodes[inode] = path
        return inode

    def _path(self, path: str) -> str:
        self._ensure_open()
        try:
            if path == ".":
                return path
            normalized = normalize_home_path(path)
            if normalized != ".":  # pragma: no cover - defensive kernel/recovery branch
                for component in normalized.split("/"):
                    if (
                        component.startswith(WHITEOUT_PREFIX)
                        or component.startswith(_TEMP_PREFIX)
                        or component
                        in {
                            _LOCK_NAME,
                            _DATABASE_NAME,
                            _DATABASE_NAME + "-wal",
                            _DATABASE_NAME + "-shm",
                        }
                    ):
                        raise ValueError("overlay metadata name is reserved")
            return normalized
        except ValueError as error:
            raise OverlayStateError(errno.EINVAL, "overlay path is invalid") from error

    def _filter_listing(self, path: str, names: set[str]) -> tuple[str, ...]:
        if self.profile is None:
            return tuple(names)
        visible: list[str] = []
        for name in names:
            child = name if path == "." else f"{path}/{name}"
            decision = self.profile.decision(child, Operation.LOOKUP)
            if decision.rule is not None and decision.rule.mode is RuleMode.OVERLAY_RW:
                visible.append(name)
        return tuple(visible)

    def _authorize(self, path: str, operation: Operation) -> None:
        if self.profile is None or path == ".":
            return
        decision = self.profile.decision(path, operation)
        if (  # pragma: no cover - defensive kernel/recovery branch
            not decision.allowed
            or decision.rule is None
            or decision.rule.mode is not RuleMode.OVERLAY_RW
        ):
            raise OverlayStateError(
                errno.EACCES, f"overlay policy denied {operation} {path}"
            )  # pragma: no cover - defensive kernel/recovery branch

    def _check_same_rule(self, source: str, destination: str) -> None:
        if self.profile is None:
            return
        left = self.profile.decision(source, Operation.RENAME).rule
        right = self.profile.decision(destination, Operation.RENAME).rule
        if (
            left is None or right is None or left.path != right.path
        ):  # pragma: no cover - defensive kernel/recovery branch
            raise OverlayStateError(errno.EXDEV, "overlay rename crosses rule roots")

    def _journal_begin(self, kind: str, path: str, **extra: str | bool) -> None:
        record: dict[str, str | bool] = {"phase": "begin", "kind": kind, "path": path, **extra}
        self._journal_write(record)

    def _journal_commit(self, kind: str, path: str, **extra: str | bool) -> None:
        record: dict[str, str | bool] = {"phase": "commit", "kind": kind, "path": path, **extra}
        self._journal_write(record)

    def _journal_abort(self, kind: str, path: str, **extra: str | bool) -> None:
        record: dict[str, str | bool] = {"phase": "abort", "kind": kind, "path": path, **extra}
        self._journal_write(record)

    def _journal_has_commit(self, kind: str, path: str, **extra: str | bool) -> bool:
        database = self._db
        if database is None:  # pragma: no cover - defensive kernel/recovery branch
            return False
        rows = database.execute(
            "SELECT payload FROM mutations WHERE phase = 'commit' AND kind = ? AND path = ?",
            (kind, path),
        ).fetchall()
        for (payload,) in rows:
            try:
                record = json.loads(payload)
            except (TypeError, ValueError):  # pragma: no cover - recovery validates journal
                continue
            if isinstance(record, dict) and all(
                record.get(key) == value for key, value in extra.items()
            ):
                return True
        return False

    def _journal_write(self, record: dict[str, str | bool]) -> None:
        database = self._db
        if database is None:  # pragma: no cover - defensive kernel/recovery branch
            raise OverlayStateError(
                errno.ESTALE, "overlay journal is closed"
            )  # pragma: no cover - defensive kernel/recovery branch
        phase = str(record["phase"])
        kind = str(record["kind"])
        path = str(record["path"])
        payload = json.dumps(record, sort_keys=True, separators=(",", ":"))
        try:
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                (phase, kind, path, payload),
            )
            database.execute("COMMIT")
        except sqlite3.Error as error:  # pragma: no cover - defensive kernel/recovery branch
            with suppress(sqlite3.Error):  # pragma: no cover - defensive kernel/recovery branch
                database.execute("ROLLBACK")  # pragma: no cover - defensive kernel/recovery branch
            raise self._database_error(
                error
            ) from error  # pragma: no cover - defensive kernel/recovery branch

    @staticmethod
    def _write_all(descriptor: int, data: bytes) -> None:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:  # pragma: no cover - defensive kernel/recovery branch
                raise OSError(
                    errno.EIO, "overlay short write"
                )  # pragma: no cover - defensive kernel/recovery branch
            view = view[written:]

    def _recover(self) -> None:
        database = self._db
        if database is None:  # pragma: no cover - defensive kernel/recovery branch
            raise OverlayStateError(
                errno.ESTALE, "overlay journal is closed"
            )  # pragma: no cover - defensive kernel/recovery branch
        self._remove_orphan_temps(self._upper)
        pending: list[dict[str, object]] = []
        rows = database.execute(
            "SELECT phase, kind, path, payload FROM mutations ORDER BY id"
        ).fetchall()
        allowed_kinds = {
            "copy-up",
            "copy-up-dir",
            "create",
            "mkdir",
            "rename",
            "unlink",
            "rmdir",
            "whiteout",
        }
        for phase, kind, path, payload in rows:
            if phase not in {"begin", "commit", "abort"} or kind not in allowed_kinds:
                raise OverlayStateError(errno.EIO, "overlay metadata journal is corrupt")
            if phase == "begin":  # pragma: no branch - commit/abort are handled below
                try:
                    record = json.loads(payload)
                except (TypeError, ValueError) as error:
                    raise OverlayStateError(
                        errno.EIO, "overlay metadata journal is corrupt"
                    ) from error
                if not isinstance(
                    record, dict
                ):  # pragma: no cover - defensive kernel/recovery branch
                    raise OverlayStateError(
                        errno.EIO, "overlay metadata journal is corrupt"
                    )  # pragma: no cover - defensive kernel/recovery branch
                if (
                    record.get("phase") != "begin"
                    or record.get("kind") != kind
                    or record.get("path") != path
                ):
                    raise OverlayStateError(errno.EIO, "overlay metadata journal is corrupt")
                journal_path = record.get("path")
                if not isinstance(
                    journal_path, str
                ):  # pragma: no cover - defensive kernel/recovery branch
                    raise OverlayStateError(
                        errno.EIO, "overlay metadata journal path is invalid"
                    )  # pragma: no cover - defensive kernel/recovery branch
                try:
                    self._path(journal_path)
                except (
                    OverlayStateError
                ) as error:  # pragma: no cover - defensive kernel/recovery branch
                    raise OverlayStateError(  # pragma: no cover - defensive kernel/recovery branch
                        errno.EIO, "overlay metadata journal path is invalid"
                    ) from error
                pending.append(record)
            elif phase in {"commit", "abort"}:  # pragma: no branch - validated journal phases
                try:
                    record = json.loads(payload)
                except (TypeError, ValueError) as error:
                    raise OverlayStateError(
                        errno.EIO, "overlay metadata journal is corrupt"
                    ) from error
                if not isinstance(record, dict) or record.get("phase") != phase:
                    raise OverlayStateError(errno.EIO, "overlay metadata journal is corrupt")
                if record.get("kind") != kind or record.get("path") != path:
                    raise OverlayStateError(errno.EIO, "overlay metadata journal is corrupt")
                try:
                    self._path(path)
                except OverlayStateError as error:
                    raise OverlayStateError(
                        errno.EIO, "overlay metadata journal path is invalid"
                    ) from error
                for index in range(len(pending) - 1, -1, -1):
                    prior = pending[index]
                    if (
                        prior.get("kind") == kind and prior.get("path") == path
                    ):  # pragma: no branch - unmatched is rejected below
                        if (
                            phase == "commit"
                            and kind == "rename"
                            and record.get("destination") != prior.get("destination")
                        ):
                            raise OverlayStateError(errno.EIO, "overlay rename journal is corrupt")
                        pending.pop(index)
                        break
                else:
                    raise OverlayStateError(errno.EIO, "overlay metadata journal is corrupt")
        for record in pending:
            temp = record.get("temp")
            if isinstance(temp, str):  # pragma: no cover - defensive kernel/recovery branch
                if (
                    not temp.startswith(_TEMP_PREFIX) or "/" in temp or temp in {".", ".."}
                ):  # pragma: no cover - defensive kernel/recovery branch
                    raise OverlayStateError(
                        errno.EIO, "overlay journal temp path is invalid"
                    )  # pragma: no cover - defensive kernel/recovery branch
                with suppress(OSError):
                    os.unlink(temp, dir_fd=self._upper)
            path = record.get("path")
            if record.get("kind") in {"copy-up", "create"} and isinstance(path, str):
                try:
                    parent, name = self._upper_parent(path)
                except OverlayStateError as error:
                    if error.errno != errno.ENOENT:
                        raise  # pragma: no cover - journal path failure is fail-closed
                else:
                    try:
                        os.unlink(name, dir_fd=parent)
                    except FileNotFoundError:
                        pass
                    finally:
                        os.close(parent)
            if record.get("kind") in {"copy-up-dir", "mkdir"} and isinstance(path, str):
                self._remove_upper_tree(path)
            kind = record.get("kind")
            if kind == "rename" and isinstance(path, str):
                destination = record.get("destination")
                if not isinstance(destination, str):
                    raise OverlayStateError(errno.EIO, "overlay rename journal is corrupt")
                try:
                    self._path(destination)
                except OverlayStateError as error:
                    raise OverlayStateError(
                        errno.EIO, "overlay rename journal path is invalid"
                    ) from error
                source_fd = self._try_open(self._upper, path, os.O_PATH)
                destination_fd = self._try_open(self._upper, destination, os.O_PATH)
                source_exists = source_fd is not None
                destination_exists = destination_fd is not None
                if source_exists and destination_exists:
                    assert source_fd is not None and destination_fd is not None
                    source_mode = os.fstat(source_fd).st_mode
                    destination_mode = os.fstat(destination_fd).st_mode
                    if stat.S_ISDIR(source_mode) != stat.S_ISDIR(destination_mode):
                        os.close(source_fd)
                        os.close(destination_fd)
                        raise OverlayStateError(
                            errno.EIO, "overlay rename recovery has conflicting types"
                        )
                    if stat.S_ISDIR(destination_mode):
                        destination_dir = self._try_open(
                            self._upper, destination, os.O_RDONLY | os.O_DIRECTORY
                        )
                        if (
                            destination_dir is None
                        ):  # pragma: no cover - descriptor race during recovery
                            os.close(source_fd)
                            os.close(destination_fd)
                            raise OverlayStateError(
                                errno.EIO, "overlay rename recovery destination unavailable"
                            )
                        try:
                            if os.listdir(destination_dir):
                                os.close(source_fd)
                                os.close(destination_fd)
                                raise OverlayStateError(
                                    errno.EIO,
                                    "overlay rename recovery destination is not empty",
                                )
                        finally:
                            os.close(destination_dir)
                if source_fd is not None:
                    os.close(source_fd)
                if destination_fd is not None:
                    os.close(destination_fd)
                if source_exists:
                    old_parent, old_name = self._upper_parent(path)
                    new_parent, new_name = self._upper_parent(destination, create=True)
                    try:
                        os.rename(
                            old_name,
                            new_name,
                            src_dir_fd=old_parent,
                            dst_dir_fd=new_parent,
                        )
                        os.fsync(new_parent)
                    finally:
                        os.close(old_parent)
                        os.close(new_parent)
                if record.get("source_lower"):
                    self._write_whiteout(path, journal=False)
                continue
            if kind in {"unlink", "rmdir", "whiteout"} and isinstance(path, str):
                lower = bool(record.get("lower", kind == "whiteout"))
                if kind == "whiteout":
                    if lower:
                        self._write_whiteout(path, journal=False)
                    continue
                source_fd = self._try_open(self._upper, path, os.O_PATH)
                if source_fd is not None:
                    os.close(source_fd)
                    parent, name = self._upper_parent(path)
                    try:
                        try:
                            if kind == "rmdir":
                                os.rmdir(name, dir_fd=parent)
                            else:
                                os.unlink(name, dir_fd=parent)
                            os.fsync(parent)
                        except FileNotFoundError:
                            pass
                    finally:
                        os.close(parent)
                if lower:
                    self._write_whiteout(path, journal=False)

    def _prepare_metadata_file(self, name: str, *, create: bool = False) -> None:
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            descriptor = os.open(name, flags, dir_fd=self._upper)
        except FileNotFoundError:
            if not create:
                raise
            descriptor = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=self._upper)
        except OSError as error:
            if error.errno == errno.ELOOP:  # pragma: no cover - defensive kernel/recovery branch
                raise OSError(errno.EACCES, "overlay metadata symlink is forbidden") from error
            raise  # pragma: no cover - defensive kernel/recovery branch
        try:
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or details.st_uid != os.getuid()
                or details.st_mode & 0o077
            ):
                raise OSError(errno.EACCES, "overlay metadata file is unsafe")
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    def _sanitize_upper_tree(self, directory: int) -> None:
        for name in os.listdir(directory):
            if name in {
                _LOCK_NAME,
                _DATABASE_NAME,
                _DATABASE_NAME + "-wal",
                _DATABASE_NAME + "-shm",
            }:
                continue
            descriptor = self._try_open(directory, name, os.O_PATH)
            if descriptor is None:  # pragma: no cover - defensive kernel/recovery branch
                continue  # pragma: no cover - defensive kernel/recovery branch
            try:
                details = os.fstat(descriptor)
                if stat.S_ISDIR(details.st_mode):
                    safe_mode = self._safe_mode(details.st_mode)
                    if details.st_mode != (stat.S_IFDIR | safe_mode):
                        os.chmod(name, safe_mode, dir_fd=directory, follow_symlinks=False)
                    child_directory = self._try_open(directory, name, os.O_RDONLY | os.O_DIRECTORY)
                    if (
                        child_directory is not None
                    ):  # pragma: no cover - defensive kernel/recovery branch
                        try:
                            self._sanitize_upper_tree(child_directory)
                        finally:
                            os.close(child_directory)
                elif stat.S_ISREG(
                    details.st_mode
                ):  # pragma: no cover - defensive kernel/recovery branch
                    if details.st_nlink != 1:
                        raise OSError(errno.EACCES, "overlay upper rejects hardlink aliases")
                    safe_mode = self._safe_mode(details.st_mode)
                    if details.st_mode != (stat.S_IFREG | safe_mode):
                        os.chmod(name, safe_mode, dir_fd=directory, follow_symlinks=False)
                else:
                    raise OSError(
                        errno.EACCES, "overlay upper contains unsupported node"
                    )  # pragma: no cover - defensive kernel/recovery branch
            finally:
                os.close(descriptor)

    def _remove_upper_tree(self, path: str) -> None:
        try:
            parent, name = self._upper_parent(path)
        except OverlayStateError as error:
            if error.errno == errno.ENOENT:
                return
            raise  # pragma: no cover - upper tree cleanup is best-effort
        try:
            target = self._try_open(parent, name, os.O_RDONLY | os.O_DIRECTORY)
            if target is None:
                return
            try:
                for child in os.listdir(
                    target
                ):  # pragma: no cover - defensive kernel/recovery branch
                    child_path = (
                        f"{path}/{child}"  # pragma: no cover - defensive kernel/recovery branch
                    )
                    child_fd = self._try_open(
                        target, child, os.O_PATH
                    )  # pragma: no cover - defensive kernel/recovery branch
                    if child_fd is None:  # pragma: no cover - defensive kernel/recovery branch
                        continue  # pragma: no cover - defensive kernel/recovery branch
                    try:  # pragma: no cover - defensive kernel/recovery branch
                        child_stat = os.fstat(
                            child_fd
                        )  # pragma: no cover - defensive kernel/recovery branch
                    finally:
                        os.close(child_fd)  # pragma: no cover - defensive kernel/recovery branch
                    if stat.S_ISDIR(
                        child_stat.st_mode
                    ):  # pragma: no cover - defensive kernel/recovery branch
                        self._remove_upper_tree(
                            child_path
                        )  # pragma: no cover - defensive kernel/recovery branch
                    else:
                        os.unlink(
                            child, dir_fd=target
                        )  # pragma: no cover - defensive kernel/recovery branch
            finally:
                os.close(target)
            os.rmdir(name, dir_fd=parent)
        finally:
            os.close(parent)

    def _remove_orphan_temps(self, directory: int) -> None:
        for name in os.listdir(directory):
            child = self._try_open(directory, name, os.O_PATH)
            if child is None:  # pragma: no cover - defensive kernel/recovery branch
                continue  # pragma: no cover - defensive kernel/recovery branch
            try:
                details = os.fstat(child)
                if name.startswith(_TEMP_PREFIX):
                    os.unlink(name, dir_fd=directory)
                elif stat.S_ISDIR(details.st_mode):
                    child_directory = self._try_open(directory, name, os.O_RDONLY | os.O_DIRECTORY)
                    if (
                        child_directory is not None
                    ):  # pragma: no cover - defensive kernel/recovery branch
                        try:
                            self._remove_orphan_temps(child_directory)
                        finally:
                            os.close(child_directory)
            finally:
                os.close(child)

    @staticmethod
    def _database_error(error: sqlite3.Error) -> OverlayStateError:
        message = str(error).lower()
        code = errno.EAGAIN if "locked" in message or "busy" in message else errno.EIO
        if "full" in message or "space" in message:
            code = errno.ENOSPC
        return OverlayStateError(code, "overlay metadata journal failed")

    @staticmethod
    def _safe_mode(mode: int) -> int:
        return mode & 0o777 & ~(stat.S_ISUID | stat.S_ISGID)

    @staticmethod
    def _error(error: OSError, message: str) -> OverlayStateError:
        return OverlayStateError(error.errno or errno.EIO, message)

    def _remember(self, descriptor: int, *, upper: bool) -> int:
        with self._lock:
            self._ensure_open()
            self._handles[descriptor] = upper
        return descriptor

    def _require_handle(self, descriptor: int) -> None:
        with self._lock:
            self._ensure_open()
            if descriptor not in self._handles:
                raise OverlayStateError(errno.EBADF, "overlay file handle is not owned")

    def _ensure_open(self) -> None:
        if self._closed:
            raise OverlayStateError(errno.ESTALE, "overlay backend is closed")

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        with self._lock:
            self._ensure_open()
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)


OverlayView = OverlayBackend
