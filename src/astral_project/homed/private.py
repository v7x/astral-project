"""Descriptor-pinned private writable profile state."""

from __future__ import annotations

import errno
import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
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

_MAX_DIRECTORY_ENTRIES = 4096
_DEFAULT_MAX_BYTES = 64 * 1024 * 1024
_LOCK_NAME = ".aspr-private-lock"


class PrivateStateError(HomedError):
    """Private state operation failed with stable errno."""


class PrivateWritableBackend:
    """Persistent per-profile filesystem confined below one directory descriptor.

    ``storage_root`` is application-owned state. One child directory is created for
    ``profile`` and all subsequent operations use descriptors relative to that child.
    Symlinks, special files, and xattrs are intentionally unsupported.
    """

    def __init__(
        self,
        storage_root: str | os.PathLike[str],
        profile: Profile | str,
        *,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        max_files: int = 16_384,
    ) -> None:
        if max_bytes < 0 or max_files <= 0:
            raise ValueError("private-state limits are invalid")
        profile_id = profile.profile_id if isinstance(profile, Profile) else profile
        validate_profile_id(profile_id)
        self.profile = profile if isinstance(profile, Profile) else None
        self.profile_id = profile_id
        self.max_bytes = max_bytes
        self.max_files = max_files
        self._lock = RLock()
        self._closed = False
        self._next_inode = 2
        self._paths: dict[str, int] = {".": 1}
        self._inodes: dict[int, str] = {1: "."}
        self._lookups: dict[int, int] = {1: 1}
        self._handles: set[int] = set()
        root = Path(storage_root)
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
        except FileExistsError as error:
            raise OSError(errno.EACCES, "private storage root is not a directory") from error
        root_details = root.lstat()
        if (
            not stat.S_ISDIR(root_details.st_mode)
            or root_details.st_uid != os.getuid()
            or root_details.st_mode & (0o077 | stat.S_ISUID | stat.S_ISGID)
        ):
            raise OSError(errno.EACCES, "private storage root has unsafe ownership or mode")
        root_fd = os.open(
            os.fspath(root), os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        try:
            with suppress(FileExistsError):
                os.mkdir(profile_id, 0o700, dir_fd=root_fd)
            profile_fd = os.open(
                profile_id,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
        except BaseException:  # pragma: no cover - descriptor cleanup after setup failure
            os.close(root_fd)
            raise
        finally:
            os.close(root_fd)
        try:
            details = os.fstat(profile_fd)
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid != os.getuid()
                or details.st_mode & (0o077 | stat.S_ISUID | stat.S_ISGID)
            ):
                raise OSError(errno.EACCES, "private profile root has unsafe ownership or mode")
            lock_fd = os.open(
                _LOCK_NAME,
                os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=profile_fd,
            )
            os.fchmod(lock_fd, 0o600)
        except BaseException:
            os.close(profile_fd)
            raise
        self._root = profile_fd
        self._lock_fd = lock_fd
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            try:
                self._used_bytes, self._file_count = self._scan_usage()
            finally:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        except BaseException:  # pragma: no cover - descriptor cleanup after setup failure
            os.close(self._lock_fd)
            os.close(self._root)
            self._closed = True
            raise
        if self._file_count > max_files or self._used_bytes > max_bytes:
            self.close()
            raise OSError(errno.EDQUOT, "private profile state exceeds configured quota")

    @property
    def root_fd(self) -> int:
        return self._root

    @property
    def inode_count(self) -> int:
        with self._lock:
            return len(self._inodes)

    @property
    def profile_root(self) -> str:
        """Return procfs diagnostic path, never used for filesystem resolution."""
        return f"/proc/self/fd/{self._root}"

    @property
    def used_bytes(self) -> int:
        with self._lock:
            self._ensure_open()
            return self._used_bytes

    @property
    def file_count(self) -> int:
        with self._lock:
            self._ensure_open()
            return self._file_count

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._closed = True
                for descriptor in self._handles:
                    with suppress(OSError):
                        os.close(descriptor)
                self._handles.clear()
                os.close(self._lock_fd)
                os.close(self._root)

    def __enter__(self) -> PrivateWritableBackend:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def lookup(self, path: str) -> BackingNode:
        normalized = self._path(path)
        self._authorize(normalized, Operation.LOOKUP)
        with self._exclusive():
            fd = self._open_existing(normalized, os.O_PATH)
            try:
                return self._node(normalized, os.fstat(fd))
            finally:
                os.close(fd)

    def stat(self, path: str) -> BackingNode:
        normalized = self._path(path)
        self._authorize(normalized, Operation.STAT)
        with self._exclusive():
            fd = self._open_existing(normalized, os.O_PATH)
            try:
                return self._node(normalized, os.fstat(fd))
            finally:
                os.close(fd)

    def node_path(self, inode: int) -> str:
        with self._lock:
            try:
                return self._inodes[inode]
            except KeyError as error:
                raise PrivateStateError(errno.ENOENT, "unknown synthetic inode") from error

    def forget(self, inode: int, count: int) -> None:
        """Release kernel lookup references; root remains permanently pinned."""
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
            fd = self._open_existing(normalized, os.O_RDONLY | os.O_DIRECTORY)
            try:
                names = tuple(sorted(name for name in os.listdir(fd) if name != _LOCK_NAME))
                names = self._filter_listing(normalized, names)
                if len(names) > _MAX_DIRECTORY_ENTRIES:
                    raise PrivateStateError(errno.EOVERFLOW, "directory listing exceeds bound")
                return names
            except OSError as error:
                raise self._error(error, "directory listing failed") from error
            finally:
                os.close(fd)

    def create(self, path: str, mode: int = 0o600) -> BackingNode:
        normalized = self._path(path)
        self._authorize(normalized, Operation.CREATE)
        with self._exclusive():
            parent, name = self._parent(normalized)
            try:
                self._check_file_quota(1, 0)
                fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    self._safe_file_mode(mode),
                    dir_fd=parent,
                )
            except OSError as error:
                raise self._error(error, "private file creation failed") from error
            try:
                os.fchmod(fd, self._safe_file_mode(mode))
                result = self._node(normalized, os.fstat(fd))
            finally:
                os.close(fd)
                os.close(parent)
            self._file_count += 1
            return result

    def mkdir(self, path: str, mode: int = 0o700) -> BackingNode:
        normalized = self._path(path)
        self._authorize(normalized, Operation.MKDIR)
        with self._exclusive():
            parent, name = self._parent(normalized)
            try:
                os.mkdir(name, self._safe_directory_mode(mode), dir_fd=parent)
                fd = os.open(
                    name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
                )
                try:
                    os.fchmod(fd, self._safe_directory_mode(mode))
                    return self._node(normalized, os.fstat(fd))
                finally:
                    os.close(fd)
            except OSError as error:
                raise self._error(error, "private directory creation failed") from error
            finally:
                os.close(parent)

    def open(self, path: str, flags: int = os.O_RDONLY, mode: int = 0o600) -> int:
        normalized = self._path(path)
        write_requested = flags & (os.O_WRONLY | os.O_RDWR)
        if flags & os.O_CREAT:
            self._authorize(normalized, Operation.CREATE)
        elif write_requested:
            self._authorize(normalized, Operation.WRITE)
        else:
            self._authorize(normalized, Operation.READ)
        if flags & os.O_TRUNC:
            self._authorize(normalized, Operation.TRUNCATE)
        with self._exclusive():
            parent, name = self._parent(normalized)
            descriptor = -1
            try:
                existed = True
                probe = -1
                try:
                    probe = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                    probe_details = os.fstat(probe)
                    if not stat.S_ISREG(probe_details.st_mode) or probe_details.st_nlink != 1:
                        raise OSError(
                            errno.EACCES, "private state supports only unaliased regular files"
                        )
                except FileNotFoundError:
                    existed = False
                finally:
                    if probe >= 0:
                        os.close(probe)
                if not existed:
                    self._check_file_quota(1, 0)
                descriptor = os.open(
                    name,
                    flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                    self._safe_file_mode(mode),
                    dir_fd=parent,
                )
                details = os.fstat(descriptor)
                if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(
                    details.st_mode
                ):  # pragma: no cover - race after O_PATH probe
                    raise OSError(errno.EACCES, "private state supports regular files only")
                if details.st_nlink != 1:  # pragma: no cover - race after O_PATH probe
                    raise OSError(errno.EACCES, "private state rejects hardlink aliases")
                os.fchmod(descriptor, self._safe_mode(details.st_mode))
                if not existed:
                    self._file_count += 1
                if flags & os.O_TRUNC:
                    self._check_size(details.st_size, -details.st_size)
                    self._used_bytes -= details.st_size
                self._handles.add(descriptor)
                return descriptor
            except OSError as error:
                if descriptor >= 0:  # pragma: no cover - failed open cleanup
                    os.close(descriptor)
                raise self._error(error, "private file open failed") from error
            finally:
                os.close(parent)

    def release(self, descriptor: int) -> None:
        with self._lock:
            if descriptor not in self._handles:
                return
            self._handles.remove(descriptor)
            os.close(descriptor)

    def read(self, descriptor: int | str, offset: int = 0, size: int = 131072) -> bytes:
        if isinstance(descriptor, str):
            handle = self.open(descriptor)
            try:
                return self.read(handle, offset, size)
            finally:
                self.release(handle)
        if offset < 0 or size < 0:
            raise ValueError("offset and size must be non-negative")
        with self._exclusive():
            self._require_handle(descriptor)
            try:
                return os.pread(descriptor, size, offset)
            except OSError as error:
                raise self._error(error, "private file read failed") from error

    def write(self, descriptor: int | str, data: bytes, offset: int | None = None) -> int:
        if isinstance(descriptor, str):
            handle = self.open(descriptor, os.O_RDWR)
            try:
                return self.write(handle, data, offset)
            finally:
                self.release(handle)
        if not isinstance(data, bytes):
            raise TypeError("private writes require bytes")
        with self._exclusive():
            self._require_handle(descriptor)
            try:
                details = os.fstat(descriptor)
                if not stat.S_ISREG(details.st_mode):
                    raise OSError(errno.EISDIR, "private write target is not a regular file")
                if offset is None:
                    file_flags = fcntl.fcntl(descriptor, fcntl.F_GETFL)
                    position = (
                        details.st_size
                        if file_flags & os.O_APPEND
                        else os.lseek(descriptor, 0, os.SEEK_CUR)
                    )
                else:
                    position = offset
                if position < 0:
                    raise ValueError("offset must be non-negative")
                self._check_size(details.st_size, max(0, position + len(data) - details.st_size))
                written = (
                    os.pwrite(descriptor, data, position)
                    if offset is not None
                    else os.write(descriptor, data)
                )
                new_size = os.fstat(descriptor).st_size
                self._used_bytes += new_size - details.st_size
                return written
            except (OSError, ValueError) as error:
                if isinstance(error, ValueError):
                    raise
                raise self._error(error, "private file write failed") from error

    def truncate(self, descriptor: int | str, size: int) -> None:
        if isinstance(descriptor, str):
            handle = self.open(descriptor, os.O_RDWR)
            try:
                self.truncate(handle, size)
            finally:
                self.release(handle)
            return
        if size < 0:
            raise ValueError("truncate size must be non-negative")
        with self._exclusive():
            self._require_handle(descriptor)
            try:
                details = os.fstat(descriptor)
                self._check_size(details.st_size, size - details.st_size)
                os.ftruncate(descriptor, size)
                self._used_bytes += size - details.st_size
            except OSError as error:
                raise self._error(error, "private file truncate failed") from error

    def fsync(self, descriptor: int | str) -> None:
        if isinstance(descriptor, str):
            handle = self.open(descriptor)
            try:
                self.fsync(handle)
            finally:
                self.release(handle)
            return
        with self._exclusive():
            self._require_handle(descriptor)
            try:
                os.fsync(descriptor)
            except OSError as error:
                raise self._error(error, "private fsync failed") from error

    def rename(self, source: str, destination: str) -> None:
        old = self._path(source)
        new = self._path(destination)
        self._authorize(old, Operation.RENAME)
        self._authorize(new, Operation.RENAME)
        with self._exclusive():
            source_parent, source_name = self._parent(old)
            destination_parent, destination_name = self._parent(new)
            try:
                source_stat = os.stat(source_name, dir_fd=source_parent, follow_symlinks=False)
                if stat.S_ISLNK(source_stat.st_mode) or not (
                    stat.S_ISREG(source_stat.st_mode) or stat.S_ISDIR(source_stat.st_mode)
                ):
                    raise OSError(errno.EACCES, "unsupported private node")
                try:
                    destination_stat = (
                        None
                        if old == new
                        else os.stat(
                            destination_name, dir_fd=destination_parent, follow_symlinks=False
                        )
                    )
                except FileNotFoundError:
                    destination_stat = None
                if destination_stat is not None:
                    if stat.S_ISLNK(destination_stat.st_mode) or stat.S_ISDIR(
                        destination_stat.st_mode
                    ):
                        if stat.S_ISREG(source_stat.st_mode):
                            raise OSError(errno.EISDIR, "private rename target is a directory")
                    elif not stat.S_ISREG(destination_stat.st_mode):
                        raise OSError(errno.EACCES, "unsupported private node")
                os.rename(
                    source_name,
                    destination_name,
                    src_dir_fd=source_parent,
                    dst_dir_fd=destination_parent,
                )
                if destination_stat is not None and stat.S_ISREG(destination_stat.st_mode):
                    self._used_bytes -= destination_stat.st_size
                    self._file_count -= 1
            except OSError as error:
                raise self._error(error, "private rename failed") from error
            finally:
                os.close(source_parent)
                os.close(destination_parent)

    def rmdir(self, path: str) -> None:
        self.unlink(path, directory=True)

    def unlink(self, path: str, *, directory: bool = False) -> None:
        normalized = self._path(path)
        self._authorize(normalized, Operation.RMDIR if directory else Operation.UNLINK)
        with self._exclusive():
            parent, name = self._parent(normalized)
            try:
                details = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (
                    stat.S_ISLNK(details.st_mode)
                    or (directory and not stat.S_ISDIR(details.st_mode))
                    or (not directory and not stat.S_ISREG(details.st_mode))
                ):
                    raise OSError(
                        errno.EISDIR if not directory else errno.ENOTDIR, "node type mismatch"
                    )
                if directory:
                    os.rmdir(name, dir_fd=parent)
                else:
                    os.unlink(name, dir_fd=parent)
                    self._used_bytes -= details.st_size
                    self._file_count -= 1
            except OSError as error:
                raise self._error(error, "private unlink failed") from error
            finally:
                os.close(parent)

    def chmod(self, descriptor: int | str, mode: int) -> None:
        if isinstance(descriptor, str):
            handle = self.open(descriptor, os.O_RDWR)
            try:
                self.chmod(handle, mode)
            finally:
                self.release(handle)
            return
        with self._exclusive():
            self._require_handle(descriptor)
            try:
                os.fchmod(descriptor, self._safe_mode(mode))
            except OSError as error:
                raise self._error(error, "private chmod failed") from error

    def setxattr(self, *_args: object, **_kwargs: object) -> None:
        raise PrivateStateError(errno.ENOTSUP, "private state does not support xattrs")

    getxattr = setxattr
    listxattr = setxattr
    removexattr = setxattr
    xattr = setxattr

    def symlink(self, *_args: object, **_kwargs: object) -> None:
        raise PrivateStateError(errno.EOPNOTSUPP, "symlinks are not supported")

    def mknod(self, *_args: object, **_kwargs: object) -> None:
        raise PrivateStateError(errno.EPERM, "device nodes are not supported")

    def _path(self, path: str) -> str:
        self._ensure_open()
        if path == ".":
            return path
        try:
            normalized = normalize_home_path(path)
            if any(component == _LOCK_NAME for component in normalized.split("/")):
                raise ValueError("private metadata name is reserved")
            return normalized
        except ValueError as error:
            raise PrivateStateError(errno.EINVAL, "private path is invalid") from error

    def _filter_listing(self, path: str, names: tuple[str, ...]) -> tuple[str, ...]:
        if self.profile is None:
            return names
        visible: list[str] = []
        for name in names:
            child = name if path == "." else f"{path}/{name}"
            decision = self.profile.decision(child, Operation.LOOKUP)
            if decision.rule is not None and decision.rule.mode is RuleMode.PRIVATE_RW:
                visible.append(name)
        return tuple(visible)

    def _authorize(self, path: str, operation: Operation) -> None:
        if self.profile is None or path == ".":
            return
        decision = self.profile.decision(path, operation)
        if (
            not decision.allowed
            or decision.rule is None
            or decision.rule.mode is not RuleMode.PRIVATE_RW
        ):
            raise PrivateStateError(errno.EACCES, f"private policy denied {operation} {path}")

    def _parent(self, path: str) -> tuple[int, str]:
        if path == ".":
            raise PrivateStateError(errno.EBUSY, "private root has no parent")
        parts = path.split("/")
        current = os.dup(self._root)
        try:
            for part in parts[:-1]:
                child = os.open(
                    part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current
                )
                os.close(current)
                current = child
            return current, parts[-1]
        except OSError as error:
            os.close(current)
            raise self._error(error, "private parent is unavailable") from error

    def _open_existing(self, path: str, flags: int) -> int:
        if path == ".":
            return os.dup(self._root)
        parent, name = self._parent(path)
        try:
            descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            details = os.fstat(descriptor)
            if (
                stat.S_ISLNK(details.st_mode)
                or stat.S_ISCHR(details.st_mode)
                or stat.S_ISBLK(details.st_mode)
                or stat.S_ISFIFO(details.st_mode)
                or stat.S_ISSOCK(details.st_mode)
                or (stat.S_ISREG(details.st_mode) and details.st_nlink != 1)
            ):
                os.close(descriptor)
                raise OSError(errno.EACCES, "unsupported private node")
            return descriptor
        except OSError as error:
            raise self._error(error, "private path is unavailable") from error
        finally:
            os.close(parent)

    def _node(self, path: str, details: os.stat_result) -> BackingNode:
        if stat.S_ISLNK(details.st_mode) or not (
            stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode)
        ):
            raise PrivateStateError(errno.EACCES, "unsupported private node")
        with self._lock:
            inode = self._paths.get(path)
            if inode is None:
                inode = self._next_inode
                self._next_inode += 1
                self._paths[path] = inode
                self._inodes[inode] = path
            self._lookups[inode] = self._lookups.get(inode, 0) + 1
        kind = stat.S_IFDIR if stat.S_ISDIR(details.st_mode) else stat.S_IFREG
        mode = kind | self._safe_mode(details.st_mode)
        return BackingNode(
            inode, path, mode, details.st_size, details.st_mtime_ns, stat.S_ISDIR(details.st_mode)
        )

    def _scan_usage(self) -> tuple[int, int]:
        total = 0
        files = 0
        stack = [os.dup(self._root)]
        try:
            while stack:
                directory = stack.pop()
                try:
                    for name in os.listdir(directory):
                        if name == _LOCK_NAME:
                            continue
                        descriptor = os.open(
                            name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory
                        )
                        try:
                            details = os.fstat(descriptor)
                            if stat.S_ISREG(details.st_mode):
                                if details.st_nlink != 1:
                                    raise OSError(
                                        errno.EACCES, "private state rejects hardlink aliases"
                                    )
                                safe_mode = self._safe_mode(details.st_mode)
                                if details.st_mode != (stat.S_IFREG | safe_mode):
                                    os.chmod(
                                        name,
                                        safe_mode,
                                        dir_fd=directory,
                                        follow_symlinks=False,
                                    )
                                total += details.st_size
                                files += 1
                            elif stat.S_ISDIR(details.st_mode):
                                safe_mode = self._safe_directory_mode(details.st_mode)
                                if details.st_mode != (stat.S_IFDIR | safe_mode):
                                    os.chmod(
                                        name,
                                        safe_mode,
                                        dir_fd=directory,
                                        follow_symlinks=False,
                                    )
                                stack.append(
                                    os.open(
                                        name,
                                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=directory,
                                    )
                                )
                            else:
                                raise OSError(
                                    errno.EACCES, "private state contains unsupported node"
                                )
                        finally:
                            os.close(descriptor)
                finally:
                    os.close(directory)
        except OSError as error:
            for descriptor in stack:
                os.close(descriptor)
            raise self._error(error, "private state scan failed") from error
        return total, files

    def _check_file_quota(self, file_delta: int, byte_delta: int) -> None:
        if self._file_count + file_delta > self.max_files:
            raise PrivateStateError(errno.EDQUOT, "private file quota exceeded")
        if self._used_bytes + byte_delta > self.max_bytes:
            raise PrivateStateError(errno.EDQUOT, "private byte quota exceeded")

    def _check_size(self, old_size: int, delta: int) -> None:
        self._check_file_quota(0, delta)
        if delta < 0 and self._used_bytes < old_size:
            self._used_bytes = max(0, self._used_bytes)

    @staticmethod
    def _safe_file_mode(mode: int) -> int:
        return mode & 0o700

    @staticmethod
    def _safe_directory_mode(mode: int) -> int:
        return mode & 0o700

    @staticmethod
    def _safe_mode(mode: int) -> int:
        return mode & 0o700

    @staticmethod
    def _error(error: OSError, message: str) -> PrivateStateError:
        return PrivateStateError(error.errno or errno.EIO, message)

    def _require_handle(self, descriptor: int) -> None:
        if descriptor not in self._handles:
            raise PrivateStateError(errno.EBADF, "private file handle is not owned")

    def _ensure_open(self) -> None:
        if self._closed:
            raise PrivateStateError(errno.ESTALE, "private profile backend is closed")

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        with self._lock:
            self._ensure_open()
            fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
            try:
                self._used_bytes, self._file_count = self._scan_usage()
                yield
            finally:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)


PrivateWritableView = PrivateWritableBackend
PrivateProfileStore = PrivateWritableBackend
