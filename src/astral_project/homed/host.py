"""Descriptor-pinned, read-only host backing for projected home."""

from __future__ import annotations

import errno
import os
import stat as stat_module
from dataclasses import dataclass
from threading import RLock
from typing import Final

from astral_project.homed.mediation import RemoteUnknownPathMediator, UnknownPathMediator
from astral_project.profile import Operation, Profile, RuleMode, Sensitivity, normalize_home_path

_ROOT_INODE: Final[int] = 1
_MAX_DIRECTORY_ENTRIES = 4096


class HostAccessError(PermissionError):
    """Host backing denied an operation or encountered an unsafe path."""


@dataclass(frozen=True, slots=True)
class BackingNode:
    inode: int
    path: str
    mode: int
    size: int
    mtime_ns: int
    is_directory: bool


class HostReadonlyView:
    """Serve explicit profile-approved host paths relative to one O_PATH root."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        profile: Profile,
        *,
        mediator: UnknownPathMediator | RemoteUnknownPathMediator | None = None,
        session_id: str = "default",
    ) -> None:
        if not session_id:
            raise ValueError("host view session identity is required")
        self._profile = profile
        self._mediator = mediator
        self._session_id = session_id
        self._root = os.open(
            os.fspath(root), os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        self._lock = RLock()
        self._next_inode = 2
        self._paths: dict[str, int] = {".": _ROOT_INODE}
        self._inodes: dict[int, str] = {_ROOT_INODE: "."}
        self._lookups: dict[int, int] = {_ROOT_INODE: 1}

    @property
    def root_fd(self) -> int:
        return self._root

    @property
    def inode_count(self) -> int:
        with self._lock:
            return len(self._inodes)

    def close(self) -> None:
        with self._lock:
            if self._root >= 0:
                os.close(self._root)
                self._root = -1

    def __enter__(self) -> HostReadonlyView:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def lookup(self, path: str) -> BackingNode:
        normalized = normalize_home_path(path)
        self._authorize(normalized, Operation.LOOKUP)
        fd = self._open_relative(normalized, os.O_PATH | os.O_CLOEXEC)
        try:
            return self._node(normalized, os.fstat(fd))
        finally:
            os.close(fd)

    def stat(self, path: str) -> BackingNode:
        if path == ".":
            if self._root < 0:
                raise HostAccessError(errno.ESTALE, "host root is closed")
            return self._node(".", os.fstat(self._root))
        normalized = normalize_home_path(path)
        self._authorize(normalized, Operation.STAT)
        fd = self._open_relative(normalized, os.O_PATH | os.O_CLOEXEC)
        try:
            return self._node(normalized, os.fstat(fd))
        finally:
            os.close(fd)

    def read(self, path: str, offset: int = 0, size: int = 131072) -> bytes:
        normalized = normalize_home_path(path)
        if offset < 0 or size < 0:
            raise ValueError("offset and size must be non-negative")
        self._authorize(normalized, Operation.READ)
        fd = self._open_relative(normalized, os.O_RDONLY | os.O_CLOEXEC)
        try:
            if offset:
                return os.pread(fd, size, offset)
            return os.read(fd, size)
        except IsADirectoryError as error:
            raise HostAccessError(errno.EISDIR, "cannot read directory") from error
        finally:
            os.close(fd)

    def listdir(self, path: str) -> tuple[str, ...]:
        if path == ".":
            raise HostAccessError(errno.EACCES, "host root listing is not explicitly approved")
        normalized = normalize_home_path(path)
        self._authorize(normalized, Operation.LIST)
        fd = self._open_relative(normalized, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            names = os.listdir(fd)
            if len(names) > _MAX_DIRECTORY_ENTRIES:
                raise HostAccessError(errno.EOVERFLOW, "directory listing exceeds bound")
            return tuple(sorted(names))
        except OSError as error:
            raise HostAccessError(error.errno or errno.EIO, "directory listing failed") from error
        finally:
            os.close(fd)

    def write(self, path: str, data: bytes) -> None:
        del path, data
        raise HostAccessError(errno.EROFS, "host-backed projected home is read-only")

    def cancel_pending(self) -> int:
        if self._mediator is None:
            return 0
        return self._mediator.cancel_session(self._session_id)

    def node_path(self, inode: int) -> str:
        with self._lock:
            try:
                return self._inodes[inode]
            except KeyError as error:
                raise HostAccessError(errno.ENOENT, "unknown synthetic inode") from error

    def forget(self, inode: int, count: int) -> None:
        """Release path cache entries after FUSE drops its lookup references."""
        if count < 0 or inode == _ROOT_INODE:
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

    def _authorize(self, path: str, operation: Operation) -> None:
        decision = self._profile.decision(path, operation)
        if decision.allowed:
            if decision.rule is None or decision.rule.mode not in {
                RuleMode.HOST_RO,
                RuleMode.HOST_RX,
            }:
                raise HostAccessError(errno.EACCES, "path is not host-backed")
            if decision.rule.sensitivity is Sensitivity.CREDENTIAL or any(
                credential.path == path for credential in self._profile.credentials
            ):
                self._confirm_credential(path, operation)
            return
        if any(credential.path == path for credential in self._profile.credentials):
            self._confirm_credential(path, operation)
            return
        opaque_ancestor = (
            decision.reason == "opaque ancestor traversal" or self._has_descendant_rule(path)
        )
        if (
            self._profile.sealed
            and opaque_ancestor
            and operation in {Operation.LOOKUP, Operation.STAT}
        ):
            # Permit component traversal toward known descendant rules only.
            # LIST remains denied; siblings and directory contents stay hidden.
            return
        if (
            decision.reason in {"no matching rule", "opaque ancestor traversal"}
            and self._mediator is not None
            and self._profile.unknown_learning == "prompt"
            and not self._profile.sealed
            and not (operation is Operation.LIST and opaque_ancestor)
        ):
            result = self._mediator.request(
                session_id=self._session_id,
                path=path,
                path_component=path.rsplit("/", 1)[-1],
                operation=operation,
                sensitivity=self._unknown_sensitivity(path),
                opaque_ancestor=opaque_ancestor,
            )
            if result.allowed:
                return
            if result.hidden:
                raise HostAccessError(errno.ENOENT, f"hidden {operation} {path}")
        if opaque_ancestor and operation is Operation.LIST:
            raise HostAccessError(errno.EACCES, f"opaque ancestor denies {operation} {path}")
        if self._profile.sealed and decision.reason == "no matching rule":
            error = errno.ENOENT if self._profile.unknown_sealed == "hide" else errno.EACCES
            raise HostAccessError(error, f"sealed policy denied {operation} {path}")
        raise HostAccessError(errno.EACCES, f"policy denied {operation} {path}")

    def _confirm_credential(self, path: str, operation: Operation) -> None:
        if self._mediator is None:
            raise HostAccessError(errno.EACCES, "credential access requires strong confirmation")
        result = self._mediator.request(
            session_id=self._session_id,
            path=path,
            path_component=path.rsplit("/", 1)[-1],
            operation=operation,
            sensitivity=Sensitivity.CREDENTIAL,
        )
        if result.allowed:
            return
        if result.hidden:
            raise HostAccessError(errno.ENOENT, f"hidden credential {path}")
        raise HostAccessError(errno.EACCES, f"credential confirmation denied for {path}")

    def _has_descendant_rule(self, path: str) -> bool:
        prefix = path + "/"
        return any(rule.path.startswith(prefix) for rule in self._profile.rules)

    def _unknown_sensitivity(self, path: str) -> Sensitivity:
        prefix = path + "/"
        descendants = [rule for rule in self._profile.rules if rule.path.startswith(prefix)]
        if not descendants:
            return Sensitivity.OTHER
        descendants.sort(key=lambda rule: len(rule.path))
        return descendants[0].sensitivity

    def _open_relative(self, path: str, flags: int) -> int:
        if self._root < 0:
            raise HostAccessError(errno.ESTALE, "host root is closed")
        parts = path.split("/")
        current = os.dup(self._root)
        try:
            for index, part in enumerate(parts):
                next_flags = flags if index == len(parts) - 1 else os.O_PATH | os.O_DIRECTORY
                next_flags |= os.O_NOFOLLOW | os.O_CLOEXEC
                try:
                    child = os.open(part, next_flags, dir_fd=current)
                except OSError as error:
                    if error.errno == errno.ELOOP:
                        raise HostAccessError(
                            errno.EACCES, "symlink or magic-link escape denied"
                        ) from error
                    raise HostAccessError(
                        error.errno or errno.EIO, "host path is unavailable"
                    ) from error
                os.close(current)
                current = child
            return current
        except BaseException:
            os.close(current)
            raise

    def _node(self, path: str, metadata: os.stat_result) -> BackingNode:
        if stat_module.S_ISLNK(metadata.st_mode):
            raise HostAccessError(errno.EACCES, "symlink and magic-link nodes are denied")
        with self._lock:
            inode = self._paths.get(path)
            if inode is None:
                inode = self._next_inode
                self._next_inode += 1
                self._paths[path] = inode
                self._inodes[inode] = path
            self._lookups[inode] = self._lookups.get(inode, 0) + 1
        mode = stat_module.S_IFMT(metadata.st_mode) | (
            metadata.st_mode & 0o777 & ~(stat_module.S_ISUID | stat_module.S_ISGID)
        )
        return BackingNode(
            inode=inode,
            path=path,
            mode=mode,
            size=metadata.st_size,
            mtime_ns=metadata.st_mtime_ns,
            is_directory=stat_module.S_ISDIR(metadata.st_mode),
        )
