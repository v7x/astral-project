"""One projected-home namespace over disjoint, policy-selected backing engines."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from threading import RLock
from typing import Literal

from astral_project.homed.host import BackingNode, HostReadonlyView
from astral_project.homed.overlay import OverlayBackend
from astral_project.homed.private import PrivateWritableBackend
from astral_project.profile import Operation, Profile, RuleMode, RuleScope

_BackendName = Literal["host", "private", "overlay"]
_Backend = HostReadonlyView | PrivateWritableBackend | OverlayBackend
_WritableBackend = PrivateWritableBackend | OverlayBackend


@dataclass(frozen=True, slots=True)
class _Node:
    backend: _BackendName | None
    backend_inode: int | None
    path: str
    mode: int
    size: int
    mtime_ns: int


class CompositeProjectedHome:
    """Route every projected path through its selected policy backing.

    The public inode and handle spaces belong solely to this object.  Backend
    inode values and file descriptors are never exposed to FUSE, thus an inode
    from one disjoint policy root cannot be mistaken for authority in another.
    """

    def __init__(
        self,
        profile: Profile,
        *,
        host: HostReadonlyView | None = None,
        private: PrivateWritableBackend | None = None,
        overlay: OverlayBackend | None = None,
    ) -> None:
        self.profile = profile
        self.host = host
        self.private = private
        self.overlay = overlay
        self._lock = RLock()
        self._next_inode = 2
        self._nodes: dict[int, _Node] = {1: _Node(None, None, ".", stat.S_IFDIR | 0o755, 0, 0)}
        self._node_ids: dict[tuple[_BackendName | None, str], int] = {(None, "."): 1}
        self._lookups: dict[int, int] = {1: 1}
        self._next_handle = 1
        self._handles: dict[int, tuple[_BackendName, int | str]] = {}
        self._closed = False

    @property
    def max_bytes(self) -> int:
        return self.private.max_bytes if self.private is not None else (1 << 63) - 1

    @property
    def used_bytes(self) -> int:
        return self.private.used_bytes if self.private is not None else 0

    @property
    def max_files(self) -> int:
        return self.private.max_files if self.private is not None else (1 << 31) - 1

    @property
    def file_count(self) -> int:
        return self.private.file_count if self.private is not None else 0

    @property
    def inode_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    def lookup(self, path: str) -> BackingNode:
        self._ensure_open()
        if path == ".":
            return self._backing(1)
        backend = self._route(path, Operation.LOOKUP)
        try:
            return self._remember(backend, backend.lookup(path))
        except OSError as error:
            if error.errno == errno.ENOENT and self._is_writable_rule_root(path):
                return self._remember_virtual(path)
            raise

    def stat(self, path: str) -> BackingNode:
        self._ensure_open()
        if path == ".":
            return self._backing(1)
        backend = self._route(path, Operation.STAT)
        try:
            return self._remember(backend, backend.stat(path))
        except OSError as error:
            if error.errno == errno.ENOENT and self._is_writable_rule_root(path):
                return self._remember_virtual(path)
            raise

    def node_path(self, inode: int) -> str:
        with self._lock:
            try:
                return self._nodes[inode].path
            except KeyError as error:
                raise OSError(errno.ENOENT, "unknown projected-home inode") from error

    def forget(self, inode: int, count: int) -> None:
        if inode == 1 or count < 0:
            return
        with self._lock:
            node = self._nodes.get(inode)
            if node is None:
                return
            remaining = max(0, self._lookups.get(inode, 0) - count)
            if remaining:
                self._lookups[inode] = remaining
                return
            self._nodes.pop(inode)
            self._node_ids.pop((node.backend, node.path), None)
            self._lookups.pop(inode, None)
        if node.backend is not None and node.backend_inode is not None:
            self._backend(node.backend).forget(node.backend_inode, count)

    def listdir(self, path: str = ".") -> tuple[str, ...]:
        self._ensure_open()
        if path == "." or any(rule.path.startswith(path + "/") for rule in self.profile.rules):
            return self._rule_children(path)
        backend = self._route(path, Operation.LIST)
        try:
            return backend.listdir(path)
        except OSError as error:
            if error.errno == errno.ENOENT and self._is_writable_rule_root(path):
                return ()
            raise

    def open(self, path: str, flags: int = os.O_RDONLY, mode: int = 0o600) -> int:
        self._ensure_open()
        operation = (
            Operation.WRITE if flags & (os.O_WRONLY | os.O_RDWR | os.O_TRUNC) else Operation.READ
        )
        backend = self._route(path, operation)
        if flags & os.O_CREAT:
            backend = self._route(path, Operation.CREATE)
            self._ensure_parents(backend, path)
        if flags & os.O_TRUNC:
            self._route(path, Operation.TRUNCATE)
        backend_name = self._backend_name(backend)
        if backend_name == "host":
            node = self.host_required.stat(path)
            if node.is_directory:
                raise OSError(errno.EISDIR, "directory is not a file")
            return self._remember_handle("host", path)
        handle = self._writable(backend).open(path, flags, mode)
        return self._remember_handle(backend_name, handle)

    def release(self, handle: int) -> None:
        with self._lock:
            entry = self._handles.pop(handle, None)
        if entry is None:
            return
        backend, native = entry
        if backend == "host":
            return
        assert isinstance(native, int)
        self._writable(self._backend(backend)).release(native)

    def read(self, handle: int, offset: int = 0, size: int = 131072) -> bytes:
        backend, native = self._handle(handle)
        if backend == "host":
            assert isinstance(native, str)
            return self.host_required.read(native, offset, size)
        assert isinstance(native, int)
        return self._writable(self._backend(backend)).read(native, offset, size)

    def write(self, handle: int, data: bytes, offset: int | None = None) -> int:
        backend, native = self._handle(handle)
        if backend == "host":
            raise OSError(errno.EROFS, "host projected-home paths are read-only")
        assert isinstance(native, int)
        return self._writable(self._backend(backend)).write(native, data, offset)

    def truncate(self, handle: int, size: int) -> None:
        backend, native = self._handle(handle)
        if backend == "host":
            raise OSError(errno.EROFS, "host projected-home paths are read-only")
        assert isinstance(native, int)
        self._writable(self._backend(backend)).truncate(native, size)

    def fsync(self, handle: int) -> None:
        backend, native = self._handle(handle)
        if backend == "host":
            return
        assert isinstance(native, int)
        self._writable(self._backend(backend)).fsync(native)

    def chmod(self, handle: int, mode: int) -> None:
        backend, native = self._handle(handle)
        if backend == "host":
            raise OSError(errno.EROFS, "host projected-home paths are read-only")
        assert isinstance(native, int)
        self._writable(self._backend(backend)).chmod(native, mode)

    def create(self, path: str, mode: int = 0o600) -> BackingNode:
        backend = self._route(path, Operation.CREATE)
        self._ensure_parents(backend, path)
        return self._remember(backend, self._writable(backend).create(path, mode))

    def mkdir(self, path: str, mode: int = 0o700) -> BackingNode:
        backend = self._route(path, Operation.MKDIR)
        self._ensure_parents(backend, path)
        return self._remember(backend, self._writable(backend).mkdir(path, mode))

    def unlink(self, path: str, *, directory: bool = False) -> None:
        backend = self._route(path, Operation.RMDIR if directory else Operation.UNLINK)
        self._writable(backend).unlink(path, directory=directory)

    def rename(self, source: str, destination: str) -> None:
        source_backend = self._route(source, Operation.RENAME)
        destination_backend = self._route(destination, Operation.RENAME)
        if source_backend is not destination_backend:
            raise OSError(errno.EXDEV, "projected-home rename crosses policy roots")
        self._ensure_parents(destination_backend, destination)
        self._writable(source_backend).rename(source, destination)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            handles = tuple(self._handles)
        for handle in handles:
            self.release(handle)
        for backend in (self.host, self.private, self.overlay):
            if backend is not None:
                backend.close()

    @property
    def host_required(self) -> HostReadonlyView:
        if self.host is None:
            raise OSError(errno.EACCES, "host projected-home backing is unavailable")
        return self.host

    def _route(self, path: str, operation: Operation) -> _Backend:
        decision = self.profile.decision(path, operation)
        if decision.rule is not None and decision.allowed:
            mode = decision.rule.mode
            if mode in {RuleMode.HOST_RO, RuleMode.HOST_RX}:
                return self.host_required
            if mode is RuleMode.PRIVATE_RW and self.private is not None:
                return self.private
            if mode is RuleMode.OVERLAY_RW and self.overlay is not None:
                return self.overlay
        if (
            operation in {Operation.LOOKUP, Operation.STAT}
            and decision.reason == "opaque ancestor traversal"
        ):
            return self.host_required
        # Host backing owns learning mediation and sealed hide/deny semantics.
        if self.host is not None and operation in {
            Operation.LOOKUP,
            Operation.STAT,
            Operation.LIST,
            Operation.READ,
        }:
            return self.host
        raise OSError(errno.EACCES, f"projected-home policy denied {operation} {path}")

    def _backend_name(self, backend: _Backend) -> _BackendName:
        if backend is self.host:
            return "host"
        if backend is self.private:
            return "private"
        if backend is self.overlay:
            return "overlay"
        raise OSError(errno.EIO, "unknown projected-home backend")

    def _backend(self, name: _BackendName) -> _Backend:
        if name == "host":
            return self.host_required
        if name == "private" and self.private is not None:
            return self.private
        if name == "overlay" and self.overlay is not None:
            return self.overlay
        raise OSError(errno.ESTALE, "projected-home backend is unavailable")

    @staticmethod
    def _writable(backend: _Backend) -> _WritableBackend:
        if isinstance(backend, HostReadonlyView):
            raise OSError(errno.EROFS, "host projected-home paths are read-only")
        return backend

    def _remember(self, backend: _Backend, node: BackingNode) -> BackingNode:
        name = self._backend_name(backend)
        key = (name, node.path)
        with self._lock:
            inode = self._node_ids.get(key)
            if inode is None:
                inode = self._next_inode
                self._next_inode += 1
                self._node_ids[key] = inode
                self._nodes[inode] = _Node(
                    name, node.inode, node.path, node.mode, node.size, node.mtime_ns
                )
            self._lookups[inode] = self._lookups.get(inode, 0) + 1
        return BackingNode(inode, node.path, node.mode, node.size, node.mtime_ns, node.is_directory)

    def _remember_virtual(self, path: str) -> BackingNode:
        key = (None, path)
        with self._lock:
            inode = self._node_ids.get(key)
            if inode is None:
                inode = self._next_inode
                self._next_inode += 1
                self._node_ids[key] = inode
                self._nodes[inode] = _Node(None, None, path, stat.S_IFDIR | 0o700, 0, 0)
            self._lookups[inode] = self._lookups.get(inode, 0) + 1
        return BackingNode(inode, path, stat.S_IFDIR | 0o700, 0, 0, True)

    def _backing(self, inode: int) -> BackingNode:
        node = self._nodes[inode]
        return BackingNode(
            inode, node.path, node.mode, node.size, node.mtime_ns, stat.S_ISDIR(node.mode)
        )

    def _remember_handle(self, backend: _BackendName, native: int | str) -> int:
        with self._lock:
            handle = self._next_handle
            self._next_handle += 1
            self._handles[handle] = (backend, native)
            return handle

    def _handle(self, handle: int) -> tuple[_BackendName, int | str]:
        with self._lock:
            try:
                return self._handles[handle]
            except KeyError as error:
                raise OSError(errno.EBADF, "unknown projected-home handle") from error

    def _is_writable_rule_root(self, path: str) -> bool:
        return any(
            rule.path == path
            and rule.scope is RuleScope.SUBTREE
            and rule.mode in {RuleMode.PRIVATE_RW, RuleMode.OVERLAY_RW}
            for rule in self.profile.rules
        )

    def _rule_children(self, path: str) -> tuple[str, ...]:
        prefix = "" if path == "." else path + "/"
        children = {
            rule.path[len(prefix) :].split("/", 1)[0]
            for rule in self.profile.rules
            if rule.path.startswith(prefix)
        }
        return tuple(sorted(children))

    def _ensure_parents(self, backend: _Backend, path: str) -> None:
        writable = self._writable(backend)
        parts = path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            parent = "/".join(parts[:index])
            try:
                writable.mkdir(parent, 0o700)
            except OSError as error:
                if error.errno != errno.EEXIST:
                    raise

    def _ensure_open(self) -> None:
        with self._lock:
            if self._closed:
                raise OSError(errno.ESTALE, "projected-home daemon is closed")
