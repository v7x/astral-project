"""Race-safe empty projected-home state used by the FUSE adapter and tests."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from threading import Lock, Semaphore
from typing import Final

ROOT_INODE: Final[int] = 1


class HomedError(OSError):
    """Projected-home operation failed with a stable errno."""

    def __init__(self, error: int, message: str) -> None:
        super().__init__(error, message)


@dataclass(frozen=True, slots=True)
class InodeRecord:
    inode: int
    mode: int
    size: int = 0


class InodeTable:
    """Synthetic inode table with explicit kernel lookup references."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._records: dict[int, InodeRecord] = {
            ROOT_INODE: InodeRecord(ROOT_INODE, stat.S_IFDIR | 0o755)
        }
        self._lookups: dict[int, int] = {ROOT_INODE: 1}

    def getattr(self, inode: int) -> InodeRecord:
        with self._lock:
            try:
                return self._records[inode]
            except KeyError as error:
                raise HomedError(errno.ENOENT, "unknown inode") from error

    def lookup_root(self, name: bytes) -> InodeRecord:
        if name in {b".", b".."}:
            with self._lock:
                self._lookups[ROOT_INODE] = self._lookups.get(ROOT_INODE, 0) + 1
                return self._records[ROOT_INODE]
        raise HomedError(errno.ENOENT, "empty projected home has no entries")

    def forget(self, inode: int, count: int) -> None:
        if count < 0:
            return
        with self._lock:
            if inode not in self._records:
                return
            self._lookups[inode] = max(0, self._lookups.get(inode, 0) - count)
            if inode != ROOT_INODE and self._lookups[inode] == 0:
                self._lookups.pop(inode, None)
                self._records.pop(inode, None)

    def lookup_count(self, inode: int) -> int:
        with self._lock:
            return self._lookups.get(inode, 0)


class FileHandleTable:
    """Distinct per-open handles; release is idempotent."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._next = 1
        self._handles: set[int] = set()

    def allocate(self, inode: int) -> int:
        if inode == ROOT_INODE:
            raise HomedError(errno.EISDIR, "root is a directory")
        with self._lock:
            handle = self._next
            self._next += 1
            self._handles.add(handle)
            return handle

    def release(self, handle: int) -> None:
        with self._lock:
            self._handles.discard(handle)

    def contains(self, handle: int) -> bool:
        with self._lock:
            return handle in self._handles

    def close_all(self) -> None:
        with self._lock:
            self._handles.clear()


class RequestBudget:
    """Bound in-flight requests and declared payload memory."""

    def __init__(self, max_requests: int = 256, max_memory: int = 16 * 1024 * 1024) -> None:
        if max_requests <= 0 or max_memory <= 0:
            raise ValueError("request limits must be positive")
        self.max_requests = max_requests
        self.max_memory = max_memory
        self._requests = Semaphore(max_requests)
        self._lock = Lock()
        self._memory = 0

    def reserve(self, size: int) -> None:
        if size < 0 or size > self.max_memory:
            raise HomedError(errno.ENOMEM, "request payload exceeds memory budget")
        if not self._requests.acquire(blocking=False):
            raise HomedError(errno.EAGAIN, "projected-home request queue is full")
        with self._lock:
            if self._memory + size > self.max_memory:
                self._requests.release()
                raise HomedError(errno.ENOMEM, "projected-home memory budget is full")
            self._memory += size

    def release(self, size: int) -> None:
        with self._lock:
            self._memory = max(0, self._memory - max(0, size))
        self._requests.release()

    @property
    def memory_used(self) -> int:
        with self._lock:
            return self._memory


class RequestLease:
    """RAII request reservation; cancellation and exceptions always release state."""

    def __init__(self, budget: RequestBudget, size: int) -> None:
        self._budget = budget
        self._size = size
        self._active = True
        budget.reserve(size)

    def cancel(self) -> None:
        if self._active:
            self._active = False
            self._budget.release(self._size)

    def __enter__(self) -> RequestLease:
        return self

    def __exit__(self, *_: object) -> None:
        self.cancel()


class EmptyProjectedHome:
    """Empty filesystem state; no host paths are reachable in Packet 25."""

    def __init__(self, budget: RequestBudget | None = None) -> None:
        self.inodes = InodeTable()
        self.handles = FileHandleTable()
        self.budget = budget or RequestBudget()
        self._closed = False
        self._lock = Lock()

    def lookup(self, parent: int, name: bytes) -> InodeRecord:
        self._ensure_open()
        if parent != ROOT_INODE:
            raise HomedError(errno.ENOENT, "unknown parent inode")
        return self.inodes.lookup_root(name)

    def getattr(self, inode: int) -> InodeRecord:
        self._ensure_open()
        return self.inodes.getattr(inode)

    def open(self, inode: int, flags: int) -> int:
        self._ensure_open()
        record = self.inodes.getattr(inode)
        if stat.S_ISDIR(record.mode):
            raise HomedError(errno.EISDIR, "root is a directory")
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_TRUNC):
            raise HomedError(errno.EROFS, "empty projected home is read-only")
        return self.handles.allocate(inode)

    def release(self, handle: int) -> None:
        self.handles.release(handle)

    def forget(self, inode: int, count: int) -> None:
        self.inodes.forget(inode, count)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self.handles.close_all()

    def _ensure_open(self) -> None:
        with self._lock:
            if self._closed:
                raise HomedError(errno.ESTALE, "projected-home daemon is closed")
