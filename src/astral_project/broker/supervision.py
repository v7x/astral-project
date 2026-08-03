"""Bounded native-worker stderr capture and terminal status supervision."""

from __future__ import annotations

import os
from contextlib import suppress
from dataclasses import dataclass, field

from astral_project.broker.mapping import WorkerProcess
from astral_project.core.errors import AstralError, ErrorCode

_MAX_WORKER_LOG_BYTES = 65536


@dataclass(slots=True)
class WorkerLogPipe:
    """Worker-only write end; parent drains bounded diagnostic bytes outside SFTP stream."""

    read_descriptor: int
    write_descriptor: int
    _content: bytearray = field(default_factory=bytearray, init=False, repr=False)
    _truncated: bool = field(default=False, init=False, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    @classmethod
    def create(cls) -> WorkerLogPipe:
        read_descriptor, write_descriptor = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        return cls(read_descriptor, write_descriptor)

    def drain(self) -> None:
        """Drain until empty; discard overflow so stderr cannot stall worker progress."""
        if self._closed:
            return
        while True:
            try:
                chunk = os.read(self.read_descriptor, 8192)
            except BlockingIOError:
                return
            if not chunk:
                return
            remaining = _MAX_WORKER_LOG_BYTES - len(self._content)
            if remaining > 0:
                self._content.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self._truncated = True

    def worker_write_descriptor(self) -> int:
        """Return write end for FD 7; parent closes its copy after successful fork."""
        if self._closed or self.write_descriptor < 0:
            raise _error("worker log write descriptor is unavailable")
        return self.write_descriptor

    def close_parent_write_descriptor(self) -> None:
        if self.write_descriptor >= 0:
            os.close(self.write_descriptor)
            self.write_descriptor = -1

    def result(self) -> tuple[bytes, bool]:
        self.drain()
        return bytes(self._content), self._truncated

    def close(self) -> None:
        if self._closed:
            return
        for descriptor in (self.read_descriptor, self.write_descriptor):
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
        self._closed = True


@dataclass(frozen=True, slots=True)
class WorkerTermination:
    exit_code: int | None
    signal: int | None
    stderr: bytes
    stderr_truncated: bool


def supervise_worker(
    process: WorkerProcess, logs: WorkerLogPipe, *, timeout_seconds: float
) -> WorkerTermination:
    """Wait with log draining; caller treats every nonzero/signal result as launch failure."""
    try:
        status = process.wait(timeout_seconds=timeout_seconds, on_tick=logs.drain)
        stderr, truncated = logs.result()
        if os.WIFEXITED(status):
            return WorkerTermination(os.WEXITSTATUS(status), None, stderr, truncated)
        if os.WIFSIGNALED(status):
            return WorkerTermination(None, os.WTERMSIG(status), stderr, truncated)
        raise _error("worker has unsupported terminal status")
    finally:
        logs.close()


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="worker lifecycle was rejected",
        unsafe_reason="worker diagnostics and termination must remain bounded outside SFTP stream",
        next_action="repair root-owned worker package and retry authenticated session",
    )
