"""Packet 15A parent-controlled UID/GID mapping for fixed native worker."""

from __future__ import annotations

import fcntl
import os
import select
import signal
import stat
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.session.broker import WORKER_FD_LAYOUT

_RELOCATION_FD_FLOOR: Final = 75
_MAPPING_HANDSHAKE_TIMEOUT_SECONDS: Final = 2.0
_STAGING_ROOT: Final = Path("/run/astral-project/staging")


@dataclass(frozen=True, slots=True)
class WorkerLaunchFds:
    """Broker-owned descriptors for fixed native worker ABI positions."""

    sealed_plan: int
    stream: int
    log: int
    sources: tuple[int, ...]
    runtime: int

    def __post_init__(self) -> None:
        if not self.sources or len(self.sources) > (
            WORKER_FD_LAYOUT.source_limit - WORKER_FD_LAYOUT.source_base
        ):
            raise _error("worker source descriptor count is invalid")
        descriptors = (self.sealed_plan, self.stream, self.log, *self.sources, self.runtime)
        if any(descriptor < 0 for descriptor in descriptors) or len(set(descriptors)) != len(
            descriptors
        ):
            raise _error("worker descriptors are invalid or aliased")

    def fixed_mapping(self) -> dict[int, int]:
        mapping = {
            WORKER_FD_LAYOUT.sealed_plan: self.sealed_plan,
            WORKER_FD_LAYOUT.stream: self.stream,
            WORKER_FD_LAYOUT.log: self.log,
            WORKER_FD_LAYOUT.runtime: self.runtime,
        }
        mapping.update(
            {
                WORKER_FD_LAYOUT.source_base + slot: descriptor
                for slot, descriptor in enumerate(self.sources)
            }
        )
        return mapping


@dataclass(slots=True)
class WorkerProcess:
    """One native worker after mapping continuation; parent owns reaping."""

    pid: int
    staging_path: Path | None = None
    _reaped: bool = field(default=False, init=False, repr=False)

    def wait(
        self,
        *,
        timeout_seconds: float | None = None,
        on_tick: Callable[[], None] | None = None,
    ) -> int:
        """Return raw wait status; timeout kills and reaps rather than orphaning authority."""
        if self._reaped or (timeout_seconds is not None and timeout_seconds <= 0):
            raise _error("worker wait state or timeout is invalid")
        deadline = None if timeout_seconds is None else time.monotonic() + timeout_seconds
        while True:
            if on_tick is not None:
                on_tick()
            waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
            if waited_pid == self.pid:
                self._reaped = True
                self._cleanup_staging()
                return status
            if deadline is not None and time.monotonic() >= deadline:
                _terminate_and_reap(self.pid)
                self._reaped = True
                self._cleanup_staging()
                raise _error("worker exceeded supervisor deadline")
            time.sleep(0.01)

    def terminate(self) -> None:
        if not self._reaped:
            _terminate_and_reap(self.pid)
            self._reaped = True
            self._cleanup_staging()

    def _cleanup_staging(self) -> None:
        if self.staging_path is None:
            return
        try:
            self.staging_path.rmdir()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise _error("worker staging cleanup failed", error) from error


@dataclass(frozen=True, slots=True)
class MappingWorker:
    """Fork fixed worker; only root broker parent writes child identity maps."""

    executable: Path

    def __post_init__(self) -> None:
        details = self.executable.lstat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_mode & 0o022
            or not details.st_mode & stat.S_IXUSR
        ):
            raise _error("namespace worker has unsafe ownership, type, mode, or executability")

    def run(self, *, uid: int, gid: int, launch_fds: WorkerLaunchFds | None = None) -> None:
        process = self.start(uid=uid, gid=gid, launch_fds=launch_fds)
        try:
            status = process.wait()
        except Exception:
            process.terminate()
            raise
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
            raise _error("namespace worker failed")

    def start(
        self, *, uid: int, gid: int, launch_fds: WorkerLaunchFds | None = None
    ) -> WorkerProcess:
        """Fork native worker, map its user namespace, then return sole reaping handle."""
        if min(uid, gid) < 0:
            raise _error("worker mapping identity is invalid")
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        continue_read, continue_write = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            try:
                os.close(ready_read)
                os.close(continue_write)
                _install_worker_fds(
                    ready_write,
                    continue_read,
                    {} if launch_fds is None else launch_fds.fixed_mapping(),
                )
                os.execve(str(self.executable), [str(self.executable)], {})
            except OSError:
                os._exit(111)
        os.close(ready_write)
        os.close(continue_read)
        try:
            if _read_mapping_ready(ready_read) != b"R":
                raise _error("namespace worker did not enter mapping wait")
            staging = _create_worker_staging(child, uid=uid, gid=gid)
            _write_identity_map(child, uid=uid, gid=gid)
            if os.write(continue_write, b"C") != 1:
                raise _error("namespace worker continuation write failed")
            return WorkerProcess(child, staging)
        except Exception:
            _terminate_and_reap(child)
            raise
        finally:
            os.close(ready_read)
            os.close(continue_write)


def _create_worker_staging(pid: int, *, uid: int, gid: int) -> Path:
    """Root precreates exact staging path before mapped child proceeds."""
    path = _STAGING_ROOT / str(pid)
    try:
        _STAGING_ROOT.mkdir(mode=0o711, exist_ok=True)
        _STAGING_ROOT.chmod(0o711)
        path.mkdir(mode=0o700)
        os.chown(path, uid, gid)
        return path
    except OSError as error:
        raise _error("could not create worker staging directory", error) from error


def _read_mapping_ready(descriptor: int) -> bytes:
    readable, _, _ = select.select([descriptor], [], [], _MAPPING_HANDSHAKE_TIMEOUT_SECONDS)
    if not readable:
        raise _error("namespace worker mapping handshake timed out")
    return os.read(descriptor, 1)


def _install_worker_sync_fds(ready_write: int, continue_read: int) -> None:
    """Install FD 3/4 without closing a channel during a descriptor collision."""
    _install_worker_fds(ready_write, continue_read, {})


def _install_worker_fds(
    ready_write: int, continue_read: int, fixed_descriptors: dict[int, int]
) -> None:
    """Install sole native ABI descriptor mapping collision-safely before exec."""
    mapping = {
        WORKER_FD_LAYOUT.mapping_ready: ready_write,
        WORKER_FD_LAYOUT.mapping_continue: continue_read,
        **fixed_descriptors,
    }
    destinations = tuple(mapping)
    sources = tuple(mapping.values())
    if len(set(destinations)) != len(destinations) or len(set(sources)) != len(sources):
        raise _error("worker fixed descriptor mapping aliases a channel")
    relocated: dict[int, int] = {}
    try:
        for destination, source in mapping.items():
            if source in destinations:
                duplicate = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, _RELOCATION_FD_FLOOR)
                os.close(source)
                relocated[destination] = duplicate
            else:
                relocated[destination] = source
        for destination, source in relocated.items():
            os.dup2(source, destination, inheritable=True)
        for source in relocated.values():
            os.close(source)
    except OSError:
        for source in relocated.values():
            with suppress(OSError):
                os.close(source)
        raise


def _write_identity_map(pid: int, *, uid: int, gid: int) -> None:
    proc = Path("/proc") / str(pid)
    try:
        (proc / "setgroups").write_text("deny\n", encoding="ascii")
    except FileNotFoundError:
        raise _error("namespace worker exited before identity mapping") from None
    except OSError as error:
        raise _error("could not deny worker supplementary groups", error) from error
    try:
        (proc / "uid_map").write_text(f"0 {uid} 1\n", encoding="ascii")
        (proc / "gid_map").write_text(f"0 {gid} 1\n", encoding="ascii")
    except OSError as error:
        raise _error("could not write worker UID/GID map", error) from error


def _terminate_and_reap(pid: int) -> None:
    with suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)
    with suppress(ChildProcessError):
        os.waitpid(pid, 0)


def _error(message: str, error: OSError | None = None) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="namespace mapping was rejected",
        unsafe_reason="only broker parent may assign native worker namespace identity",
        next_action="repair root-owned worker package and broker configuration",
        dependency_error=None if error is None else str(error),
    )
