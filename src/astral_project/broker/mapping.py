"""Packet 15A parent-controlled UID/GID mapping for fixed native worker."""

from __future__ import annotations

import fcntl
import os
import signal
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode


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

    def run(self, *, uid: int, gid: int) -> None:
        if min(uid, gid) < 0:
            raise _error("worker mapping identity is invalid")
        ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
        continue_read, continue_write = os.pipe2(os.O_CLOEXEC)
        child = os.fork()
        if child == 0:
            try:
                os.close(ready_read)
                os.close(continue_write)
                _install_worker_sync_fds(ready_write, continue_read)
                os.execve(str(self.executable), [str(self.executable)], {})
            except OSError:
                os._exit(111)
        os.close(ready_write)
        os.close(continue_read)
        try:
            if os.read(ready_read, 1) != b"R":
                raise _error("namespace worker did not enter mapping wait")
            _write_identity_map(child, uid=uid, gid=gid)
            if os.write(continue_write, b"C") != 1:
                raise _error("namespace worker continuation write failed")
            _, status = os.waitpid(child, 0)
            if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                raise _error("namespace worker mapping failed")
        except Exception:
            _terminate_and_reap(child)
            raise
        finally:
            os.close(ready_read)
            os.close(continue_write)


def _install_worker_sync_fds(ready_write: int, continue_read: int) -> None:
    """Install FD 3/4 without closing a channel during a descriptor collision."""
    destinations = (3, 4)
    sources = (ready_write, continue_read)
    relocated: list[int] = []
    try:
        for source in sources:
            if source in destinations:
                duplicate = fcntl.fcntl(source, fcntl.F_DUPFD_CLOEXEC, 8)
                os.close(source)
                relocated.append(duplicate)
            else:
                relocated.append(source)
        for source, destination in zip(relocated, destinations, strict=True):
            os.dup2(source, destination, inheritable=True)
        for source in relocated:
            if source not in destinations:
                os.close(source)
    except OSError:
        for source in relocated:
            if source not in destinations:
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
