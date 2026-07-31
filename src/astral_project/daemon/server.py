"""Same-UID local daemon control socket."""

from __future__ import annotations

import fcntl
import os
import socket
import stat
import struct
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import ensure_private_directory
from astral_project.daemon.protocol import encode, make_response, parse_request, receive
from astral_project.state.sqlite import StateDatabase


@dataclass(frozen=True, slots=True)
class DaemonPaths:
    runtime: Path
    state: Path

    @property
    def socket(self) -> Path:
        return self.runtime / "daemon.sock"

    @property
    def lock(self) -> Path:
        return self.runtime / "daemon.lock"


def _error(code: ErrorCode, message: str) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="daemon operation was rejected",
        unsafe_reason="main daemon control requires private same-user IPC",
        next_action="run `aspr doctor` and repair private runtime state",
    )


def _check_private_socket(path: Path) -> None:
    details = path.lstat()
    if (
        not stat.S_ISSOCK(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_mode & 0o077
    ):
        raise _error(ErrorCode.DAEMON_STARTUP, "daemon socket has unsafe ownership, type, or mode")


def peer_uid(connection: socket.socket) -> int:
    """Read Linux peer UID; no fallback exists for trusted daemon IPC."""
    credentials = connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    return int(struct.unpack("3i", credentials)[1])


class DaemonLock:
    """Advisory lock whose kernel lifetime prevents daemon-start races."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    def acquire(self) -> None:
        try:
            descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            with suppress(UnboundLocalError):
                os.close(descriptor)
            raise _error(ErrorCode.DAEMON_STARTUP, "another daemon owns startup lock") from error
        self._descriptor = descriptor

    def close(self) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None


class DaemonServer:
    """Small control daemon; only liveness/status operations exist in Packet 5."""

    def __init__(self, paths: DaemonPaths) -> None:
        self.paths = paths
        self._listener: socket.socket | None = None
        self._lock = DaemonLock(paths.lock)
        self._database: StateDatabase | None = None

    def start(self) -> None:
        ensure_private_directory(self.paths.runtime)
        self._lock.acquire()
        try:
            self._repair_stale_socket()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self.paths.socket))
            os.chmod(self.paths.socket, 0o600)
            _check_private_socket(self.paths.socket)
            listener.listen()
            self._database = StateDatabase.open(self.paths.state)
            self._listener = listener
        except Exception:
            self.close()
            raise

    def serve_forever(self) -> None:
        """Serve until process shutdown; trusted entry point owns lifecycle."""
        while True:
            self.serve_once()

    def serve_once(self) -> None:
        if self._listener is None:
            raise _error(ErrorCode.DAEMON_STARTUP, "daemon is not started")
        connection, _ = self._listener.accept()
        with connection:
            if peer_uid(connection) != os.getuid():
                return
            try:
                request = parse_request(receive(connection))
                response = self._response(request.operation)
                connection.sendall(encode(make_response(request, ok=True, result=response)))
            except AstralError as error:
                connection.sendall(
                    encode(
                        {
                            "kind": "error",
                            "message": error.message,
                            "version": 1,
                        }
                    )
                )

    def _response(self, operation: str) -> Mapping[str, object]:
        if operation == "ping":
            return {"alive": True}
        if operation == "status":
            if self._database is None:
                raise _error(ErrorCode.DAEMON_STARTUP, "state database is unavailable")
            return {"alive": True, "state_version": self._database.state_version}
        if operation == "cancel":
            return {"cancelled": True}
        raise _error(ErrorCode.DAEMON_PROTOCOL, "request operation is not permitted")

    def _repair_stale_socket(self) -> None:
        if not self.paths.socket.exists():
            return
        _check_private_socket(self.paths.socket)
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.1)
            probe.connect(str(self.paths.socket))
        except OSError:
            self.paths.socket.unlink()
        else:
            raise _error(ErrorCode.DAEMON_STARTUP, "daemon socket is already active")
        finally:
            probe.close()

    def close(self) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        with suppress(FileNotFoundError):
            self.paths.socket.unlink()
        self._lock.close()
