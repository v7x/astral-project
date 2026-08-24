"""Narrow bearer session socket exposed inside one sandbox."""

from __future__ import annotations

import json
import os
import socket
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode

_MAX_LINE = 16 * 1024
_ALLOWED = frozenset(
    {"DescribeSession", "RunLs", "GetRemoteMounts", "GetExpiry", "CloseOwnSession"}
)


class SessionApiServer:
    """Serve only read/session-close operations; never forward arbitrary daemon IPC."""

    def __init__(
        self,
        path: Path,
        *,
        session_id: str,
        describe: Callable[[], Mapping[str, object]],
        mounts: Callable[[], list[Mapping[str, object]]],
        expiry: Callable[[], int],
        close: Callable[[], Mapping[str, object]],
        run_ls: Callable[[Mapping[str, object]], Mapping[str, object]] | None = None,
    ) -> None:
        if not path.is_absolute() or not session_id:
            raise _error("sandbox session socket path or identity is invalid")
        self.path = path
        self.session_id = session_id
        self._describe = describe
        self._mounts = mounts
        self._expiry = expiry
        self._close = close
        self._run_ls = run_ls
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        with suppress(FileNotFoundError):
            self.path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(self.path))
        # Socket inode crosses an unprivileged user namespace through bwrap.
        # Parent directory remains 0700; bearer session ID supplies per-session binding.
        os.chmod(self.path, 0o666)
        listener.listen(8)
        listener.settimeout(0.2)
        self._listener = listener
        self._thread = threading.Thread(
            target=self._serve, name="aspr-sandbox-session", daemon=True
        )
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        if listener is not None:
            listener.close()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2)
        with suppress(FileNotFoundError):
            self.path.unlink()

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop.is_set():
            try:
                connection, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            with connection:
                self._handle(connection)

    def _handle(self, connection: socket.socket) -> None:
        try:
            raw = _read_line(connection)
            request = json.loads(raw)
            if not isinstance(request, dict):
                raise _error("sandbox session request fields are invalid")
            method = request.get("method")
            session_id = request.get("session_id")
            if not isinstance(method, str) or method not in _ALLOWED:
                raise _error("sandbox session method is not permitted")
            expected = {"method", "session_id"}
            if method == "RunLs":
                expected.add("payload")
                if not isinstance(request.get("payload"), dict):
                    raise _error("sandbox session listing payload is invalid")
            if set(request) != expected:
                raise _error("sandbox session request fields are invalid")
            if session_id != self.session_id:
                raise _error("sandbox session identity is invalid")
            result: Mapping[str, object]
            if method == "DescribeSession":
                result = self._describe()
            elif method == "RunLs":
                if self._run_ls is None:
                    raise _error("sandbox session listing is unavailable")
                result = self._run_ls(request["payload"])
            elif method == "GetRemoteMounts":
                result = {"mounts": self._mounts()}
            elif method == "GetExpiry":
                result = {"expires_at": self._expiry()}
            else:
                result = self._close()
            _write(connection, {"ok": True, "result": dict(result)})
        except (AstralError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            if not isinstance(error, AstralError):
                error = _error("sandbox session request encoding is invalid")
            _write(connection, {"ok": False, "error": error.to_dict()})


class SessionApiClient:
    """Call only the fixed API on one already-bound sandbox session socket."""

    def __init__(self, path: Path, *, session_id: str, timeout: float = 60.0) -> None:
        if not path.is_absolute() or not session_id or timeout <= 0:
            raise _error("sandbox session client configuration is invalid")
        self.path = path
        self.session_id = session_id
        self.timeout = timeout

    def request(
        self, method: str, payload: Mapping[str, object] | None = None
    ) -> Mapping[str, object]:
        request: dict[str, object] = {"method": method, "session_id": self.session_id}
        if method == "RunLs":
            if payload is None:
                raise _error("sandbox session listing payload is missing")
            request["payload"] = dict(payload)
        elif payload is not None:
            raise _error("sandbox session method does not accept a payload")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(str(self.path))
                connection.sendall(
                    json.dumps(request, separators=(",", ":"), sort_keys=True).encode() + b"\n"
                )
                response = json.loads(_read_line(connection))
        except OSError as error:
            raise _error(f"sandbox session socket is unavailable: {error}") from error
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as error:
            raise _error("sandbox session response encoding is invalid") from error
        if not isinstance(response, dict) or response.get("ok") is not True:
            detail = response.get("error") if isinstance(response, dict) else None
            message = detail.get("message") if isinstance(detail, dict) else None
            raise _error(message if isinstance(message, str) else "sandbox session request failed")
        result = response.get("result")
        if not isinstance(result, dict):
            raise _error("sandbox session response result is invalid")
        return result


def _read_line(connection: socket.socket) -> str:
    data = bytearray()
    while len(data) <= _MAX_LINE:
        chunk = connection.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if not data or len(data) > _MAX_LINE or b"\n" not in data:
        raise _error("sandbox session request is too large or incomplete")
    return bytes(data).split(b"\n", 1)[0].decode("utf-8")


def _write(connection: socket.socket, payload: Mapping[str, object]) -> None:
    connection.sendall(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode() + b"\n")


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="sandbox session request was rejected",
        unsafe_reason="session bearer socket exposes only fixed same-session operations",
        next_action="use the installed sandbox session client",
    )
