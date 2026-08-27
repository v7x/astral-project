"""Private per-rclone transport capability and byte-clean stream bridge."""

from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Protocol, cast

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import ensure_private_directory
from astral_project.sandbox.environment import sanitize_subprocess_environment
from astral_project.server.protocol import read_outer_response, write_outer_request
from astral_project.session.contracts import RemoteSessionRequestV1

MAX_TRANSPORT_FRAME = 64 * 1024
COPY_BYTES = 64 * 1024


class DuplexStream(Protocol):
    def recv(self, length: int) -> bytes: ...
    def sendall(self, data: bytes) -> None: ...
    def close(self) -> None: ...


def _error(message: str, *, code: ErrorCode = ErrorCode.DAEMON_PROTOCOL) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="private transport request was rejected",
        unsafe_reason="rclone transport receives only one daemon-bound SFTP stream",
        next_action="use daemon-created transport capability and exact SFTP invocation",
    )


def parse_external_ssh_argv(argv: Sequence[str]) -> tuple[str, str]:
    """Accept exactly rclone's SFTP subsystem argv and nothing else."""
    if tuple(argv) != ("-s", "sftp"):
        raise _error(
            "transport accepts only exact rclone SFTP subsystem argv",
            code=ErrorCode.PROTOCOL_COMMAND,
        )
    return "-s", "sftp"


@dataclass(frozen=True, slots=True)
class TransportEnvironment:
    """Environment values supplied only to one daemon-supervised wrapper."""

    socket_path: Path
    token: str

    def __post_init__(self) -> None:
        if not self.socket_path.is_absolute() or not self.token or len(self.token) > 256:
            raise _error("transport capability environment is invalid")

    def as_dict(self) -> dict[str, str]:
        return {
            "ASPR_TRANSPORT_SOCKET": str(self.socket_path),
            "ASPR_TRANSPORT_TOKEN": self.token,
        }


@dataclass(frozen=True, slots=True)
class TransportCapability:
    """Random bearer token and private socket path for one rclone process."""

    environment: TransportEnvironment

    @classmethod
    def create(cls, directory: Path) -> TransportCapability:
        ensure_private_directory(directory)
        path = directory / f"transport-{secrets.token_hex(12)}.sock"
        token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
        return cls(TransportEnvironment(path, token))


class PrivateTransportServer:
    """One-shot private listener that opens exactly one daemon-selected stream."""

    def __init__(
        self,
        capability: TransportCapability,
        stream_factory: Callable[[], DuplexStream],
    ) -> None:
        self.capability = capability
        self.stream_factory = stream_factory
        self._listener: socket.socket | None = None

    def start(self) -> None:
        path = self.capability.environment.socket_path
        ensure_private_directory(path.parent)
        with suppress(FileNotFoundError):
            path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        try:
            listener.bind(str(path))
            os.chmod(path, 0o600)
            listener.listen(1)
            self._listener = listener
        except Exception:
            listener.close()
            with suppress(FileNotFoundError):
                path.unlink()
            raise

    def serve_forever(self) -> None:
        """Serve concurrent exact SFTP connections until listener shutdown."""
        if self._listener is None:
            raise _error("private transport server is not started", code=ErrorCode.DAEMON_STARTUP)
        while self._listener is not None:
            try:
                connection, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(
                target=self._serve_connection,
                args=(connection,),
                daemon=True,
            ).start()

    def serve_once(self) -> None:
        if self._listener is None:
            raise _error("private transport server is not started", code=ErrorCode.DAEMON_STARTUP)
        connection, _ = self._listener.accept()
        self._serve_connection(connection)

    def _serve_connection(self, connection: socket.socket) -> None:
        with connection:
            try:
                request = _read_frame(connection)
                if request.get("version") != 1 or request.get("operation") != "open_sftp":
                    raise _error("private transport request is invalid")
                if request.get("token") != self.capability.environment.token:
                    raise _error("private transport token is invalid", code=ErrorCode.DAEMON_AUTH)
                stream = self.stream_factory()
                try:
                    _write_frame(connection, {"version": 1, "ok": True})
                    _bridge_socket_stream(connection, stream)
                finally:
                    stream.close()
            except AstralError as error:
                print(error.to_text(), file=sys.stderr, flush=True)
                with suppress(OSError):
                    _write_frame(
                        connection, {"version": 1, "ok": False, "error": error.code.string}
                    )
                return

    def close(self) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        with suppress(FileNotFoundError):
            self.capability.environment.socket_path.unlink()


def run_transport(
    argv: Sequence[str],
    *,
    environment: Mapping[str, str],
    stdin: BinaryIO,
    stdout: BinaryIO,
    stderr: BinaryIO,
) -> int:
    """Run external wrapper; stdout is raw SFTP bytes after private handshake."""
    try:
        parse_external_ssh_argv(argv)
        socket_path = _absolute_environment(environment, "ASPR_TRANSPORT_SOCKET")
        token = environment.get("ASPR_TRANSPORT_TOKEN", "")
        if not token:
            raise _error("ASPR_TRANSPORT_TOKEN is missing", code=ErrorCode.DAEMON_AUTH)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(5.0)
        connection.connect(str(socket_path))
        _write_frame(connection, {"version": 1, "operation": "open_sftp", "token": token})
        response = _read_frame(connection)
        if response.get("ok") is not True:
            raise _error("private transport server rejected stream", code=ErrorCode.DAEMON_AUTH)
        connection.settimeout(None)
        _bridge_stdio(connection, stdin=stdin, stdout=stdout)
        return 0
    except (AstralError, OSError) as error:
        if isinstance(error, AstralError):
            rendered = error.to_text()
        else:
            rendered = _error(
                "private transport connection failed", code=ErrorCode.DAEMON_UNAVAILABLE
            ).to_text()
        stderr.write((rendered + "\n").encode("utf-8"))
        return 70


def fixed_ssh_argv(
    *,
    ssh_binary: Path,
    identity_file: Path,
    host: str,
    remote_user: str,
    port: int = 22,
    known_hosts: Path | None = None,
) -> list[str]:
    """Build fixed SSH argv; caller cannot supply command or options."""
    if (
        not ssh_binary.is_absolute()
        or not identity_file.is_absolute()
        or (known_hosts is not None and not known_hosts.is_absolute())
        or not host
        or not remote_user
    ):
        raise _error("SSH transport identity or endpoint is invalid")
    if not 1 <= port <= 65535 or any(character.isspace() for character in host + remote_user):
        raise _error("SSH transport endpoint is invalid")
    return [
        str(ssh_binary),
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts or Path.home() / '.ssh' / 'known_hosts'}",
        "-o",
        "RequestTTY=no",
        "-i",
        str(identity_file),
        "-p",
        str(port),
        f"{remote_user}@{host}",
        "aspr-channel-v1",
    ]


class ProcessStream:
    """Duplex adapter over one fixed SSH subprocess."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        if process.stdin is None or process.stdout is None:
            raise _error("SSH process did not expose bidirectional pipes")
        self.process = process
        self._stdin = process.stdin
        self._stdout = process.stdout

    def recv(self, length: int) -> bytes:
        return self._read_stdout(length)

    def read(self, length: int = -1) -> bytes:
        return self._read_stdout(length)

    def _read_stdout(self, length: int) -> bytes:
        read1 = getattr(self._stdout, "read1", None)
        if callable(read1):
            return cast(Callable[[int], bytes], read1)(length)
        return self._stdout.read(length)

    def sendall(self, data: bytes) -> None:
        self._stdin.write(data)
        self._stdin.flush()

    def shutdown_write(self) -> None:
        with suppress(OSError, ValueError):
            self._stdin.close()

    def write(self, data: bytes) -> int:
        self.sendall(data)
        return len(data)

    def flush(self) -> None:
        self._stdin.flush()

    def close(self) -> None:
        with suppress(OSError, ValueError):
            self._stdin.close()
        with suppress(OSError, ValueError):
            self._stdout.close()
        with suppress(OSError):
            self.process.terminate()
        with suppress(OSError):
            self.process.wait(timeout=2)


def open_remote_sftp_stream(
    request: RemoteSessionRequestV1,
    *,
    ssh_binary: Path,
    identity_file: Path,
    host: str,
    remote_user: str,
    port: int = 22,
    known_hosts: Path | None = None,
) -> ProcessStream:
    """Open fixed forced-command SSH stream and consume outer Ready frame."""
    process = subprocess.Popen(
        fixed_ssh_argv(
            ssh_binary=ssh_binary,
            identity_file=identity_file,
            host=host,
            remote_user=remote_user,
            port=port,
            known_hosts=known_hosts,
        ),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,
        close_fds=True,
        env=sanitize_subprocess_environment(
            os.environ,
            visible_paths=(
                Path("/usr"),
                Path("/bin"),
                Path("/sbin"),
                Path("/lib"),
                Path("/lib64"),
            ),
        ),
    )
    stream = ProcessStream(process)
    try:
        assert process.stdin is not None and process.stdout is not None
        write_outer_request(cast(BinaryIO, process.stdin), request)
        response = read_outer_response(cast(BinaryIO, process.stdout))
        if response.get("status") != "ready":
            raise _error(
                "remote server rejected SFTP session"
                + (f": {response.get('error_code')}" if response.get("error_code") else "")
            )
        return stream
    except Exception:
        stream.close()
        raise


def _absolute_environment(environment: Mapping[str, str], name: str) -> Path:
    value = environment.get(name)
    if not value or not Path(value).is_absolute():
        raise _error(f"{name} must be an absolute path")
    return Path(value)


def _write_frame(connection: socket.socket, payload: Mapping[str, object]) -> None:
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if not body or len(body) > MAX_TRANSPORT_FRAME:
        raise _error("private transport frame is too large")
    connection.sendall(struct.pack(">I", len(body)) + body)


def _read_frame(connection: socket.socket) -> dict[str, object]:
    header = _recv_exact(connection, 4)
    length = struct.unpack(">I", header)[0]
    if not 0 < length <= MAX_TRANSPORT_FRAME:
        raise _error("private transport frame length is invalid")
    try:
        payload = json.loads(_recv_exact(connection, length))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _error("private transport frame is not JSON") from error
    if not isinstance(payload, dict):
        raise _error("private transport frame is not an object")
    return payload


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise _error("private transport frame was truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _bridge_socket_stream(left: socket.socket, right: DuplexStream) -> None:
    errors: list[BaseException] = []

    def left_to_right() -> None:
        try:
            while chunk := left.recv(COPY_BYTES):
                right.sendall(chunk)
            shutdown_write = getattr(right, "shutdown_write", None)
            if callable(shutdown_write):
                shutdown_write()
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=left_to_right, daemon=True)
    thread.start()
    try:
        while chunk := right.recv(COPY_BYTES):
            left.sendall(chunk)
    except OSError:
        pass
    finally:
        thread.join(timeout=2)


def _bridge_stdio(connection: socket.socket, *, stdin: BinaryIO, stdout: BinaryIO) -> None:
    errors: list[BaseException] = []

    def stdin_to_socket() -> None:
        try:
            while chunk := stdin.read(COPY_BYTES):
                connection.sendall(chunk)
            connection.shutdown(socket.SHUT_WR)
        except (OSError, ValueError) as error:
            errors.append(error)

    thread = threading.Thread(target=stdin_to_socket, daemon=True)
    thread.start()
    try:
        while chunk := connection.recv(COPY_BYTES):
            stdout.write(chunk)
            stdout.flush()
    finally:
        connection.close()
        thread.join(timeout=2)
