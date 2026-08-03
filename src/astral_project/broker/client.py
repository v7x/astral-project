"""Fixed Unix broker control client; sole descriptor transfer is SFTP stream FD."""

from __future__ import annotations

import array
import socket
import struct
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.session.broker import CreateNamespaceV1, NamespaceReadyV1, NamespaceRejectedV1

_FRAME_HEADER = struct.Struct(">I")
_MAX_RESPONSE_BYTES = 1 << 20


def request_namespace(
    socket_path: Path, request: CreateNamespaceV1, *, stream_descriptor: int
) -> NamespaceReadyV1 | NamespaceRejectedV1:
    """Send canonical request and exactly one local stream socket by SCM_RIGHTS."""
    if stream_descriptor < 0:
        raise _error("broker stream descriptor is invalid")
    payload = request.canonical_bytes()
    frame = _FRAME_HEADER.pack(len(payload)) + payload
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        connection.connect(str(socket_path))
        sent = connection.sendmsg(
            [frame],
            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [stream_descriptor]))],
        )
        if sent <= 0:
            raise _error("broker request made no progress")
        connection.sendall(frame[sent:])
        header = _read_exact(connection, _FRAME_HEADER.size)
        (length,) = _FRAME_HEADER.unpack(header)
        if not 0 < length <= _MAX_RESPONSE_BYTES:
            raise _error("broker response length is invalid")
        response = _read_exact(connection, length)
        try:
            return NamespaceReadyV1.from_cbor(response)
        except AstralError:
            return NamespaceRejectedV1.from_cbor(response)
    except OSError as error:
        raise _error("broker control connection failed") from error
    finally:
        connection.close()


def _read_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise _error("broker response is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="broker control request was rejected",
        unsafe_reason="outer session may transfer only one local SFTP stream descriptor",
        next_action="use enrolled remote session through installed broker",
    )
