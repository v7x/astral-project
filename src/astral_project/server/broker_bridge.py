"""Fixed forced-entry bridge from SSH stdio to broker-owned SFTP stream socket."""

from __future__ import annotations

import socket
import threading
import uuid
from pathlib import Path
from typing import BinaryIO

from astral_project.broker.client import request_namespace
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.session.broker import CreateNamespaceV1, NamespaceReadyV1
from astral_project.session.contracts import RemoteSessionRequestV1

BROKER_SOCKET = Path("/run/astral-project/broker.sock")
_COPY_BYTES = 65536


def open_broker_sftp_stream(request: RemoteSessionRequestV1) -> socket.socket:
    """Transfer worker stream socket to broker; retain only opposite bridge endpoint."""
    bridge, worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
    try:
        result = request_namespace(
            BROKER_SOCKET,
            CreateNamespaceV1(
                request_id=uuid.uuid4().bytes,
                session_id=uuid.UUID(request.session_id.value).bytes,
                grant_envelope=request.signed_grant.to_cbor(),
                client_nonce=request.session_nonce,
            ),
            stream_descriptor=worker.fileno(),
        )
        if not isinstance(result, NamespaceReadyV1):
            raise _error("broker rejected namespace request")
        if result.session_id != uuid.UUID(request.session_id.value).bytes:
            raise _error("broker returned mismatched session identifier")
        return bridge
    except Exception:
        bridge.close()
        raise
    finally:
        worker.close()


def bridge_sftp_stream(stream: socket.socket, *, stdin: BinaryIO, stdout: BinaryIO) -> None:
    """Forward raw bytes only after outer ready frame; stderr never enters stream."""
    input_thread = threading.Thread(target=_copy_stdin_to_stream, args=(stdin, stream), daemon=True)
    input_thread.start()
    try:
        while True:
            chunk = stream.recv(_COPY_BYTES)
            if not chunk:
                return
            stdout.write(chunk)
            stdout.flush()
    finally:
        stream.close()
        input_thread.join(timeout=1)


def _copy_stdin_to_stream(stdin: BinaryIO, stream: socket.socket) -> None:
    try:
        while chunk := stdin.read(_COPY_BYTES):
            stream.sendall(chunk)
        stream.shutdown(socket.SHUT_WR)
    except (OSError, ValueError):
        return


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="broker SFTP bridge was rejected",
        unsafe_reason="forced SSH entry transfers only fixed SFTP socket to authenticated broker",
        next_action="use enrolled session with running root broker",
    )
