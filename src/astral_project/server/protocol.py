"""Outer SSH framing. One `RemoteSessionRequestV1` precedes raw SFTP bytes."""

from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO, cast

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.cbor import canonical_loads
from astral_project.session.contracts import (
    MAX_REMOTE_SESSION_BYTES,
    RemoteSessionReadyV1,
    RemoteSessionRejectedV1,
    RemoteSessionRequestV1,
    read_remote_session_request,
    write_remote_session_request,
)

MAX_OUTER_SESSION_BYTES = MAX_REMOTE_SESSION_BYTES
_FRAME_HEADER = struct.Struct(">I")


def read_outer_request(stream: BinaryIO) -> RemoteSessionRequestV1:
    return read_remote_session_request(stream)


def write_outer_request(stream: BinaryIO, request: RemoteSessionRequestV1) -> None:
    write_remote_session_request(stream, request)


def write_outer_ready(stream: BinaryIO, ready: RemoteSessionReadyV1) -> None:
    _write_frame(stream, ready.canonical_bytes())


def write_outer_rejection(stream: BinaryIO, rejection: RemoteSessionRejectedV1) -> None:
    _write_frame(stream, rejection.canonical_bytes())


def read_outer_response(stream: BinaryIO) -> dict[str, object]:
    header = _read_exact(stream, _FRAME_HEADER.size)
    (length,) = _FRAME_HEADER.unpack(header)
    if not 0 < length <= MAX_OUTER_SESSION_BYTES:
        raise _frame_error("outer response length is outside protocol limit")
    decoded = canonical_loads(_read_exact(stream, length))
    if not isinstance(decoded, dict):
        raise _frame_error("outer response is not a map")
    return cast(dict[str, object], decoded)


def fuzz_outer_request(data: bytes) -> None:
    try:
        read_outer_request(BytesIO(data))
    except AstralError:
        return


def _write_frame(stream: BinaryIO, payload: bytes) -> None:
    if not 0 < len(payload) <= MAX_OUTER_SESSION_BYTES:
        raise _frame_error("outer response frame exceeds limit")
    stream.write(_FRAME_HEADER.pack(len(payload)))
    stream.write(payload)
    stream.flush()


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise _frame_error("truncated outer session frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _frame_error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PROTOCOL_FRAME,
        message=message,
        security_result="outer session request was rejected",
        unsafe_reason="outer session frames must be complete, bounded, and unambiguous",
        next_action="use compatible Astral Project session protocol",
    )
