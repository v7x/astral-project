"""Bounded JSON framing for local daemon control IPC."""

from __future__ import annotations

import json
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal, cast

from astral_project.core.errors import AstralError, ErrorCode

MAX_FRAME_BYTES = 64 * 1024
_PROTOCOL_VERSION = 1


@dataclass(frozen=True, slots=True)
class Request:
    request_id: str
    cancellation_id: str
    operation: Literal["ping", "status", "cancel"]


@dataclass(frozen=True, slots=True)
class Response:
    request_id: str
    cancellation_id: str
    ok: bool
    result: Mapping[str, object]


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_PROTOCOL,
        message=message,
        security_result="daemon request was rejected",
        unsafe_reason="local control protocol accepts only bounded typed messages",
        next_action="use a compatible Astral Project CLI",
    )


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise _error(f"{field} must be a non-empty string of at most 128 bytes")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as error:
        raise _error(f"{field} must be ASCII") from error
    return value


def encode(payload: Mapping[str, object]) -> bytes:
    """Encode one canonical transport frame."""
    try:
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise _error("frame payload is not JSON serializable") from error
    if not body or len(body) > MAX_FRAME_BYTES:
        raise _error("frame payload exceeds size limit")
    return struct.pack("!I", len(body)) + body


def receive(connection: object) -> dict[str, object]:
    """Read exactly one bounded frame from socket-like object."""
    receiver = connection.recv  # type: ignore[attr-defined]
    header = _read_exact(receiver, 4)
    length = struct.unpack("!I", header)[0]
    if not 0 < length <= MAX_FRAME_BYTES:
        raise _error("frame length is outside allowed range")
    try:
        payload = json.loads(_read_exact(receiver, length))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _error("frame payload is not valid JSON") from error
    if not isinstance(payload, dict):
        raise _error("frame payload must be an object")
    return payload


def _read_exact(receiver: Callable[[int], bytes], length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = receiver(remaining)
        if not isinstance(chunk, bytes) or not chunk:
            raise _error("frame ended before declared length")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def parse_request(payload: Mapping[str, object]) -> Request:
    """Validate one request frame; reject unknown fields and operations."""
    if set(payload) != {"cancellation_id", "kind", "operation", "request_id", "version"}:
        raise _error("request fields are invalid")
    if payload["version"] != _PROTOCOL_VERSION or payload["kind"] != "request":
        raise _error("request protocol version or kind is invalid")
    operation = payload["operation"]
    if operation not in {"ping", "status", "cancel"}:
        raise _error("request operation is not permitted")
    return Request(
        request_id=_identifier(payload["request_id"], "request_id"),
        cancellation_id=_identifier(payload["cancellation_id"], "cancellation_id"),
        operation=cast(Literal["ping", "status", "cancel"], operation),
    )


def make_response(request: Request, *, ok: bool, result: Mapping[str, object]) -> dict[str, object]:
    """Build response paired with request and cancellation identifiers."""
    return {
        "cancellation_id": request.cancellation_id,
        "kind": "response",
        "ok": ok,
        "request_id": request.request_id,
        "result": dict(result),
        "version": _PROTOCOL_VERSION,
    }
