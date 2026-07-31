"""Bounded remote preface framing before any remote path operation."""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import BinaryIO, cast

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.cbor import CborValue, canonical_dumps, canonical_loads
from astral_project.crypto.grants import SignedGrant

PREFACE_VERSION = 1
MAX_PREFACE_BYTES = 1 << 20
MAX_NONCE_BYTES = 64
_FRAME_HEADER = struct.Struct(">I")


class PrefaceOperation(StrEnum):
    VALIDATE = "validate"
    OPEN_SFTP = "open_sftp"
    REVOKE = "revoke"
    HEALTH = "health"


@dataclass(frozen=True, slots=True)
class Preface:
    """Authenticated request envelope; grant bytes remain canonical and opaque here."""

    operation: PrefaceOperation
    nonce: bytes
    signed_grant: SignedGrant

    def __post_init__(self) -> None:
        if not 1 <= len(self.nonce) <= MAX_NONCE_BYTES:
            raise _frame_error("preface nonce length is invalid")

    def to_bytes(self) -> bytes:
        return canonical_dumps(
            {
                "grant": self.signed_grant.to_cbor(),
                "nonce": self.nonce,
                "operation": self.operation.value,
                "version": PREFACE_VERSION,
            }
        )

    @classmethod
    def from_bytes(cls, payload: bytes) -> Preface:
        try:
            value = canonical_loads(payload)
        except AstralError as error:
            raise _frame_error("preface CBOR is invalid") from error
        if not isinstance(value, Mapping) or set(value) != {
            "grant",
            "nonce",
            "operation",
            "version",
        }:
            raise _frame_error("preface field set is invalid")
        version = value["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise _frame_error("preface version is invalid")
        if version != PREFACE_VERSION:
            raise _version_error("preface protocol version is unsupported")
        nonce = value["nonce"]
        grant = value["grant"]
        operation = value["operation"]
        if (
            not isinstance(nonce, bytes)
            or not isinstance(grant, bytes)
            or not isinstance(operation, str)
        ):
            raise _frame_error("preface field type is invalid")
        try:
            return cls(PrefaceOperation(operation), nonce, SignedGrant.from_cbor(grant))
        except ValueError as error:
            raise _frame_error("preface operation is unsupported") from error


def read_preface(stream: BinaryIO) -> Preface:
    """Read exactly one bounded length-prefixed preface. Never consume SFTP bytes."""
    header = _read_exact(stream, _FRAME_HEADER.size)
    (length,) = _FRAME_HEADER.unpack(header)
    if length == 0 or length > MAX_PREFACE_BYTES:
        raise _frame_error("preface length is outside protocol limit")
    return Preface.from_bytes(_read_exact(stream, length))


def write_preface(stream: BinaryIO, preface: Preface) -> None:
    _write_frame(stream, preface.to_bytes())


def write_ready(stream: BinaryIO, nonce: bytes) -> None:
    _write_response(stream, {"nonce": nonce, "status": "ready", "version": PREFACE_VERSION})


def write_error(stream: BinaryIO, nonce: bytes, code: ErrorCode) -> None:
    """Write protocol-only denial. Detail belongs solely on stderr."""
    _write_response(
        stream,
        {"code": code.string, "nonce": nonce, "status": "error", "version": PREFACE_VERSION},
    )


def read_response(stream: BinaryIO) -> dict[str, object]:
    """Test and client helper for one bounded response frame."""
    header = _read_exact(stream, _FRAME_HEADER.size)
    (length,) = _FRAME_HEADER.unpack(header)
    if length == 0 or length > MAX_PREFACE_BYTES:
        raise _frame_error("response length is outside protocol limit")
    try:
        value = canonical_loads(_read_exact(stream, length))
    except AstralError as error:
        raise _frame_error("response CBOR is invalid") from error
    if not isinstance(value, dict):
        raise _frame_error("response is not a map")
    return cast(dict[str, object], value)


def fuzz_preface(data: bytes) -> None:
    """Parser fuzz target: arbitrary bytes may yield only expected protocol errors."""
    from io import BytesIO

    try:
        read_preface(BytesIO(data))
    except AstralError:
        return


def _write_response(stream: BinaryIO, payload: dict[str, CborValue]) -> None:
    _write_frame(stream, canonical_dumps(payload))


def _write_frame(stream: BinaryIO, payload: bytes) -> None:
    if len(payload) > MAX_PREFACE_BYTES:
        raise _frame_error("protocol frame exceeds limit")
    stream.write(_FRAME_HEADER.pack(len(payload)))
    stream.write(payload)
    stream.flush()


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise _frame_error("truncated protocol frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _frame_error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PROTOCOL_FRAME,
        message=message,
        security_result="remote protocol request was rejected",
        unsafe_reason="remote protocol frames must be complete, bounded, and unambiguous",
        next_action="use compatible Astral Project client",
    )


def _version_error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PROTOCOL_VERSION,
        message=message,
        security_result="remote protocol request was rejected",
        unsafe_reason="unknown protocol versions cannot safely select authorization semantics",
        next_action="upgrade both Astral Project endpoints together",
    )
