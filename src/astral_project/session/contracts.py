"""Packet 14A bounded session contracts.

Schemas only. They neither contact broker nor create namespace, mount, or workload.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import BinaryIO, Self

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import HostId, SessionId
from astral_project.crypto.cbor import CborValue, canonical_dumps, canonical_loads
from astral_project.crypto.grants import NONCE_LENGTH, SignedGrant

SESSION_FORMAT_VERSION = 1
MAX_REMOTE_SESSION_BYTES = 1 << 20
_FRAME_HEADER = struct.Struct(">I")


class SessionOperation(StrEnum):
    SFTP_V1 = "sftp_v1"


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PROTOCOL_FRAME,
        message=message,
        security_result="session request was rejected",
        unsafe_reason="session authority requires complete bounded messages",
        next_action="use compatible Astral Project session protocol",
    )


@dataclass(frozen=True, slots=True)
class OpenSessionV1:
    """CLI-to-daemon request; grant remains signed bytes, never reconstructed fields."""

    host_id: HostId
    session_id: SessionId
    signed_grant: SignedGrant
    operation: SessionOperation = SessionOperation.SFTP_V1
    version: int = SESSION_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.version != SESSION_FORMAT_VERSION:
            raise _error("unsupported open session version")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "host_id": self.host_id.value,
            "operation": self.operation.value,
            "session_id": self.session_id.value,
            "signed_grant": self.signed_grant.to_cbor(),
            "version": self.version,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())

    @classmethod
    def from_cbor(cls, data: bytes) -> Self:
        payload = _payload(data, {"host_id", "operation", "session_id", "signed_grant", "version"})
        try:
            return cls(
                host_id=HostId(_string(payload, "host_id")),
                operation=SessionOperation(_string(payload, "operation")),
                session_id=SessionId(_string(payload, "session_id")),
                signed_grant=SignedGrant.from_cbor(_bytes(payload, "signed_grant")),
                version=_integer(payload, "version"),
            )
        except ValueError as error:
            raise _error("open session has unsupported identifiers or operation") from error


@dataclass(frozen=True, slots=True)
class RemoteSessionRequestV1:
    """Daemon-to-remote-server request carrying original signed GrantV1."""

    session_id: SessionId
    session_nonce: bytes
    signed_grant: SignedGrant
    operation: SessionOperation = SessionOperation.SFTP_V1
    version: int = SESSION_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.version != SESSION_FORMAT_VERSION:
            raise _error("unsupported remote session version")
        if len(self.session_nonce) != NONCE_LENGTH:
            raise _error("remote session nonce must be 32 bytes")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "operation": self.operation.value,
            "session_id": self.session_id.value,
            "session_nonce": self.session_nonce,
            "signed_grant": self.signed_grant.to_cbor(),
            "version": self.version,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())

    @classmethod
    def from_cbor(cls, data: bytes) -> Self:
        payload = _payload(
            data, {"operation", "session_id", "session_nonce", "signed_grant", "version"}
        )
        try:
            return cls(
                operation=SessionOperation(_string(payload, "operation")),
                session_id=SessionId(_string(payload, "session_id")),
                session_nonce=_bytes(payload, "session_nonce"),
                signed_grant=SignedGrant.from_cbor(_bytes(payload, "signed_grant")),
                version=_integer(payload, "version"),
            )
        except ValueError as error:
            raise _error("remote session has unsupported identifiers or operation") from error


def write_remote_session_request(stream: BinaryIO, request: RemoteSessionRequestV1) -> None:
    """Write one bounded canonical remote session frame; no transport is opened here."""
    payload = request.canonical_bytes()
    if len(payload) > MAX_REMOTE_SESSION_BYTES:
        raise _error("remote session frame exceeds size limit")
    stream.write(_FRAME_HEADER.pack(len(payload)))
    stream.write(payload)
    stream.flush()


def read_remote_session_request(stream: BinaryIO) -> RemoteSessionRequestV1:
    """Read exactly one remote session frame before future broker dispatch."""
    header = _read_exact(stream, _FRAME_HEADER.size)
    (length,) = _FRAME_HEADER.unpack(header)
    if not 0 < length <= MAX_REMOTE_SESSION_BYTES:
        raise _error("remote session frame length is invalid")
    return RemoteSessionRequestV1.from_cbor(_read_exact(stream, length))


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise _error("remote session frame is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _payload(data: bytes, expected: set[str]) -> Mapping[str, object]:
    decoded = canonical_loads(data)
    if not isinstance(decoded, Mapping) or set(decoded) != expected:
        raise _error("session fields are incomplete or unknown")
    return decoded


def _string(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str):
        raise _error(f"{name} must be string")
    return value


def _bytes(payload: Mapping[str, object], name: str) -> bytes:
    value = payload.get(name)
    if not isinstance(value, bytes):
        raise _error(f"{name} must be bytes")
    return value


def _integer(payload: Mapping[str, object], name: str) -> int:
    value = payload.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(f"{name} must be integer")
    return value
