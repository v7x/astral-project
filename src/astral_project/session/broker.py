"""Packet 14B broker protocol, peer rules, replay model, and audit schema.

No socket, credential syscall, descriptor, namespace, mount, or process operation occurs here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Self

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, SessionId
from astral_project.crypto.cbor import CborValue, canonical_dumps, canonical_loads
from astral_project.crypto.grants import NONCE_LENGTH, SignedGrant
from astral_project.session.contracts import SESSION_FORMAT_VERSION, _integer


class BrokerFailureCode(StrEnum):
    PROTOCOL_INVALID = "protocol_invalid"
    PEER_UNAUTHORIZED = "peer_unauthorized"
    GRANT_INVALID = "grant_invalid"
    SERVER_CEILING_DENIED = "server_ceiling_denied"
    REPLAY_DENIED = "replay_denied"
    PLAN_INVALID = "plan_invalid"
    WORKER_FAILED = "worker_failed"


class ReplayState(StrEnum):
    ISSUED = "issued"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class WorkerResult(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class WorkerFdLayoutV1:
    """Fixed broker-to-native-worker FD ABI; no caller-selectable descriptors."""

    mapping_ready: int = 3
    mapping_continue: int = 4
    sealed_plan: int = 5
    stream: int = 6
    source_base: int = 10
    source_limit: int = 74

    def __post_init__(self) -> None:
        if (
            self.mapping_ready,
            self.mapping_continue,
            self.sealed_plan,
            self.stream,
            self.source_base,
            self.source_limit,
        ) != (3, 4, 5, 6, 10, 74):
            raise _error("worker FD layout is not fixed")


WORKER_FD_LAYOUT = WorkerFdLayoutV1()


def _error(message: str, code: ErrorCode = ErrorCode.PROTOCOL_FRAME) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="broker request was rejected",
        unsafe_reason="broker authority requires authenticated bounded state transitions",
        next_action="use an authorized unexpired session request",
    )


@dataclass(frozen=True, slots=True)
class CreateNamespaceV1:
    """Sole Packet 14B broker wire request. Grant stays canonical opaque bytes."""

    request_id: bytes
    session_id: bytes
    grant_envelope: bytes
    client_nonce: bytes
    requested_workload: str = "sftp_v1"
    protocol_version: int = SESSION_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.protocol_version != SESSION_FORMAT_VERSION:
            raise _error("unsupported broker request version")
        if len(self.request_id) != 16 or len(self.session_id) != 16:
            raise _error("broker request or session ID must be 16 bytes")
        if not 1 <= len(self.grant_envelope) <= 131072:
            raise _error("broker grant envelope size is invalid")
        if len(self.client_nonce) != NONCE_LENGTH:
            raise _error("broker client nonce must be 32 bytes")
        if self.requested_workload != "sftp_v1":
            raise _error("broker workload is unsupported")

    @property
    def signed_grant(self) -> SignedGrant:
        return SignedGrant.from_cbor(self.grant_envelope)

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "client_nonce": self.client_nonce,
            "grant_envelope": self.grant_envelope,
            "protocol_version": self.protocol_version,
            "request_id": self.request_id,
            "requested_workload": self.requested_workload,
            "session_id": self.session_id,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())

    @classmethod
    def from_cbor(cls, data: bytes) -> Self:
        decoded = canonical_loads(data)
        fields = {
            "client_nonce",
            "grant_envelope",
            "protocol_version",
            "request_id",
            "requested_workload",
            "session_id",
        }
        if not isinstance(decoded, Mapping) or set(decoded) != fields:
            raise _error("broker request fields are incomplete or unknown")
        return cls(
            client_nonce=_bytes(decoded, "client_nonce"),
            grant_envelope=_bytes(decoded, "grant_envelope"),
            protocol_version=_integer(decoded, "protocol_version"),
            request_id=_bytes(decoded, "request_id"),
            requested_workload=_string(decoded, "requested_workload"),
            session_id=_bytes(decoded, "session_id"),
        )


@dataclass(frozen=True, slots=True)
class CancelNamespaceV1:
    request_id: bytes
    session_id: bytes
    protocol_version: int = SESSION_FORMAT_VERSION

    def __post_init__(self) -> None:
        if (
            self.protocol_version != SESSION_FORMAT_VERSION
            or len(self.request_id) != 16
            or len(self.session_id) != 16
        ):
            raise _error("cancel namespace request is invalid")


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    """Kernel-observed `SO_PEERCRED`; never decoded from request bytes."""

    pid: int
    uid: int
    gid: int

    def __post_init__(self) -> None:
        if min(self.pid, self.uid, self.gid) < 0:
            raise _error("peer credentials are invalid")


def require_expected_peer(peer: PeerCredentials, *, uid: int) -> None:
    """Broker accepts only kernel-observed expected remote service UID."""
    if uid < 1 or peer.uid != uid:
        raise _error("SO_PEERCRED UID is not authorized", ErrorCode.DAEMON_AUTH)


@dataclass(frozen=True, slots=True)
class BrokerAuditV1:
    """Path-free stable audit record for each broker terminal decision."""

    event_time: int
    failure: BrokerFailureCode | None
    grant_id: GrantId
    peer_uid: int
    result: WorkerResult
    session_id: SessionId
    version: int = SESSION_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.version != SESSION_FORMAT_VERSION or self.event_time < 0 or self.peer_uid < 0:
            raise _error("broker audit fields are invalid")
        if (self.result is WorkerResult.PASSED) != (self.failure is None):
            raise _error("broker audit result and failure disagree")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "event_time": self.event_time,
            "failure": None if self.failure is None else self.failure.value,
            "grant_id": self.grant_id.value,
            "peer_uid": self.peer_uid,
            "result": self.result.value,
            "session_id": self.session_id.value,
            "version": self.version,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())

    @classmethod
    def from_cbor(cls, data: bytes) -> Self:
        payload = _terminal_payload(
            data,
            {"event_time", "failure", "grant_id", "peer_uid", "result", "session_id", "version"},
        )
        try:
            return cls(
                event_time=_integer(payload, "event_time"),
                failure=_optional_failure(payload, "failure"),
                grant_id=GrantId(_string(payload, "grant_id")),
                peer_uid=_integer(payload, "peer_uid"),
                result=WorkerResult(_string(payload, "result")),
                session_id=SessionId(_string(payload, "session_id")),
                version=_integer(payload, "version"),
            )
        except ValueError as error:
            raise _error("broker audit has unsupported result or identifiers") from error


@dataclass(frozen=True, slots=True)
class WorkerResultV1:
    """Stable worker-to-broker terminal result schema; no executable output."""

    failure: BrokerFailureCode | None
    result: WorkerResult
    session_id: SessionId
    version: int = SESSION_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.version != SESSION_FORMAT_VERSION:
            raise _error("unsupported worker result version")
        if (self.result is WorkerResult.PASSED) != (self.failure is None):
            raise _error("worker result and failure disagree")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "failure": None if self.failure is None else self.failure.value,
            "result": self.result.value,
            "session_id": self.session_id.value,
            "version": self.version,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())

    @classmethod
    def from_cbor(cls, data: bytes) -> Self:
        payload = _terminal_payload(data, {"failure", "result", "session_id", "version"})
        try:
            return cls(
                failure=_optional_failure(payload, "failure"),
                result=WorkerResult(_string(payload, "result")),
                session_id=SessionId(_string(payload, "session_id")),
                version=_integer(payload, "version"),
            )
        except ValueError as error:
            raise _error("worker result has unsupported result or session identifier") from error


@dataclass(frozen=True, slots=True)
class NamespaceReadyV1:
    """Framed success response; exactly one stream FD follows through `SCM_RIGHTS`."""

    request_id: bytes
    session_id: bytes
    backend_id: str
    effective_exports_digest: bytes
    runtime_manifest_digest: bytes
    expires_at: int
    stream_fd_count: int = 1
    protocol_version: int = SESSION_FORMAT_VERSION

    def __post_init__(self) -> None:
        if (
            self.protocol_version != SESSION_FORMAT_VERSION
            or len(self.request_id) != 16
            or len(self.session_id) != 16
            or len(self.effective_exports_digest) != 32
            or len(self.runtime_manifest_digest) != 32
            or self.expires_at < 0
            or self.stream_fd_count != 1
            or not self.backend_id
        ):
            raise _error("namespace ready response is invalid")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "backend_id": self.backend_id,
            "effective_exports_digest": self.effective_exports_digest,
            "expires_at": self.expires_at,
            "protocol_version": self.protocol_version,
            "request_id": self.request_id,
            "runtime_manifest_digest": self.runtime_manifest_digest,
            "session_id": self.session_id,
            "stream_fd_count": self.stream_fd_count,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())


@dataclass(frozen=True, slots=True)
class NamespaceRejectedV1:
    request_id: bytes
    stable_error_code: BrokerFailureCode
    stage: str
    safe_message: str
    protocol_version: int = SESSION_FORMAT_VERSION

    def __post_init__(self) -> None:
        if (
            self.protocol_version != SESSION_FORMAT_VERSION
            or len(self.request_id) != 16
            or not self.stage
            or len(self.stage) > 64
            or not self.safe_message
            or len(self.safe_message) > 256
        ):
            raise _error("namespace rejection response is invalid")


class ReplayLedger:
    """Thread-safe in-memory model for broker-owned atomic grant-nonce transitions.

    Packet 15 supplies durable root-owned storage. This class freezes semantics only.
    """

    def __init__(self) -> None:
        self._entries: dict[bytes, tuple[ReplayState, int]] = {}
        self._lock = Lock()

    def issue(self, nonce: bytes, *, expires_at: int, now: int) -> ReplayState:
        _nonce(nonce)
        if expires_at <= now:
            raise _error("cannot issue expired nonce")
        with self._lock:
            self._expire_locked(now)
            if nonce in self._entries:
                raise _error("nonce already exists")
            self._entries[nonce] = (ReplayState.ISSUED, expires_at)
            return ReplayState.ISSUED

    def consume_grant(self, signed_grant: SignedGrant, *, now: int) -> ReplayState:
        """Bind replay decision to signed GrantV1 nonce and expiry after broker verification."""
        return self.consume(signed_grant.grant.nonce, now=now)

    def consume(self, nonce: bytes, *, now: int) -> ReplayState:
        _nonce(nonce)
        with self._lock:
            self._expire_locked(now)
            try:
                state, expires_at = self._entries[nonce]
            except KeyError as error:
                raise _error("nonce was not issued") from error
            if state is not ReplayState.ISSUED or now >= expires_at:
                raise _error("nonce cannot be consumed")
            self._entries[nonce] = (ReplayState.CONSUMED, expires_at)
            return ReplayState.CONSUMED

    def revoke(self, nonce: bytes) -> ReplayState:
        _nonce(nonce)
        with self._lock:
            try:
                _, expires_at = self._entries[nonce]
            except KeyError as error:
                raise _error("nonce was not issued") from error
            self._entries[nonce] = (ReplayState.REVOKED, expires_at)
            return ReplayState.REVOKED

    def state(self, nonce: bytes, *, now: int) -> ReplayState | None:
        _nonce(nonce)
        with self._lock:
            self._expire_locked(now)
            entry = self._entries.get(nonce)
            return None if entry is None else entry[0]

    def _expire_locked(self, now: int) -> None:
        for nonce, (state, expires_at) in tuple(self._entries.items()):
            if state is ReplayState.ISSUED and now >= expires_at:
                self._entries[nonce] = (ReplayState.EXPIRED, expires_at)


def _terminal_payload(data: bytes, expected: set[str]) -> Mapping[str, object]:
    decoded = canonical_loads(data)
    if not isinstance(decoded, Mapping) or set(decoded) != expected:
        raise _error("terminal result fields are incomplete or unknown")
    return decoded


def _bytes(payload: Mapping[str, object], field: str) -> bytes:
    value = payload.get(field)
    if not isinstance(value, bytes):
        raise _error(f"{field} must be bytes")
    return value


def _string(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise _error(f"{field} must be string")
    return value


def _optional_failure(payload: Mapping[str, object], field: str) -> BrokerFailureCode | None:
    value = payload.get(field)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _error(f"{field} must be string or null")
    try:
        return BrokerFailureCode(value)
    except ValueError as error:
        raise _error(f"{field} is unsupported") from error


def _nonce(value: bytes) -> None:
    if len(value) != NONCE_LENGTH:
        raise _error("replay nonce must be 32 bytes")
