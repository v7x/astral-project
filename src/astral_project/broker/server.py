"""Packet 15 root broker skeleton.

It authenticates Unix peers and validates bounded broker requests. It deliberately
contains no descriptor, fork, namespace, mount, capability, or workload operation.
"""

from __future__ import annotations

import array
import os
import socket
import struct
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from astral_project.broker.executor import ActiveWorkerSession, BrokerSessionExecutor
from astral_project.broker.mapping import MappingWorker
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import SessionId
from astral_project.crypto.grants import GrantVerificationContext
from astral_project.server.entry import ServerTrust
from astral_project.session.broker import (
    BrokerAuditV1,
    BrokerBackendId,
    BrokerConnectionAuditV1,
    BrokerFailureCode,
    CreateNamespaceV1,
    NamespaceReadyV1,
    NamespaceRejectedV1,
    PeerCredentials,
    WorkerResult,
    WorkerResultV1,
    require_expected_peer,
)
from astral_project.session.ceiling import ServerCeilingV1, validate_grant_against_ceiling

MAX_BROKER_FRAME_BYTES = 1 << 20
BROKER_IO_TIMEOUT_SECONDS = 2.0
_FRAME_HEADER = struct.Struct(">I")


@dataclass(frozen=True, slots=True)
class BrokerPaths:
    socket: Path


@dataclass(frozen=True, slots=True)
class BrokerAuthority:
    """Administrator-supplied authority; request bytes supply none of these fields."""

    expected_peer_uid: int
    expected_peer_gid: int
    server_ceiling: ServerCeilingV1
    trust: ServerTrust

    def __post_init__(self) -> None:
        if self.expected_peer_uid < 1 or self.expected_peer_gid < 1:
            raise _error("broker expected peer UID or GID is invalid")


class BrokerServer:
    """Root-owned socket skeleton. Valid requests receive stable backend-unavailable result."""

    def __init__(
        self,
        paths: BrokerPaths,
        authority: BrokerAuthority,
        *,
        audit_sink: Callable[[BrokerAuditV1], None] | None = None,
        connection_audit_sink: Callable[[BrokerConnectionAuditV1], None] | None = None,
        clock: Callable[[], int] | None = None,
        mapping_worker: MappingWorker | None = None,
        stream_handoff_sink: Callable[[int], None] | None = None,
        executor: BrokerSessionExecutor | None = None,
        active_session_sink: Callable[[bytes, ActiveWorkerSession, int], None] | None = None,
        rejection_sink: Callable[[str, AstralError], None] | None = None,
    ) -> None:
        self.paths = paths
        self.authority = authority
        self._audit_sink = audit_sink if audit_sink is not None else lambda _: None
        self._connection_audit_sink = (
            connection_audit_sink if connection_audit_sink is not None else lambda _: None
        )
        self._clock = clock if clock is not None else lambda: int(time.time())
        self._mapping_worker = mapping_worker
        if executor is not None and (
            active_session_sink is None or stream_handoff_sink is not None
        ):
            raise _error("broker executor requires sole active-session supervisor")
        self._stream_handoff_sink = stream_handoff_sink
        self._executor = executor
        self._active_session_sink = active_session_sink
        self._rejection_sink = rejection_sink if rejection_sink is not None else lambda _, __: None
        self._listener: socket.socket | None = None

    def start(self, *, inherited_listener: socket.socket | None = None) -> None:
        """Bind socket or adopt sole validated systemd-owned listener."""
        if os.geteuid() != 0:
            raise _error("broker must run as root")
        if inherited_listener is not None:
            if self._listener is not None or inherited_listener.family != socket.AF_UNIX:
                raise _error("broker inherited listener is invalid")
            self._listener = inherited_listener
            return
        if not self.paths.socket.parent.is_dir():
            raise _error("broker socket directory is unavailable")
        if self.paths.socket.exists():
            raise _error("broker socket path already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.paths.socket))
            os.chmod(self.paths.socket, 0o660)
            listener.listen()
        except Exception:
            listener.close()
            with suppress(FileNotFoundError):
                self.paths.socket.unlink()
            raise
        self._listener = listener

    def serve_once(self) -> None:
        """Handle one request. Peer authentication happens before request-byte parsing."""
        if self._listener is None:
            raise _error("broker is not started")
        connection, _ = self._listener.accept()
        with connection:
            request: CreateNamespaceV1 | None = None
            peer: PeerCredentials | None = None
            stream_descriptor = -1
            stage = "peer_authentication"
            try:
                connection.settimeout(BROKER_IO_TIMEOUT_SECONDS)
                peer = _peer_credentials(connection)
                require_expected_peer(
                    peer, uid=self.authority.expected_peer_uid, gid=self.authority.expected_peer_gid
                )
                stage = "request_read"
                request, stream_descriptor = _read_request(connection)
                stage = "grant_validation"
                self._validate(request)
                if self._executor is not None:
                    stage = "worker_start"
                    active = self._executor.start(
                        request.signed_grant.grant,
                        stream_descriptor=stream_descriptor,
                        peer_uid=peer.uid,
                        peer_gid=peer.gid,
                    )
                    stream_descriptor = -1
                    assert self._active_session_sink is not None
                    stage = "worker_registration"
                    self._active_session_sink(
                        request.session_id, active, request.signed_grant.grant.expires_at
                    )
                    _write_response(
                        connection,
                        NamespaceReadyV1(
                            request_id=request.request_id,
                            session_id=request.session_id,
                            backend_id=BrokerBackendId.ADMIN_BOOTSTRAPPED_V1,
                            effective_exports_digest=active.effective_exports_digest,
                            runtime_manifest_digest=active.runtime_manifest_digest,
                            expires_at=request.signed_grant.grant.expires_at,
                        ),
                    )
                    return
                if self._stream_handoff_sink is not None:
                    self._stream_handoff_sink(stream_descriptor)
                    stream_descriptor = -1
                if self._mapping_worker is not None:
                    self._mapping_worker.run(
                        uid=self.authority.expected_peer_uid, gid=self.authority.expected_peer_gid
                    )
                result = WorkerResultV1(
                    failure=BrokerFailureCode.WORKER_FAILED,
                    result=WorkerResult.FAILED,
                    session_id=_session_id_text(request.session_id),
                )
                self._audit(request, result)
                _write_response(
                    connection,
                    NamespaceRejectedV1(
                        request_id=request.request_id,
                        session_id=request.session_id,
                        stable_error_code=BrokerFailureCode.BACKEND_UNAVAILABLE,
                        stage="worker_start",
                        retryable=False,
                        safe_message="namespace backend is unavailable",
                    ),
                )
            except TimeoutError:
                if peer is not None:
                    self._connection_audit_sink(
                        BrokerConnectionAuditV1(
                            event_time=self._clock(),
                            peer_uid=peer.uid,
                            failure=BrokerFailureCode.PROTOCOL_INVALID,
                            stage="frame_timeout",
                        )
                    )
                return
            except AstralError as error:
                # Never emit a parser oracle to an unauthenticated or partial request.
                if request is not None and peer is not None:
                    self._connection_audit_sink(
                        BrokerConnectionAuditV1(
                            event_time=self._clock(),
                            peer_uid=peer.uid,
                            failure=BrokerFailureCode.WORKER_FAILED,
                            stage=stage,
                        )
                    )
                    self._rejection_sink(stage, error)
                    _write_response(
                        connection,
                        NamespaceRejectedV1(
                            request_id=request.request_id,
                            session_id=request.session_id,
                            stable_error_code=BrokerFailureCode.BACKEND_UNAVAILABLE,
                            stage=stage,
                            retryable=False,
                            safe_message="broker request could not be completed",
                        ),
                    )
                return
            finally:
                if stream_descriptor >= 0:
                    os.close(stream_descriptor)

    def close(self) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        with suppress(FileNotFoundError):
            self.paths.socket.unlink()

    def _validate(self, request: CreateNamespaceV1) -> None:
        signed_grant = request.signed_grant
        issuer = self.authority.trust.issuer_keys.get(signed_grant.grant.issuer_key_id)
        if issuer is None:
            raise _error("grant issuer is not enrolled")
        signed_grant.verify(
            issuer,
            GrantVerificationContext(
                host_id=self.authority.trust.host_id,
                ssh_host_key_fingerprint=self.authority.trust.ssh_host_key_fingerprint,
                remote_user=self.authority.trust.remote_user,
                now=self._clock(),
            ),
        )
        validate_grant_against_ceiling(signed_grant.grant, self.authority.server_ceiling)

    def _audit(self, request: CreateNamespaceV1, result: WorkerResultV1) -> None:
        failure = result.failure
        assert failure is not None
        self._audit_sink(
            BrokerAuditV1(
                event_time=self._clock(),
                failure=failure,
                grant_id=request.signed_grant.grant.grant_id,
                peer_uid=self.authority.expected_peer_uid,
                result=result.result,
                session_id=result.session_id,
            )
        )


def _session_id_text(value: bytes) -> SessionId:
    import uuid

    return SessionId(str(uuid.UUID(bytes=value)))


def _peer_credentials(connection: socket.socket) -> PeerCredentials:
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def _read_request(connection: socket.socket) -> tuple[CreateNamespaceV1, int]:
    """Receive one bounded broker request plus sole AF_UNIX stream descriptor."""
    header, stream_descriptor = _read_header_with_stream_descriptor(connection)
    (length,) = _FRAME_HEADER.unpack(header)
    if not 0 < length <= MAX_BROKER_FRAME_BYTES:
        os.close(stream_descriptor)
        raise _error("broker request length is invalid")
    try:
        return CreateNamespaceV1.from_cbor(_read_exact(connection, length)), stream_descriptor
    except Exception:
        os.close(stream_descriptor)
        raise


def _read_header_with_stream_descriptor(connection: socket.socket) -> tuple[bytes, int]:
    ancillary_size = socket.CMSG_SPACE(array.array("i", [0]).itemsize)
    try:
        header, ancillary, flags, _ = connection.recvmsg(
            _FRAME_HEADER.size,
            ancillary_size,
            getattr(socket, "MSG_CMSG_CLOEXEC", 0),
        )
    except OSError as error:
        raise _error("broker stream descriptor receive failed") from error
    if not header or flags & socket.MSG_CTRUNC:
        raise _error("broker request header or descriptor is truncated")
    descriptors: list[int] = []
    for level, kind, payload in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            for descriptor in descriptors:
                os.close(descriptor)
            raise _error("broker request has unsupported ancillary control data")
        values = array.array("i")
        values.frombytes(payload[: len(payload) - (len(payload) % values.itemsize)])
        descriptors.extend(values)
    if len(header) < _FRAME_HEADER.size:
        try:
            header += _read_exact(connection, _FRAME_HEADER.size - len(header))
        except Exception:
            for descriptor in descriptors:
                os.close(descriptor)
            raise
    if len(descriptors) != 1:
        for descriptor in descriptors:
            os.close(descriptor)
        raise _error("broker request requires exactly one stream descriptor")
    descriptor = descriptors[0]
    try:
        _require_unix_stream_descriptor(descriptor)
        return header, descriptor
    except Exception:
        os.close(descriptor)
        raise


def _require_unix_stream_descriptor(descriptor: int) -> None:
    duplicate = socket.socket(fileno=os.dup(descriptor))
    try:
        domain_option = getattr(socket, "SO_DOMAIN", None)
        if (
            domain_option is None
            or duplicate.getsockopt(socket.SOL_SOCKET, domain_option) != socket.AF_UNIX
            or duplicate.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM
        ):
            raise _error("broker stream descriptor is not an AF_UNIX stream socket")
    except OSError as error:
        raise _error("broker stream descriptor is invalid") from error
    finally:
        duplicate.close()


def _write_response(
    connection: socket.socket, result: NamespaceReadyV1 | NamespaceRejectedV1
) -> None:
    payload = result.canonical_bytes()
    connection.sendall(_FRAME_HEADER.pack(len(payload)) + payload)


def _read_exact(connection: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise _error("broker request is truncated")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="broker request was rejected",
        unsafe_reason="root broker accepts only authenticated bounded requests",
        next_action="use installed broker through enrolled remote session",
    )
