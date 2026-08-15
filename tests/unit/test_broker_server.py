"""Packet 15 root broker protocol and supervised execution-boundary tests."""

from __future__ import annotations

import array
import os
import socket
import threading
from contextlib import suppress
from pathlib import Path
from typing import ClassVar, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project.broker.client import request_namespace
from astral_project.broker.executor import BrokerSessionExecutor
from astral_project.broker.mapping import MappingWorker
from astral_project.broker.server import (
    BrokerAuthority,
    BrokerPaths,
    BrokerServer,
    _peer_credentials,
    _read_exact,
    _read_header_with_stream_descriptor,
    _require_unix_stream_descriptor,
    _session_id_text,
    _write_response,
)
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    SignedGrant,
    SourceIdentity,
)
from astral_project.crypto.keys import public_key_bytes, public_key_from_bytes
from astral_project.server.entry import ServerTrust
from astral_project.session.broker import (
    BrokerAuditV1,
    BrokerConnectionAuditV1,
    BrokerFailureCode,
    CreateNamespaceV1,
    NamespaceRejectedV1,
    PeerCredentials,
)
from astral_project.session.ceiling import ServerCeilingV1, SourceRootCeilingV1


def _authority() -> tuple[BrokerAuthority, SignedGrant]:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    issuer = IssuerKeyId("00000000-0000-4000-8000-000000000002")
    host = HostId("00000000-0000-4000-8000-000000000003")
    grant = Grant(
        grant_id=GrantId("00000000-0000-4000-8000-000000000001"),
        issuer_key_id=issuer,
        host_id=host,
        ssh_host_key_fingerprint="SHA256:host",
        remote_user="alice",
        issued_at=100,
        not_before=100,
        expires_at=200,
        nonce=b"g" * 32,
        exports=(
            GrantExport(
                "/source",
                "/source",
                "/project",
                AccessMode.READ_ONLY,
                ExportKind.DIRECTORY,
                SourceIdentity(1, 2, "ext4", ExportKind.DIRECTORY),
            ),
        ),
    )
    signed = SignedGrant.create(grant, key)
    trust = ServerTrust(
        host_id=host,
        ssh_host_key_fingerprint="SHA256:host",
        remote_user="alice",
        issuer_keys={issuer: public_key_from_bytes(public_key_bytes(key))},
        transport_key_ids=frozenset({"transport"}),
    )
    return (
        BrokerAuthority(
            expected_peer_uid=1000,
            expected_peer_gid=1000,
            server_ceiling=ServerCeilingV1(
                source_roots=(
                    SourceRootCeilingV1("/source", AccessMode.READ_ONLY, (ExportKind.DIRECTORY,)),
                ),
                allowed_issuers=(issuer,),
                forbidden_source_roots=(),
                max_exports=1,
                max_ttl_seconds=100,
                policy_hash=b"p" * 32,
            ),
            trust=trust,
        ),
        signed,
    )


def _request(signed: SignedGrant) -> CreateNamespaceV1:
    return CreateNamespaceV1(
        request_id=b"r" * 16,
        session_id=bytes.fromhex("00000000000040008000000000000004"),
        grant_envelope=signed.to_cbor(),
        client_nonce=b"s" * 32,
    )


class _RecordingMappingWorker:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def run(self, *, uid: int, gid: int) -> None:
        self.calls.append((uid, gid))


def _send_request_with_stream(
    connection: socket.socket, request: CreateNamespaceV1, stream_descriptor: int
) -> None:
    frame = len(request.canonical_bytes()).to_bytes(4, "big") + request.canonical_bytes()
    sent = connection.sendmsg(
        [frame],
        [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [stream_descriptor]))],
    )
    connection.sendall(frame[sent:])


def _serve(server: BrokerServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_once)
    thread.start()
    return thread


def test_broker_authority_and_server_lifecycle_reject_invalid_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, _ = _authority()
    with pytest.raises(AstralError):
        BrokerAuthority(0, authority.expected_peer_gid, authority.server_ceiling, authority.trust)
    server = BrokerServer(BrokerPaths(tmp_path / "broker.sock"), authority)
    with pytest.raises(AstralError):
        server.serve_once()
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    invalid = socket.socket(socket.AF_INET)
    with pytest.raises(AstralError):
        server.start(inherited_listener=invalid)
    invalid.close()
    assert server._listener is None
    inherited = socket.socket(socket.AF_UNIX)
    server.start(inherited_listener=inherited)
    with pytest.raises(AstralError):
        server.start(inherited_listener=inherited)
    server.close()
    inherited.close()


def test_broker_server_start_rejects_missing_or_existing_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, _ = _authority()
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    with pytest.raises(AstralError):
        BrokerServer(BrokerPaths(tmp_path / "missing" / "broker.sock"), authority).start()
    existing = tmp_path / "broker.sock"
    existing.write_text("x", encoding="ascii")
    with pytest.raises(AstralError):
        BrokerServer(BrokerPaths(existing), authority).start()


def test_broker_server_header_and_descriptor_helpers_accept_socket() -> None:
    local, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    descriptor = os.dup(peer.fileno())

    class Connection:
        def recvmsg(
            self, *_args: object
        ) -> tuple[bytes, list[tuple[int, int, bytes]], int, object]:
            return (
                (1).to_bytes(4, "big"),
                [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [descriptor]).tobytes())],
                0,
                None,
            )

    try:
        header, received = _read_header_with_stream_descriptor(Connection())  # type: ignore[arg-type]
        assert header == (1).to_bytes(4, "big")
        _require_unix_stream_descriptor(received)
        os.close(received)
        credentials = _peer_credentials(local)
        assert credentials.pid > 0
    finally:
        local.close()
        peer.close()
        with suppress(OSError):
            os.close(descriptor)


def test_broker_server_descriptor_helpers_reject_bad_controls() -> None:
    regular = os.open("/dev/null", os.O_RDONLY)
    try:
        with pytest.raises(AstralError):
            _require_unix_stream_descriptor(regular)
    finally:
        os.close(regular)

    class BadControl:
        def recvmsg(
            self, *_args: object
        ) -> tuple[bytes, list[tuple[int, int, bytes]], int, object]:
            return ((1).to_bytes(4, "big"), [(1, 2, b"")], 0, None)

    with pytest.raises(AstralError):
        _read_header_with_stream_descriptor(BadControl())  # type: ignore[arg-type]


def test_broker_server_private_frame_helpers_reject_truncation() -> None:
    class Connection:
        def __init__(self) -> None:
            self.sent: bytes | None = None

        def recv(self, _length: int) -> bytes:
            return b""

        def sendall(self, payload: bytes) -> None:
            self.sent = payload

    connection = Connection()
    with pytest.raises(AstralError):
        _read_exact(connection, 1)  # type: ignore[arg-type]
    response = NamespaceRejectedV1(
        b"r" * 16, None, BrokerFailureCode.PLAN_INVALID, "plan", False, "bad"
    )
    _write_response(connection, response)  # type: ignore[arg-type]
    assert connection.sent is not None
    assert _session_id_text(bytes.fromhex("00000000000040008000000000000004")).value.endswith(
        "0004"
    )


def test_root_skeleton_validates_request_audits_and_never_executes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, signed = _authority()
    audits: list[BrokerAuditV1] = []
    mapping = _RecordingMappingWorker()
    server = BrokerServer(
        BrokerPaths(tmp_path / "broker.sock"),
        authority,
        audit_sink=audits.append,
        clock=lambda: 150,
        mapping_worker=cast(MappingWorker, mapping),
    )
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "astral_project.broker.server._peer_credentials",
        lambda connection: PeerCredentials(pid=1, uid=1000, gid=1000),
    )
    server.start()
    try:
        thread = _serve(server)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(tmp_path / "broker.sock"))
        stream_client, stream_worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        _send_request_with_stream(client, _request(signed), stream_worker.fileno())
        length = int.from_bytes(client.recv(4), "big")
        result = NamespaceRejectedV1.from_cbor(client.recv(length))
        stream_client.close()
        stream_worker.close()
        client.close()
        thread.join(timeout=1)

        assert not thread.is_alive()
        assert result.retryable is False
        assert result.stable_error_code is BrokerFailureCode.BACKEND_UNAVAILABLE
        assert result.stage == "worker_start"
        assert len(audits) == 1
        assert audits[0].peer_uid == 1000
        assert mapping.calls == [(1000, 1000)]
    finally:
        server.close()


def test_executor_path_returns_ready_and_preserves_raw_stream_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, signed = _authority()
    active_sessions: list[tuple[bytes, object, int]] = []

    class Active:
        effective_exports_digest = b"e" * 32
        runtime_manifest_digest = b"m" * 32

    class Executor:
        descriptor = -1

        def start(
            self, grant: object, *, stream_descriptor: int, peer_uid: int, peer_gid: int
        ) -> Active:
            assert peer_uid == peer_gid == 1000
            self.descriptor = stream_descriptor
            return Active()

    executor = Executor()
    server = BrokerServer(
        BrokerPaths(tmp_path / "broker.sock"),
        authority,
        executor=cast(BrokerSessionExecutor, executor),
        active_session_sink=lambda session_id, active, expires_at: active_sessions.append(
            (session_id, active, expires_at)
        ),
        clock=lambda: 150,
    )
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "astral_project.broker.server._peer_credentials",
        lambda connection: PeerCredentials(pid=1, uid=1000, gid=1000),
    )
    server.start()
    stream_client, stream_worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        thread = _serve(server)
        result = request_namespace(
            tmp_path / "broker.sock", _request(signed), stream_descriptor=stream_worker.fileno()
        )
        thread.join(timeout=1)
        assert not thread.is_alive()
        assert result.session_id == _request(signed).session_id
        assert stream_client.send(b"S") == 1
        assert os.read(executor.descriptor, 1) == b"S"
        assert len(active_sessions) == 1
        assert active_sessions[0][0] == result.session_id
        assert active_sessions[0][2] == 200
    finally:
        stream_client.close()
        stream_worker.close()
        if executor.descriptor >= 0:
            os.close(executor.descriptor)
        server.close()


def test_replayed_grant_and_client_nonce_pair_is_rejected_before_second_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, signed = _authority()

    class Active:
        effective_exports_digest = b"e" * 32
        runtime_manifest_digest = b"m" * 32

    class Executor:
        calls = 0
        descriptors: ClassVar[list[int]] = []

        def start(self, grant: object, *, stream_descriptor: int, **_: object) -> Active:
            self.calls += 1
            self.descriptors.append(stream_descriptor)
            return Active()

    executor = Executor()
    server = BrokerServer(
        BrokerPaths(tmp_path / "broker.sock"),
        authority,
        executor=cast(BrokerSessionExecutor, executor),
        active_session_sink=lambda *_: None,
        clock=lambda: 150,
    )
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "astral_project.broker.server._peer_credentials",
        lambda connection: PeerCredentials(pid=1, uid=1000, gid=1000),
    )
    server.start()
    streams = [socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM) for _ in range(2)]
    try:
        first_thread = _serve(server)
        first = request_namespace(
            tmp_path / "broker.sock", _request(signed), stream_descriptor=streams[0][1].fileno()
        )
        first_thread.join(timeout=1)
        assert first.__class__.__name__ == "NamespaceReadyV1"

        second_thread = _serve(server)
        second = request_namespace(
            tmp_path / "broker.sock", _request(signed), stream_descriptor=streams[1][1].fileno()
        )
        second_thread.join(timeout=1)
        assert isinstance(second, NamespaceRejectedV1)
        assert second.stage == "grant_validation"
        assert executor.calls == 1
    finally:
        for pair in streams:
            pair[0].close()
            pair[1].close()
        for descriptor in executor.descriptors:
            os.close(descriptor)
        server.close()


def test_authenticated_executor_failure_is_audited_and_returns_terminal_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, signed = _authority()
    rejections: list[tuple[str, AstralError]] = []

    class Executor:
        def start(self, *_: object, **__: object) -> object:
            raise AstralError(
                ErrorCode.PATH_RESOLUTION,
                "pinned source does not match signed source identity",
                "broker source descriptor was rejected",
                "worker authority requires a root-owned descriptor",
                "issue a current grant",
            )

    server = BrokerServer(
        BrokerPaths(tmp_path / "broker.sock"),
        authority,
        executor=cast(BrokerSessionExecutor, Executor()),
        active_session_sink=lambda *_: None,
        rejection_sink=lambda stage, error: rejections.append((stage, error)),
        clock=lambda: 150,
    )
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "astral_project.broker.server._peer_credentials",
        lambda connection: PeerCredentials(pid=1, uid=1000, gid=1000),
    )
    server.start()
    stream_client, stream_worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        thread = _serve(server)
        result = request_namespace(
            tmp_path / "broker.sock", _request(signed), stream_descriptor=stream_worker.fileno()
        )
        thread.join(timeout=1)
        assert not thread.is_alive()
        assert isinstance(result, NamespaceRejectedV1)
        assert result.stage == "worker_start"
        assert result.safe_message == "broker request could not be completed"
        assert len(rejections) == 1
        assert rejections[0][0] == "worker_start"
        assert rejections[0][1].message == "pinned source does not match signed source identity"
    finally:
        stream_client.close()
        stream_worker.close()
        server.close()


def test_broker_client_transfers_exact_stream_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, signed = _authority()
    received: list[int] = []
    server = BrokerServer(
        BrokerPaths(tmp_path / "broker.sock"),
        authority,
        clock=lambda: 150,
        stream_handoff_sink=received.append,
    )
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "astral_project.broker.server._peer_credentials",
        lambda connection: PeerCredentials(pid=1, uid=1000, gid=1000),
    )
    server.start()
    stream_client, stream_worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        thread = _serve(server)
        result = request_namespace(
            tmp_path / "broker.sock", _request(signed), stream_descriptor=stream_worker.fileno()
        )
        thread.join(timeout=1)
        assert isinstance(result, NamespaceRejectedV1)
        assert result.stable_error_code is BrokerFailureCode.BACKEND_UNAVAILABLE
        assert len(received) == 1
        stream_worker.close()
        assert stream_client.send(b"S") == 1
        assert os.read(received[0], 1) == b"S"
    finally:
        stream_client.close()
        stream_worker.close()
        for descriptor in received:
            os.close(descriptor)
        server.close()


@pytest.mark.parametrize("uid, gid", [(1001, 1000), (1000, 1001)])
def test_root_skeleton_rejects_unauthorized_peer_before_request_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uid: int, gid: int
) -> None:
    authority, _ = _authority()
    server = BrokerServer(BrokerPaths(tmp_path / "broker.sock"), authority)
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "astral_project.broker.server._peer_credentials",
        lambda connection: PeerCredentials(pid=1, uid=uid, gid=gid),
    )
    server.start()
    try:
        thread = _serve(server)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(tmp_path / "broker.sock"))
        client.sendall(b"not a broker request")
        try:
            response = client.recv(1)
        except ConnectionResetError:
            response = b""
        assert response == b""
        client.close()
        thread.join(timeout=1)
        assert not thread.is_alive()
    finally:
        server.close()


def test_root_skeleton_times_out_partial_frame_before_worker_or_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, _ = _authority()
    audits: list[BrokerAuditV1] = []
    connection_audits: list[BrokerConnectionAuditV1] = []
    server = BrokerServer(
        BrokerPaths(tmp_path / "broker.sock"),
        authority,
        audit_sink=audits.append,
        connection_audit_sink=connection_audits.append,
    )
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    monkeypatch.setattr("astral_project.broker.server.BROKER_IO_TIMEOUT_SECONDS", 0.01)
    monkeypatch.setattr(
        "astral_project.broker.server._peer_credentials",
        lambda connection: PeerCredentials(pid=1, uid=1000, gid=1000),
    )
    server.start()
    try:
        thread = _serve(server)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(tmp_path / "broker.sock"))
        client.sendall(b"\x00\x00")
        thread.join(timeout=1)
        assert not thread.is_alive()
        assert audits == []
        assert len(connection_audits) == 1
        assert connection_audits[0].stage == "frame_timeout"
        client.close()
    finally:
        server.close()


def test_root_skeleton_refuses_non_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    authority, _ = _authority()
    server = BrokerServer(BrokerPaths(tmp_path / "broker.sock"), authority)
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 1000)

    with pytest.raises(Exception, match="broker must run as root"):
        server.start()
