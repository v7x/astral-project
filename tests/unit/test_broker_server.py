"""Packet 15 root broker skeleton tests; no namespace or mount execution."""

from __future__ import annotations

import socket
import threading
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project.broker.mapping import MappingWorker
from astral_project.broker.server import BrokerAuthority, BrokerPaths, BrokerServer
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
    BrokerFailureCode,
    CreateNamespaceV1,
    PeerCredentials,
    WorkerResult,
    WorkerResultV1,
)
from astral_project.session.ceiling import ServerCeilingV1


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
                SourceIdentity(1, 2, 3, "ext4", ExportKind.DIRECTORY),
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
            server_ceiling=ServerCeilingV1(
                allowed_source_roots=("/source",),
                allowed_issuers=(issuer,),
                allowed_kinds=(ExportKind.DIRECTORY,),
                allow_read_write=False,
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


def _serve(server: BrokerServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_once)
    thread.start()
    return thread


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
        payload = _request(signed).canonical_bytes()
        client.sendall(len(payload).to_bytes(4, "big") + payload)
        length = int.from_bytes(client.recv(4), "big")
        result = WorkerResultV1.from_cbor(client.recv(length))
        client.close()
        thread.join(timeout=1)

        assert not thread.is_alive()
        assert result.result is WorkerResult.FAILED
        assert result.failure is BrokerFailureCode.WORKER_FAILED
        assert len(audits) == 1
        assert audits[0].peer_uid == 1000
        assert mapping.calls == [(1000, 1000)]
    finally:
        server.close()


def test_root_skeleton_rejects_unauthorized_peer_before_request_parse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority, _ = _authority()
    server = BrokerServer(BrokerPaths(tmp_path / "broker.sock"), authority)
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 0)
    monkeypatch.setattr(
        "astral_project.broker.server._peer_credentials",
        lambda connection: PeerCredentials(pid=1, uid=1001, gid=1001),
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


def test_root_skeleton_refuses_non_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    authority, _ = _authority()
    server = BrokerServer(BrokerPaths(tmp_path / "broker.sock"), authority)
    monkeypatch.setattr("astral_project.broker.server.os.geteuid", lambda: 1000)

    with pytest.raises(Exception, match="broker must run as root"):
        server.start()
