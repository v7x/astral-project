"""Packet 14A/14B bounded protocol and replay contract tests."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, HostId, IssuerKeyId, SessionId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    SignedGrant,
    SourceIdentity,
)
from astral_project.session.broker import (
    WORKER_FD_LAYOUT,
    BrokerAuditV1,
    BrokerFailureCode,
    CreateNamespaceV1,
    NamespaceReadyV1,
    PeerCredentials,
    ReplayLedger,
    ReplayState,
    WorkerFdLayoutV1,
    WorkerResult,
    WorkerResultV1,
    require_expected_peer,
)
from astral_project.session.ceiling import ServerCeilingV1, validate_grant_against_ceiling
from astral_project.session.contracts import (
    OpenSessionV1,
    RemoteSessionRequestV1,
    read_remote_session_request,
    write_remote_session_request,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "session"


def _signed_grant() -> SignedGrant:
    key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    grant = Grant(
        grant_id=GrantId("00000000-0000-4000-8000-000000000001"),
        issuer_key_id=IssuerKeyId("00000000-0000-4000-8000-000000000002"),
        host_id=HostId("00000000-0000-4000-8000-000000000003"),
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
    return SignedGrant.create(grant, key)


def _open() -> OpenSessionV1:
    signed = _signed_grant()
    return OpenSessionV1(
        signed.grant.host_id, SessionId("00000000-0000-4000-8000-000000000004"), signed
    )


def _remote() -> RemoteSessionRequestV1:
    opened = _open()
    return RemoteSessionRequestV1(opened.session_id, b"s" * 32, opened.signed_grant)


def test_open_and_remote_session_schema_golden_round_trip() -> None:
    opened = _open()
    remote = _remote()

    assert opened.canonical_bytes() == (FIXTURES / "open-session-v1.cbor").read_bytes()
    assert remote.canonical_bytes() == (FIXTURES / "remote-session-v1.cbor").read_bytes()
    assert OpenSessionV1.from_cbor(opened.canonical_bytes()) == opened
    assert RemoteSessionRequestV1.from_cbor(remote.canonical_bytes()) == remote
    stream = BytesIO()
    write_remote_session_request(stream, remote)
    stream.seek(0)
    assert read_remote_session_request(stream) == remote


def test_create_namespace_schema_golden_round_trip() -> None:
    request = CreateNamespaceV1(
        request_id=b"r" * 16,
        session_id=bytes.fromhex("00000000000040008000000000000004"),
        grant_envelope=_signed_grant().to_cbor(),
        client_nonce=b"s" * 32,
    )

    assert request.canonical_bytes() == (FIXTURES / "create-namespace-v1.cbor").read_bytes()
    assert CreateNamespaceV1.from_cbor(request.canonical_bytes()) == request


def test_root_owned_server_ceiling_is_independent_grant_check() -> None:
    signed = _signed_grant()
    ceiling = ServerCeilingV1(
        allowed_source_roots=("/source",),
        allowed_issuers=(signed.grant.issuer_key_id,),
        allowed_kinds=(ExportKind.DIRECTORY,),
        allow_read_write=False,
        forbidden_source_roots=(),
        max_exports=1,
        max_ttl_seconds=100,
        policy_hash=b"p" * 32,
    )

    validate_grant_against_ceiling(signed.grant, ceiling)
    assert ceiling.canonical_bytes() == (FIXTURES / "server-ceiling-v1.cbor").read_bytes()
    assert ServerCeilingV1.from_cbor(ceiling.canonical_bytes()) == ceiling
    with pytest.raises(AstralError):
        validate_grant_against_ceiling(
            Grant.from_payload({**signed.grant.to_payload(), "server_policy_hash": b"x" * 32}),
            ceiling,
        )


def test_broker_stream_transition_and_worker_fd_abi_are_fixed() -> None:
    ready = NamespaceReadyV1(
        request_id=b"r" * 16,
        session_id=bytes.fromhex("00000000000040008000000000000004"),
        backend_id="ubuntu_broker_v1",
        effective_exports_digest=b"e" * 32,
        runtime_manifest_digest=b"m" * 32,
        expires_at=200,
    )

    assert ready.canonical_bytes() == (FIXTURES / "namespace-ready-v1.cbor").read_bytes()
    assert WorkerFdLayoutV1() == WORKER_FD_LAYOUT
    with pytest.raises(AstralError):
        WorkerFdLayoutV1(stream=7)


def test_broker_peer_rule_uses_kernel_observed_uid() -> None:
    require_expected_peer(PeerCredentials(pid=1, uid=1000, gid=1000), uid=1000)

    with pytest.raises(AstralError) as error:
        require_expected_peer(PeerCredentials(pid=1, uid=1001, gid=1000), uid=1000)
    assert error.value.code is ErrorCode.DAEMON_AUTH


@pytest.mark.parametrize("operation", ["issue", "consume", "revoke", "expire"])
def test_replay_ledger_has_atomic_terminal_state_rules(operation: str) -> None:
    ledger = ReplayLedger()
    nonce = b"n" * 32
    ledger.issue(nonce, expires_at=20, now=10)

    if operation == "consume":
        assert ledger.consume(nonce, now=11) is ReplayState.CONSUMED
        with pytest.raises(AstralError):
            ledger.consume(nonce, now=12)
    elif operation == "revoke":
        assert ledger.revoke(nonce) is ReplayState.REVOKED
        with pytest.raises(AstralError):
            ledger.consume(nonce, now=11)
    elif operation == "expire":
        assert ledger.state(nonce, now=20) is ReplayState.EXPIRED
        with pytest.raises(AstralError):
            ledger.consume(nonce, now=20)
    else:
        assert ledger.state(nonce, now=11) is ReplayState.ISSUED


def test_replay_consumes_signed_grant_nonce_not_session_nonce() -> None:
    signed = _signed_grant()
    ledger = ReplayLedger()
    ledger.issue(signed.grant.nonce, expires_at=signed.grant.expires_at, now=150)

    assert ledger.consume_grant(signed, now=151) is ReplayState.CONSUMED


def test_audit_and_worker_result_golden_schema() -> None:
    session_id = _open().session_id
    audit = BrokerAuditV1(
        event_time=123,
        failure=None,
        grant_id=_signed_grant().grant.grant_id,
        peer_uid=1000,
        result=WorkerResult.PASSED,
        session_id=session_id,
    )
    worker = WorkerResultV1(None, WorkerResult.PASSED, session_id)

    assert audit.canonical_bytes() == (FIXTURES / "broker-audit-v1.cbor").read_bytes()
    assert worker.canonical_bytes() == (FIXTURES / "worker-result-v1.cbor").read_bytes()
    assert BrokerAuditV1.from_cbor(audit.canonical_bytes()) == audit
    assert WorkerResultV1.from_cbor(worker.canonical_bytes()) == worker
    with pytest.raises(AstralError):
        WorkerResultV1(BrokerFailureCode.WORKER_FAILED, WorkerResult.PASSED, session_id)
