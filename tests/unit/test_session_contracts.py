"""Packet 14A/14B bounded protocol and replay contract tests."""

from __future__ import annotations

from io import BytesIO
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, HostId, IssuerKeyId, SessionId
from astral_project.crypto.cbor import canonical_dumps
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
    BrokerBackendId,
    BrokerConnectionAuditV1,
    BrokerFailureCode,
    CancelNamespaceV1,
    CancelReason,
    CreateNamespaceV1,
    NamespaceCancelledV1,
    NamespaceNotFoundV1,
    NamespaceReadyV1,
    NamespaceRejectedV1,
    PeerCredentials,
    ReplayLedger,
    ReplayState,
    WorkerFdLayoutV1,
    WorkerResult,
    WorkerResultV1,
    _boolean,
    _bytes,
    _optional_failure,
    _string,
    replay_key,
    require_expected_peer,
)
from astral_project.session.ceiling import (
    ServerCeilingV1,
    SourceRootCeilingV1,
    validate_grant_against_ceiling,
)
from astral_project.session.contracts import (
    OpenSessionV1,
    RemoteSessionReadyV1,
    RemoteSessionRejectedV1,
    RemoteSessionRequestV1,
    _read_exact,
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
                SourceIdentity(1, 2, "ext4", ExportKind.DIRECTORY),
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


def test_session_from_cbor_rejects_unknown_operations_and_types() -> None:
    opened = _open()
    payload = opened.to_payload()
    payload["operation"] = "other"
    with pytest.raises(AstralError):
        OpenSessionV1.from_cbor(canonical_dumps(payload))
    payload = opened.to_payload()
    payload["signed_grant"] = b"bad"
    with pytest.raises(AstralError):
        OpenSessionV1.from_cbor(canonical_dumps(payload))
    remote = _remote()
    payload = remote.to_payload()
    payload["operation"] = "other"
    with pytest.raises(AstralError):
        RemoteSessionRequestV1.from_cbor(canonical_dumps(payload))
    payload = remote.to_payload()
    payload["session_nonce"] = "bad"
    with pytest.raises(AstralError):
        RemoteSessionRequestV1.from_cbor(canonical_dumps(payload))


def test_session_contracts_reject_invalid_versions_and_frames() -> None:
    opened = _open()
    with pytest.raises(AstralError):
        OpenSessionV1(opened.host_id, opened.session_id, opened.signed_grant, version=99)
    with pytest.raises(AstralError):
        RemoteSessionRequestV1(opened.session_id, b"short", opened.signed_grant)
    with pytest.raises(AstralError):
        RemoteSessionReadyV1(opened.session_id, b"short")
    with pytest.raises(AstralError):
        RemoteSessionRejectedV1(None, "")
    with pytest.raises(AstralError):
        _read_exact(BytesIO(b""), 1)
    with pytest.raises(AstralError):
        read_remote_session_request(BytesIO((0).to_bytes(4, "big")))


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


def test_outer_response_golden_fixtures() -> None:
    opened = _open()
    ready = RemoteSessionReadyV1(opened.session_id, b"s" * 32)
    rejected = RemoteSessionRejectedV1(b"s" * 32, "ASPR_PROTOCOL_FRAME")

    assert ready.canonical_bytes() == (FIXTURES / "remote-session-ready-v1.cbor").read_bytes()
    assert rejected.canonical_bytes() == (FIXTURES / "remote-session-rejected-v1.cbor").read_bytes()


def test_create_namespace_schema_golden_round_trip() -> None:
    request = CreateNamespaceV1(
        request_id=b"r" * 16,
        session_id=bytes.fromhex("00000000000040008000000000000004"),
        grant_envelope=_signed_grant().to_cbor(),
        client_nonce=b"s" * 32,
    )

    assert request.canonical_bytes() == (FIXTURES / "create-namespace-v1.cbor").read_bytes()
    assert CreateNamespaceV1.from_cbor(request.canonical_bytes()) == request


def test_cancel_namespace_has_separate_canonical_control_frame() -> None:
    cancel = CancelNamespaceV1(
        request_id=b"r" * 16,
        session_id=bytes.fromhex("00000000000040008000000000000004"),
        reason=CancelReason.CLIENT_REQUEST,
    )

    assert CancelNamespaceV1.from_cbor(cancel.canonical_bytes()) == cancel


def test_root_owned_server_ceiling_is_independent_grant_check() -> None:
    signed = _signed_grant()
    ceiling = ServerCeilingV1(
        source_roots=(
            SourceRootCeilingV1("/source", AccessMode.READ_ONLY, (ExportKind.DIRECTORY,)),
        ),
        allowed_issuers=(signed.grant.issuer_key_id,),
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


@pytest.mark.parametrize(
    ("source", "reject"),
    [
        ("/source/secrets", True),
        ("/source", True),
        ("/source/public", False),
        ("/foobar", False),
    ],
)
def test_ceiling_rejects_forbidden_root_overlap_both_directions(source: str, reject: bool) -> None:
    signed = _signed_grant()
    ceiling = ServerCeilingV1(
        source_roots=(SourceRootCeilingV1("/", AccessMode.READ_WRITE, (ExportKind.DIRECTORY,)),),
        allowed_issuers=(signed.grant.issuer_key_id,),
        forbidden_source_roots=("/source/secrets",),
        max_exports=1,
        max_ttl_seconds=100,
        policy_hash=b"p" * 32,
    )
    export = signed.grant.exports[0]
    grant = Grant.from_payload(
        {
            **signed.grant.to_payload(),
            "exports": [
                {
                    **export.to_payload(),
                    "canonical_source": source,
                    "display_source": source,
                }
            ],
        }
    )
    if reject:
        with pytest.raises(AstralError):
            validate_grant_against_ceiling(grant, ceiling)
    else:
        validate_grant_against_ceiling(grant, ceiling)


def test_per_root_access_and_overlap_rules_are_independent() -> None:
    signed = _signed_grant()
    with pytest.raises(AstralError):
        ServerCeilingV1(
            source_roots=(
                SourceRootCeilingV1("/a", AccessMode.READ_ONLY, (ExportKind.DIRECTORY,)),
                SourceRootCeilingV1("/a/b", AccessMode.READ_WRITE, (ExportKind.DIRECTORY,)),
            ),
            allowed_issuers=(signed.grant.issuer_key_id,),
            forbidden_source_roots=(),
            max_exports=1,
            max_ttl_seconds=100,
            policy_hash=b"p" * 32,
        )
    ceiling = ServerCeilingV1(
        source_roots=(
            SourceRootCeilingV1("/rw", AccessMode.READ_WRITE, (ExportKind.DIRECTORY,)),
            SourceRootCeilingV1("/source", AccessMode.READ_ONLY, (ExportKind.DIRECTORY,)),
        ),
        allowed_issuers=(signed.grant.issuer_key_id,),
        forbidden_source_roots=(),
        max_exports=1,
        max_ttl_seconds=100,
        policy_hash=b"p" * 32,
    )
    ro = signed.grant
    validate_grant_against_ceiling(ro, ceiling)
    rw = Grant.from_payload(
        {
            **ro.to_payload(),
            "exports": [
                {**ro.exports[0].to_payload(), "canonical_source": "/source", "access_mode": "rw"}
            ],
        }
    )
    with pytest.raises(AstralError):
        validate_grant_against_ceiling(rw, ceiling)


def test_broker_stream_transition_and_worker_fd_abi_are_fixed() -> None:
    ready = NamespaceReadyV1(
        request_id=b"r" * 16,
        session_id=bytes.fromhex("00000000000040008000000000000004"),
        backend_id=BrokerBackendId.ADMIN_BOOTSTRAPPED_V1,
        effective_exports_digest=b"e" * 32,
        runtime_manifest_digest=b"m" * 32,
        expires_at=200,
    )

    assert ready.canonical_bytes() == (FIXTURES / "namespace-ready-v1.cbor").read_bytes()
    assert NamespaceReadyV1.from_cbor(ready.canonical_bytes()) == ready
    rejected = NamespaceRejectedV1(
        request_id=b"r" * 16,
        session_id=bytes.fromhex("00000000000040008000000000000004"),
        stable_error_code=BrokerFailureCode.BACKEND_UNAVAILABLE,
        stage="worker_start",
        retryable=False,
        safe_message="namespace backend is unavailable",
    )
    assert rejected.canonical_bytes() == (FIXTURES / "namespace-rejected-v1.cbor").read_bytes()
    assert NamespaceRejectedV1.from_cbor(rejected.canonical_bytes()) == rejected
    assert WorkerFdLayoutV1() == WORKER_FD_LAYOUT
    with pytest.raises(AstralError):
        WorkerFdLayoutV1(stream=7)


def test_broker_peer_rule_uses_kernel_observed_uid() -> None:
    require_expected_peer(PeerCredentials(pid=1, uid=1000, gid=1000), uid=1000, gid=1000)

    with pytest.raises(AstralError) as error:
        require_expected_peer(PeerCredentials(pid=1, uid=1001, gid=1000), uid=1000, gid=1000)
    assert error.value.code is ErrorCode.DAEMON_AUTH


def test_replay_key_binds_grant_identity_and_client_nonce() -> None:
    signed = _signed_grant()
    ledger = ReplayLedger()
    first = b"a" * 32
    second = b"b" * 32

    assert ledger.issue(signed, first, now=150) is ReplayState.ISSUED
    assert ledger.consume(signed, first, now=151) is ReplayState.CONSUMED
    with pytest.raises(AstralError):
        ledger.issue(signed, first, now=152)
    assert ledger.issue(signed, second, now=152) is ReplayState.ISSUED
    assert ledger.revoke(signed, second) is ReplayState.REVOKED
    with pytest.raises(AstralError):
        ledger.consume(signed, second, now=153)


def test_replay_expiry_is_terminal_per_client_nonce() -> None:
    signed = _signed_grant()
    ledger = ReplayLedger()
    nonce = b"n" * 32
    ledger.issue(signed, nonce, now=150)

    assert ledger.state(signed, nonce, now=200) is ReplayState.EXPIRED
    with pytest.raises(AstralError):
        ledger.consume(signed, nonce, now=200)


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


def test_connection_audit_and_terminal_result_validation() -> None:
    audit = BrokerConnectionAuditV1(1, 1000, BrokerFailureCode.PEER_UNAUTHORIZED, "peer")
    assert audit.stage == "peer"
    with pytest.raises(AstralError):
        BrokerConnectionAuditV1(-1, 1000, BrokerFailureCode.PROTOCOL_INVALID, "peer")
    with pytest.raises(AstralError):
        BrokerAuditV1(
            1, None, _signed_grant().grant.grant_id, 1000, WorkerResult.FAILED, _open().session_id
        )
    with pytest.raises(AstralError):
        BrokerAuditV1(
            1,
            None,
            _signed_grant().grant.grant_id,
            1000,
            WorkerResult.PASSED,
            _open().session_id,
            99,
        )
    with pytest.raises(AstralError):
        WorkerResultV1(None, WorkerResult.PASSED, _open().session_id, 99)


def test_terminal_payload_helpers_reject_wrong_types() -> None:
    with pytest.raises(AstralError):
        _bytes({"x": "not-bytes"}, "x")
    with pytest.raises(AstralError):
        _string({"x": b"not-string"}, "x")
    with pytest.raises(AstralError):
        _boolean({"x": 1}, "x")
    with pytest.raises(AstralError):
        _optional_failure({"x": 1}, "x")
    with pytest.raises(AstralError):
        _optional_failure({"x": "unknown"}, "x")


def test_protocol_constructor_rejects_invalid_bounds() -> None:
    signed = _signed_grant().to_cbor()
    base = CreateNamespaceV1(b"r" * 16, b"s" * 16, signed, b"n" * 32)
    payload = base.to_payload()
    payload.pop("session_id")
    with pytest.raises(AstralError):
        CreateNamespaceV1.from_cbor(canonical_dumps(payload))
    payload = base.to_payload()
    payload["protocol_version"] = 99
    with pytest.raises(AstralError):
        CreateNamespaceV1.from_cbor(canonical_dumps(payload))
    payload = base.to_payload()
    payload["requested_workload"] = "other"
    with pytest.raises(AstralError):
        CreateNamespaceV1.from_cbor(canonical_dumps(payload))
    payload = base.to_payload()
    payload["grant_envelope"] = b""
    with pytest.raises(AstralError):
        CreateNamespaceV1.from_cbor(canonical_dumps(payload))
    signed_envelope = _signed_grant().to_cbor()
    with pytest.raises(AstralError):
        CreateNamespaceV1(b"r", b"s" * 16, signed_envelope, b"n" * 32)
    with pytest.raises(AstralError):
        CreateNamespaceV1(b"r" * 16, b"s" * 16, b"", b"n" * 32)
    with pytest.raises(AstralError):
        CreateNamespaceV1(b"r" * 16, b"s" * 16, signed_envelope, b"n")
    with pytest.raises(AstralError):
        CreateNamespaceV1(b"r" * 16, b"s" * 16, signed_envelope, b"n" * 32, "other")
    with pytest.raises(AstralError):
        CancelNamespaceV1(b"r", b"s" * 16, CancelReason.CLIENT_REQUEST)
    with pytest.raises(AstralError):
        PeerCredentials(-1, 1, 1)
    with pytest.raises(AstralError):
        NamespaceReadyV1(
            b"r", b"s" * 16, BrokerBackendId.ADMIN_BOOTSTRAPPED_V1, b"e" * 32, b"m" * 32, 1
        )
    with pytest.raises(AstralError):
        NamespaceRejectedV1(b"r" * 16, None, BrokerFailureCode.PLAN_INVALID, "", False, "message")
    with pytest.raises(AstralError):
        NamespaceCancelledV1(b"r", b"s" * 16)
    with pytest.raises(AstralError):
        NamespaceNotFoundV1(b"r" * 16, b"s", 1)
    with pytest.raises(AstralError):
        CancelNamespaceV1.from_cbor(
            canonical_dumps(
                {
                    "protocol_version": 1,
                    "reason": "unknown",
                    "request_id": b"r" * 16,
                    "session_id": b"s" * 16,
                }
            )
        )
    signed_grant = _signed_grant()
    with pytest.raises(AstralError):
        replay_key(signed_grant, b"short")
    ledger = ReplayLedger()
    with pytest.raises(AstralError):
        ledger.issue(signed_grant, b"x" * 32, now=200)
    with pytest.raises(AstralError):
        ledger.consume(signed_grant, b"y" * 32, now=150)
    with pytest.raises(AstralError):
        ledger.revoke(signed_grant, b"z" * 32)


def test_terminal_from_cbor_rejects_unsupported_enums_and_identifiers() -> None:
    audit = BrokerAuditV1(
        1,
        BrokerFailureCode.PLAN_INVALID,
        _signed_grant().grant.grant_id,
        1,
        WorkerResult.FAILED,
        _open().session_id,
    )
    payload = audit.to_payload()
    payload["result"] = "unknown"
    with pytest.raises(AstralError):
        BrokerAuditV1.from_cbor(canonical_dumps(payload))
    worker = WorkerResultV1(BrokerFailureCode.PLAN_INVALID, WorkerResult.FAILED, _open().session_id)
    payload = worker.to_payload()
    payload["result"] = "unknown"
    with pytest.raises(AstralError):
        WorkerResultV1.from_cbor(canonical_dumps(payload))
    ready = NamespaceReadyV1(
        b"r" * 16, b"s" * 16, BrokerBackendId.ADMIN_BOOTSTRAPPED_V1, b"e" * 32, b"m" * 32, 1
    )
    payload = ready.to_payload()
    payload["backend_id"] = "unknown"
    with pytest.raises(AstralError):
        NamespaceReadyV1.from_cbor(canonical_dumps(payload))
    rejected = NamespaceRejectedV1(
        b"r" * 16, None, BrokerFailureCode.PLAN_INVALID, "plan", False, "bad"
    )
    payload = rejected.to_payload()
    payload["stable_error_code"] = "unknown"
    with pytest.raises(AstralError):
        NamespaceRejectedV1.from_cbor(canonical_dumps(payload))


def test_terminal_response_variants_round_trip_and_invalid_fields() -> None:
    request_id = b"r" * 16
    session_id = b"s" * 16
    cancelled = NamespaceCancelledV1(request_id, session_id)
    missing = NamespaceNotFoundV1(request_id, session_id)
    assert NamespaceCancelledV1.from_cbor(cancelled.canonical_bytes()) == cancelled
    assert NamespaceNotFoundV1.from_cbor(missing.canonical_bytes()) == missing
    rejected = NamespaceRejectedV1(
        request_id, None, BrokerFailureCode.PLAN_INVALID, "plan", False, "bad plan"
    )
    assert NamespaceRejectedV1.from_cbor(rejected.canonical_bytes()) == rejected
    payload = rejected.to_payload()
    payload["session_id"] = "wrong"
    with pytest.raises(AstralError):
        NamespaceRejectedV1.from_cbor(canonical_dumps(payload))
