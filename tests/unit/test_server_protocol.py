"""Outer remote-session framing and forced-command transition tests."""

from __future__ import annotations

from dataclasses import replace
from io import BytesIO, StringIO
from pathlib import Path

import pytest

from astral_project.audit import AuditLog
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
from astral_project.crypto.keys import generate_private_key, public_key_bytes, public_key_from_bytes
from astral_project.server.entry import SSH_ORIGINAL_COMMAND, ServerTrust, run_ssh_entry
from astral_project.server.protocol import (
    MAX_OUTER_SESSION_BYTES,
    fuzz_outer_request,
    read_outer_request,
    read_outer_response,
    write_outer_request,
)
from astral_project.session.contracts import RemoteSessionRequestV1


def signed_request() -> tuple[RemoteSessionRequestV1, ServerTrust]:
    key = generate_private_key()
    issuer_id = IssuerKeyId("00000000-0000-4000-8000-000000000002")
    host_id = HostId("00000000-0000-4000-8000-000000000003")
    grant = Grant(
        grant_id=GrantId("00000000-0000-4000-8000-000000000001"),
        issuer_key_id=issuer_id,
        host_id=host_id,
        ssh_host_key_fingerprint="SHA256:host-fingerprint",
        remote_user="alice",
        issued_at=100,
        not_before=100,
        expires_at=200,
        nonce=b"g" * 32,
        exports=(
            GrantExport(
                "/project",
                "/project",
                "/project",
                AccessMode.READ_ONLY,
                ExportKind.DIRECTORY,
                SourceIdentity(1, 2, "ext4", ExportKind.DIRECTORY),
            ),
        ),
    )
    return (
        RemoteSessionRequestV1(
            SessionId("00000000-0000-4000-8000-000000000004"),
            b"n" * 32,
            SignedGrant.create(grant, key),
        ),
        ServerTrust(
            host_id,
            "SHA256:host-fingerprint",
            "alice",
            {issuer_id: public_key_from_bytes(public_key_bytes(key))},
            frozenset({"transport-1"}),
        ),
    )


def framed(request: RemoteSessionRequestV1) -> BytesIO:
    stream = BytesIO()
    write_outer_request(stream, request)
    stream.seek(0)
    return stream


def test_outer_request_round_trip_and_bounded_rejection() -> None:
    request, _ = signed_request()
    assert read_outer_request(framed(request)) == request
    for payload in (b"", b"\x00\x00\x00\x01", (MAX_OUTER_SESSION_BYTES + 1).to_bytes(4, "big")):
        with pytest.raises(AstralError):
            read_outer_request(BytesIO(payload))


def test_unenrolled_issuer_is_rejected() -> None:
    request, trust = signed_request()
    stdout = BytesIO()
    rejected_trust = replace(trust, issuer_keys={})
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(request),
            stdout=stdout,
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
            trust=rejected_trust,
            now=150,
        )
        == 70
    )


def test_remote_audit_log_records_verified_and_rejected_sessions(tmp_path: Path) -> None:
    request, trust = signed_request()
    verified_log = AuditLog(tmp_path / "verified.log")
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(request),
            stdout=BytesIO(),
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
            trust=trust,
            now=150,
            audit_log=verified_log,
        )
        == 0
    )
    assert verified_log.read()[0].kind == "session.remote.verified"
    rejected_log = AuditLog(tmp_path / "rejected.log")
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(request),
            stdout=BytesIO(),
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": "wrong"},
            trust=trust,
            now=150,
            audit_log=rejected_log,
        )
        == 70
    )
    assert rejected_log.read()[0].kind == "session.remote.rejected"


def test_remote_entry_applies_final_child_hardening(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, trust = signed_request()
    broker_directory = tmp_path / "broker"
    broker_directory.mkdir()
    monkeypatch.setattr(
        "astral_project.server.entry.BROKER_SOCKET", broker_directory / "broker.sock"
    )
    policies: list[object] = []
    monkeypatch.setattr(
        "astral_project.server.entry.enforce", lambda policy: policies.append(policy)
    )
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(request),
            stdout=BytesIO(),
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
            trust=trust,
            now=150,
            apply_hardening=True,
        )
        == 0
    )
    assert len(policies) == 1


def test_remote_hardening_failure_is_audited(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    request, trust = signed_request()
    broker_directory = tmp_path / "broker"
    broker_directory.mkdir()
    monkeypatch.setattr(
        "astral_project.server.entry.BROKER_SOCKET", broker_directory / "broker.sock"
    )
    audit_log = AuditLog(tmp_path / "hardening.log")
    failure = AstralError(
        code=ErrorCode.HARDENING_APPLY,
        message="rule load failed",
        security_result="remote process was rejected",
        unsafe_reason="hardening is mandatory",
        next_action="repair hardening",
    )
    monkeypatch.setattr(
        "astral_project.server.entry.enforce", lambda _policy: (_ for _ in ()).throw(failure)
    )
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(request),
            stdout=BytesIO(),
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
            trust=trust,
            now=150,
            apply_hardening=True,
            audit_log=audit_log,
        )
        == 70
    )
    assert [event.kind for event in audit_log.read()] == [
        "session.remote.verified",
        "hardening.failure",
        "session.remote.rejected",
    ]


def test_authenticated_verification_callback_runs_before_dispatch() -> None:
    request, trust = signed_request()
    observed: list[RemoteSessionRequestV1] = []
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(request),
            stdout=BytesIO(),
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
            trust=trust,
            now=150,
            after_verification=observed.append,
        )
        == 0
    )
    assert observed == [request]


def test_broker_dispatch_bridges_authenticated_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    request, trust = signed_request()
    stream = object()
    observed: list[object] = []
    monkeypatch.setattr(
        "astral_project.server.entry.open_broker_sftp_stream", lambda _request: stream
    )
    monkeypatch.setattr(
        "astral_project.server.entry.bridge_sftp_stream",
        lambda value, **_kwargs: observed.append(value),
    )
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(request),
            stdout=BytesIO(),
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
            trust=trust,
            now=150,
            broker_dispatch=True,
        )
        == 0
    )
    assert observed == [stream]


def test_outer_ready_is_final_frame_before_raw_sftp_transition() -> None:
    request, trust = signed_request()
    stdout = BytesIO()
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(request),
            stdout=stdout,
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
            trust=trust,
            now=150,
        )
        == 0
    )
    stdout.seek(0)
    assert read_outer_response(stdout) == {
        "session_id": request.session_id.value,
        "session_nonce": request.session_nonce,
        "status": "ready",
        "version": 1,
    }
    assert stdout.read() == b""


def test_malformed_or_bad_signature_request_reaches_no_dispatch() -> None:
    request, trust = signed_request()
    tampered = RemoteSessionRequestV1(
        request.session_id,
        request.session_nonce,
        SignedGrant(
            Grant.from_payload(
                {**request.signed_grant.grant.to_payload(), "remote_user": "mallory"}
            ),
            request.signed_grant.signature,
        ),
    )
    dispatched: list[RemoteSessionRequestV1] = []
    stdout = BytesIO()
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(tampered),
            stdout=stdout,
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
            trust=trust,
            now=150,
            after_verification=dispatched.append,
        )
        == 70
    )
    assert dispatched == []
    stdout.seek(0)
    assert read_outer_response(stdout)["error_code"] == ErrorCode.CRYPTO_SIGNATURE.string


def test_outer_command_and_fuzz_fail_closed() -> None:
    request, trust = signed_request()
    stdout = BytesIO()
    assert (
        run_ssh_entry(
            "transport-1",
            stdin=framed(request),
            stdout=stdout,
            stderr=StringIO(),
            environment={"SSH_ORIGINAL_COMMAND": "sh -c id"},
            trust=trust,
            now=150,
        )
        == 70
    )
    stdout.seek(0)
    assert read_outer_response(stdout)["error_code"] == ErrorCode.PROTOCOL_COMMAND.string
    for payload in (b"", b"x", b"\xff" * 16, b"\x00\x00\x00\x02\xff\xff"):
        fuzz_outer_request(payload)
