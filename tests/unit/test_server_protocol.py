"""Packet 9 forced-command and bounded-preface tests."""

from __future__ import annotations

from io import BytesIO, StringIO

import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.cbor import canonical_dumps
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
    MAX_PREFACE_BYTES,
    Preface,
    PrefaceOperation,
    fuzz_preface,
    read_preface,
    read_response,
    write_preface,
)


def signed_preface() -> tuple[Preface, ServerTrust]:
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
                SourceIdentity(1, 2, 3, "ext4", ExportKind.DIRECTORY),
            ),
        ),
    )
    return (
        Preface(PrefaceOperation.OPEN_SFTP, b"request-nonce", SignedGrant.create(grant, key)),
        ServerTrust(
            host_id=host_id,
            ssh_host_key_fingerprint="SHA256:host-fingerprint",
            remote_user="alice",
            issuer_keys={issuer_id: public_key_from_bytes(public_key_bytes(key))},
            transport_key_ids=frozenset({"transport-1"}),
        ),
    )


def framed(preface: Preface) -> BytesIO:
    stream = BytesIO()
    write_preface(stream, preface)
    stream.seek(0)
    return stream


def test_preface_round_trip_all_operations() -> None:
    preface, _ = signed_preface()
    for operation in PrefaceOperation:
        candidate = Preface(operation, preface.nonce, preface.signed_grant)
        assert read_preface(framed(candidate)) == candidate


@pytest.mark.parametrize(
    "payload", [b"", b"\x00\x00\x00\x01", (MAX_PREFACE_BYTES + 1).to_bytes(4, "big")]
)
def test_preface_rejects_truncated_and_oversized_frames(payload: bytes) -> None:
    with pytest.raises(AstralError) as error:
        read_preface(BytesIO(payload))
    assert error.value.code is ErrorCode.PROTOCOL_FRAME


def test_preface_rejects_unknown_version() -> None:
    preface, _ = signed_preface()
    payload = canonical_dumps(
        {
            "grant": preface.signed_grant.to_cbor(),
            "nonce": preface.nonce,
            "operation": preface.operation.value,
            "version": 2,
        }
    )
    stream = BytesIO(len(payload).to_bytes(4, "big") + payload)
    with pytest.raises(AstralError) as error:
        read_preface(stream)
    assert error.value.code is ErrorCode.PROTOCOL_VERSION


def test_ssh_entry_accepts_only_exact_command_and_stdout_is_binary_protocol() -> None:
    preface, trust = signed_preface()
    stdout = BytesIO()
    stderr = StringIO()

    result = run_ssh_entry(
        "transport-1",
        stdin=framed(preface),
        stdout=stdout,
        stderr=stderr,
        environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
        trust=trust,
        now=150,
    )

    assert result == 0
    assert stderr.getvalue() == ""
    stdout.seek(0)
    assert read_response(stdout) == {
        "nonce": preface.nonce,
        "status": "ready",
        "version": 1,
    }

    stdout = BytesIO()
    stderr = StringIO()
    result = run_ssh_entry(
        "transport-1",
        stdin=framed(preface),
        stdout=stdout,
        stderr=stderr,
        environment={"SSH_ORIGINAL_COMMAND": "sh -c id"},
        trust=trust,
        now=150,
    )
    assert result == 70
    stdout.seek(0)
    assert read_response(stdout)["code"] == ErrorCode.PROTOCOL_COMMAND.string
    assert "SSH original command" in stderr.getvalue()


def test_bad_signature_fails_before_post_verification_dispatch() -> None:
    preface, trust = signed_preface()
    tampered_grant = Grant.from_payload(
        {**preface.signed_grant.grant.to_payload(), "remote_user": "mallory"}
    )
    tampered = Preface(
        PrefaceOperation.OPEN_SFTP,
        preface.nonce,
        SignedGrant(tampered_grant, preface.signed_grant.signature),
    )
    dispatched: list[Preface] = []
    stdout = BytesIO()

    result = run_ssh_entry(
        "transport-1",
        stdin=framed(tampered),
        stdout=stdout,
        stderr=StringIO(),
        environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_COMMAND},
        trust=trust,
        now=150,
        after_verification=dispatched.append,
    )

    assert result == 70
    assert dispatched == []
    stdout.seek(0)
    assert read_response(stdout)["code"] == ErrorCode.CRYPTO_SIGNATURE.string


def test_fuzz_target_never_raises_for_malformed_corpus() -> None:
    for payload in (b"", b"x", b"\xff" * 16, b"\x00\x00\x00\x02\xff\xff"):
        fuzz_preface(payload)
