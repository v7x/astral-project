"""Packet 20 durable grant lifecycle tests."""

import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from grant_helpers import matching_context, sample_grant

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, HostId, SessionId
from astral_project.crypto.grants import AccessMode, Grant, GrantVerificationContext, SignedGrant
from astral_project.crypto.keys import generate_private_key
from astral_project.grants.lifecycle import GrantLifecycle, GrantValidator, compare_grants
from astral_project.state.sqlite import StateDatabase


def test_create_validates_before_signing_and_stores(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    lifecycle = GrantLifecycle(database)
    key = generate_private_key()
    events: list[str] = []

    def validator(grant: Grant) -> Grant:
        events.append("validate")
        return grant

    def approver(changes: tuple[str, ...]) -> bool:
        events.append(f"approve:{len(changes)}")
        return True

    signed = lifecycle.create(
        sample_grant(), validator=validator, approver=approver, signing_key=key
    )
    assert events == ["validate", "approve:0"]
    assert database.signed_grant(signed.grant.grant_id.value) == signed
    assert database.list_signed_grants() == (signed,)


def test_create_does_not_sign_when_remote_validation_fails(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    calls: list[str] = []

    def validator(_grant: Grant) -> Grant:
        calls.append("validate")
        raise RuntimeError("offline")

    with pytest.raises(AstralError, match="remote grant validation failed"):
        GrantLifecycle(database).create(
            sample_grant(),
            validator=cast(GrantValidator, validator),
            approver=lambda _changes: True,
            signing_key=generate_private_key(),
        )
    assert calls == ["validate"]
    assert database.list_signed_grants() == ()


def test_canonical_change_requires_approval(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    # Validator supplies changed canonical grant; constructor-level path checks remain active.
    changed = replace(sample_grant(), requested_features=())
    with pytest.raises(AstralError, match="approval"):
        GrantLifecycle(database).create(
            sample_grant(),
            validator=lambda _grant: changed,
            approver=lambda _changes: False,
            signing_key=generate_private_key(),
        )


def test_renew_rejects_widening_without_approval(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    key = generate_private_key()
    current = SignedGrant.create(sample_grant(requested_features=()), key)
    with pytest.raises(AstralError, match="fresh grant"):
        GrantLifecycle(database).renew(
            current,
            current.grant,
            validator=lambda value: value,
            approver=lambda _changes: True,
            signing_key=key,
            host_metadata={},
        )
    proposed = replace(
        sample_grant(requested_features=("sftp",)),
        grant_id=GrantId("00000000-0000-4000-8000-000000000014"),
        expires_at=1_700_007_200,
    )
    with pytest.raises(AstralError, match="widen"):
        GrantLifecycle(database).renew(
            current,
            proposed,
            validator=lambda grant: grant,
            approver=lambda _changes: False,
            signing_key=key,
            host_metadata={},
        )


def test_revoke_is_local_first_and_offline_is_recorded(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    signed = SignedGrant.create(sample_grant(), generate_private_key())
    database.store_signed_grant(
        signed,
        host_key_fingerprint=signed.grant.ssh_host_key_fingerprint,
        remote_user=signed.grant.remote_user,
        host_metadata={},
    )

    def offline(_signed: SignedGrant) -> None:
        raise OSError("remote unavailable")

    state = database.revoke_grant(signed.grant.grant_id.value, reason="test", remote_revoke=offline)
    assert state.startswith("offline:")
    assert database.grant_is_revoked(signed.grant.grant_id.value)
    with pytest.raises(AstralError, match="revoked"):
        database.import_signed_grant(signed)


def test_state_rejects_invalid_storage_and_session_transitions(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    signed = SignedGrant.create(sample_grant(), generate_private_key())
    with pytest.raises(AstralError, match="binding"):
        database.store_signed_grant(
            signed,
            host_key_fingerprint="wrong",
            remote_user=signed.grant.remote_user,
            host_metadata={},
        )
    with pytest.raises(AstralError, match="metadata"):
        database.store_signed_grant(
            signed,
            host_key_fingerprint=signed.grant.ssh_host_key_fingerprint,
            remote_user=signed.grant.remote_user,
            host_metadata={"bad": object()},
        )
    with pytest.raises(AstralError, match="enrolled"):
        database.import_signed_grant(signed)
    with pytest.raises(AstralError, match="not found"):
        database.signed_grant("missing")
    database.store_signed_grant(
        signed,
        host_key_fingerprint=signed.grant.ssh_host_key_fingerprint,
        remote_user=signed.grant.remote_user,
        host_metadata={},
        stored_at=signed.grant.not_before,
    )
    session_id = database.open_session(
        signed.grant.grant_id.value, started_at=signed.grant.not_before
    )
    assert database.list_sessions()[0]["session_id"] == session_id
    with pytest.raises(AstralError, match="another"):
        database.open_session(signed.grant.grant_id.value, started_at=signed.grant.not_before)
    database.close_session(session_id, ended_at=signed.grant.not_before + 1)
    with pytest.raises(AstralError, match="active session"):
        database.close_session(session_id)
    with database.transaction(write=True) as connection:
        connection.execute("UPDATE hosts SET metadata_json = '[]'")
    imported_again = SignedGrant.create(
        replace(
            signed.grant,
            grant_id=type(signed.grant.grant_id)("00000000-0000-4000-8000-000000000012"),
        ),
        generate_private_key(),
    )
    with pytest.raises(AstralError, match="metadata"):
        database.import_signed_grant(imported_again)
    with database.transaction(write=True) as connection:
        connection.execute("UPDATE hosts SET metadata_json = '{}'")
    with pytest.raises(AstralError, match="reason"):
        database.revoke_grant(signed.grant.grant_id.value, reason="")
    database.revoke_grant(signed.grant.grant_id.value, reason="done", revoked_at=2)
    assert len(database.list_signed_grants(include_revoked=True)) == 1
    with pytest.raises(AstralError, match="revoked"):
        database.open_session(signed.grant.grant_id.value, started_at=signed.grant.not_before)
    assert (
        database.revoke_grant(
            signed.grant.grant_id.value, reason="remote", remote_revoke=lambda _value: None
        )
        == "confirmed"
    )
    with pytest.raises(AstralError, match="revoked"):
        database.store_signed_grant(
            signed,
            host_key_fingerprint=signed.grant.ssh_host_key_fingerprint,
            remote_user=signed.grant.remote_user,
            host_metadata={},
        )


def test_lifecycle_rejects_invalid_validator_and_renewal_change(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    lifecycle = GrantLifecycle(database)
    with pytest.raises(AstralError, match="bad"):
        lifecycle.create(
            sample_grant(),
            validator=lambda _grant: (_ for _ in ()).throw(
                AstralError(ErrorCode.GRANT_INVALID, "bad", "bad", "bad", "retry")
            ),
            approver=lambda _changes: True,
            signing_key=generate_private_key(),
        )
    with pytest.raises(AstralError, match="canonical"):
        lifecycle.create(
            sample_grant(),
            validator=cast(GrantValidator, lambda _grant: "bad"),
            approver=lambda _changes: True,
            signing_key=generate_private_key(),
        )
    with pytest.raises(AstralError, match="approval"):
        lifecycle.create(
            sample_grant(),
            validator=lambda grant: grant,
            approver=lambda _changes: False,
            signing_key=generate_private_key(),
        )
    current = SignedGrant.create(sample_grant(), generate_private_key())
    changed = replace(sample_grant(), requested_features=())
    with pytest.raises(AstralError, match="renewed canonical"):
        lifecycle.renew(
            current,
            replace(sample_grant(), grant_id=GrantId("00000000-0000-4000-8000-000000000015")),
            validator=lambda _grant: changed,
            approver=lambda _changes: False,
            signing_key=generate_private_key(),
            host_metadata={},
        )
    with pytest.raises(AstralError, match="invalid renewed"):
        lifecycle.renew(
            current,
            replace(sample_grant(), grant_id=GrantId("00000000-0000-4000-8000-000000000017")),
            validator=cast(GrantValidator, lambda _grant: "bad"),
            approver=lambda _changes: True,
            signing_key=generate_private_key(),
            host_metadata={},
        )
    database.store_signed_grant(
        current,
        host_key_fingerprint=current.grant.ssh_host_key_fingerprint,
        remote_user=current.grant.remote_user,
        host_metadata={},
    )
    assert lifecycle.revoke(current.grant.grant_id.value, reason="done") == "pending"


def test_state_corrupt_grant_and_mount_record_errors(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    signed = SignedGrant.create(sample_grant(), generate_private_key())
    database.store_signed_grant(
        signed,
        host_key_fingerprint=signed.grant.ssh_host_key_fingerprint,
        remote_user=signed.grant.remote_user,
        host_metadata={},
    )
    with pytest.raises(AstralError, match="already stored"):
        database.store_signed_grant(
            signed,
            host_key_fingerprint=signed.grant.ssh_host_key_fingerprint,
            remote_user=signed.grant.remote_user,
            host_metadata={},
        )
    with database.transaction(write=True) as connection:
        connection.execute("UPDATE grants SET grant_cbor = X'00'")
    with pytest.raises(AstralError, match="stored grant"):
        database.list_signed_grants()
    with pytest.raises(AstralError, match="stored grant"):
        database.signed_grant(signed.grant.grant_id.value)
    with pytest.raises(AstralError, match="verification"):
        database.validate_signed_grant(
            signed, issuer_key=object(), context=matching_context(signed.grant)
        )
    with pytest.raises(AstralError, match="fields"):
        database.create_mount_runtime({"mount_id": "bad"})
    with pytest.raises(AstralError, match="update fields"):
        database.update_mount_runtime("bad", unknown=True)
    with pytest.raises(AstralError, match="not found"):
        database.update_mount_runtime("bad", state="failed")
    with pytest.raises(AstralError, match="not found"):
        database.mount_runtime("bad")
    valid = SignedGrant.create(sample_grant(), generate_private_key())
    unsigned = SignedGrant.from_cbor(valid.to_cbor())
    with pytest.raises(AstralError, match="issuer key"):
        database.activate_session(
            session_id=SessionId("00000000-0000-4000-8000-000000000021"),
            signed_grant=unsigned,
            host_id=unsigned.grant.host_id,
            host_key_fingerprint=unsigned.grant.ssh_host_key_fingerprint,
            remote_user=unsigned.grant.remote_user,
            host_metadata={},
            started_at=unsigned.grant.not_before,
        )
    with pytest.raises(AstralError, match="binding"):
        database.activate_session(
            session_id=SessionId("00000000-0000-4000-8000-000000000022"),
            signed_grant=valid,
            host_id=valid.grant.host_id,
            host_key_fingerprint=valid.grant.ssh_host_key_fingerprint,
            remote_user=valid.grant.remote_user,
            host_metadata=[],  # type: ignore[arg-type]
            started_at=valid.grant.not_before,
        )
    with pytest.raises(AstralError, match="issuer key"):
        database.store_signed_grant(
            unsigned,
            host_key_fingerprint=unsigned.grant.ssh_host_key_fingerprint,
            remote_user=unsigned.grant.remote_user,
            host_metadata={},
        )
    with pytest.raises(AstralError, match="issuer key"):
        database.issuer_public_key("missing")
    expired_db = StateDatabase.open(tmp_path / "expired.sqlite3")
    expired = SignedGrant.create(
        replace(valid.grant, expires_at=valid.grant.not_before + 1), generate_private_key()
    )
    expired_db.store_signed_grant(
        expired,
        host_key_fingerprint=expired.grant.ssh_host_key_fingerprint,
        remote_user=expired.grant.remote_user,
        host_metadata={},
    )
    with pytest.raises(AstralError, match="expired"):
        expired_db.open_session(expired.grant.grant_id.value, started_at=expired.grant.expires_at)
    hostless_db = StateDatabase.open(tmp_path / "hostless.sqlite3")
    hostless = SignedGrant.create(sample_grant(), generate_private_key())
    hostless_db.store_signed_grant(
        hostless,
        host_key_fingerprint=hostless.grant.ssh_host_key_fingerprint,
        remote_user=hostless.grant.remote_user,
        host_metadata={},
    )
    with sqlite3.connect(hostless_db.path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DELETE FROM hosts")
    with pytest.raises(AstralError, match="host binding"):
        hostless_db.open_session(
            hostless.grant.grant_id.value, started_at=hostless.grant.not_before
        )
    with hostless_db.transaction(write=True) as connection:
        connection.execute("UPDATE grant_issuer_keys SET public_key = X'00'")
    with pytest.raises(AstralError, match="issuer key"):
        hostless_db.issuer_public_key(hostless.grant.grant_id.value)
    with pytest.raises(AstralError, match="host binding"):
        hostless_db.grant_verification_context(hostless.grant.grant_id.value, now=1)
    with pytest.raises(AstralError):
        database.validate_signed_grant(
            valid,
            issuer_key=generate_private_key().public_key(),
            context=matching_context(valid.grant),
        )


def test_compare_all_capability_fields_and_renew(tmp_path: Path) -> None:
    grant = sample_grant()
    variants = (
        replace(grant, host_id=HostId("00000000-0000-4000-8000-000000000004")),
        replace(grant, ssh_host_key_fingerprint="SHA256:other"),
        replace(grant, remote_user="bob"),
        replace(
            grant,
            exports=(replace(grant.exports[0], access_mode=AccessMode.READ_ONLY),),
        ),
        replace(grant, requested_features=()),
        replace(grant, server_policy_hash=None),
        replace(grant, mandatory_extensions={"x": 1}),
        replace(grant, optional_extensions={"x": 1}),
    )
    assert all(compare_grants(grant, variant).changes for variant in variants)
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    key = generate_private_key()
    current = SignedGrant.create(grant, key)
    renewed = replace(
        grant,
        grant_id=GrantId("00000000-0000-4000-8000-000000000016"),
        expires_at=grant.expires_at + 10,
    )
    result = GrantLifecycle(database).renew(
        current,
        renewed,
        validator=lambda value: value,
        approver=lambda _changes: True,
        signing_key=key,
        host_metadata={},
    )
    assert result.grant.expires_at == grant.expires_at + 10
    canonical = replace(
        grant,
        grant_id=GrantId("00000000-0000-4000-8000-000000000013"),
        requested_features=(),
    )
    changed_result = GrantLifecycle(database).renew(
        current,
        replace(grant, grant_id=canonical.grant_id),
        validator=lambda _value: canonical,
        approver=lambda _changes: True,
        signing_key=key,
        host_metadata={},
    )
    assert changed_result.grant.requested_features == ()


def test_validate_signature_and_context(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    key = Ed25519PrivateKey.generate()
    grant = sample_grant()
    signed = SignedGrant.create(grant, key)
    context: GrantVerificationContext = matching_context(grant)
    assert (
        GrantLifecycle(database).validate(signed, issuer_key=key.public_key(), context=context)
        == grant
    )
    decision = compare_grants(grant, replace(grant, expires_at=grant.expires_at + 10))
    assert decision.changes == ()
    assert not decision.widened
