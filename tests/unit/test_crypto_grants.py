"""Canonical signed grant tests."""

from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    GrantVerificationContext,
    SignedGrant,
    SourceIdentity,
    _bytes,
    _cbor_mapping,
    _exact_fields,
    _integer,
    _list,
    _mapping,
    _object_mapping,
    _optional_bytes,
    _string,
    _string_value,
)
from astral_project.crypto.keys import generate_private_key, public_key_bytes, public_key_from_bytes

FIXTURE = Path(__file__).parents[1] / "fixtures" / "grants" / "grant-v1.cbor"


def sample_grant(**changes: object) -> Grant:
    values: dict[str, object] = {
        "grant_id": GrantId("00000000-0000-4000-8000-000000000001"),
        "issuer_key_id": IssuerKeyId("00000000-0000-4000-8000-000000000002"),
        "host_id": HostId("00000000-0000-4000-8000-000000000003"),
        "ssh_host_key_fingerprint": "SHA256:host-fingerprint",
        "remote_user": "alice",
        "issued_at": 1_700_000_000,
        "not_before": 1_700_000_000,
        "expires_at": 1_700_003_600,
        "nonce": b"n" * 32,
        "exports": (
            GrantExport(
                requested_source="/scratch/alice/project",
                canonical_source="/scratch/alice/project",
                virtual_target="/project",
                access_mode=AccessMode.READ_WRITE,
                kind=ExportKind.DIRECTORY,
                source_identity=SourceIdentity(
                    device=8,
                    inode=42,
                    filesystem_type="ext4",
                    object_type=ExportKind.DIRECTORY,
                ),
            ),
        ),
        "requested_features": ("sftp",),
        "server_policy_hash": b"p" * 32,
        "mandatory_extensions": {},
        "optional_extensions": {},
    }
    values.update(changes)
    return Grant(**values)  # type: ignore[arg-type]


def matching_context(grant: Grant, **changes: object) -> GrantVerificationContext:
    values: dict[str, object] = {
        "host_id": grant.host_id,
        "ssh_host_key_fingerprint": grant.ssh_host_key_fingerprint,
        "remote_user": grant.remote_user,
        "now": grant.not_before,
    }
    values.update(changes)
    return GrantVerificationContext(**values)  # type: ignore[arg-type]


def test_same_grant_structure_has_same_canonical_bytes_and_signature() -> None:
    key = generate_private_key()
    first = sample_grant(mandatory_extensions={"z": 1, "a": True})
    second = sample_grant(mandatory_extensions={"a": True, "z": 1})

    assert first.canonical_bytes() == second.canonical_bytes()
    assert SignedGrant.create(first, key).signature == SignedGrant.create(second, key).signature


def test_signed_grant_round_trip_and_golden_fixture() -> None:
    grant = sample_grant()
    signing_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    signed = SignedGrant.create(grant, signing_key)
    encoded = signed.to_cbor()
    decoded = SignedGrant.from_cbor(encoded)

    assert encoded == FIXTURE.read_bytes()
    assert decoded == signed
    assert (
        decoded.verify(
            public_key_from_bytes(public_key_bytes(signing_key)), matching_context(grant)
        )
        == grant
    )


def test_signature_rejects_mutated_bound_fields() -> None:
    signing_key = generate_private_key()
    grant = sample_grant()
    signed = SignedGrant.create(grant, signing_key)
    public = public_key_from_bytes(public_key_bytes(signing_key))
    replacements = (
        replace(grant, grant_id=GrantId("00000000-0000-4000-8000-000000000004")),
        replace(grant, issuer_key_id=IssuerKeyId("00000000-0000-4000-8000-000000000005")),
        replace(grant, host_id=HostId("00000000-0000-4000-8000-000000000006")),
        replace(grant, ssh_host_key_fingerprint="SHA256:changed"),
        replace(grant, remote_user="bob"),
        replace(grant, issued_at=1_699_999_999),
        replace(grant, not_before=1_700_000_001),
        replace(grant, expires_at=1_700_003_601),
        replace(grant, nonce=b"m" * 32),
        replace(grant, exports=(replace(grant.exports[0], virtual_target="/changed"),)),
        replace(grant, requested_features=("sftp", "stat")),
        replace(grant, server_policy_hash=b"q" * 32),
        replace(grant, mandatory_extensions={"required": True}),
        replace(grant, optional_extensions={"optional": True}),
    )

    for mutated in replacements:
        with pytest.raises(AstralError) as error:
            SignedGrant(mutated, signed.signature).verify(public, matching_context(mutated))
        assert error.value.code is ErrorCode.CRYPTO_SIGNATURE

    format_mutated = sample_grant()
    object.__setattr__(format_mutated, "format_version", 2)
    with pytest.raises(AstralError) as error:
        SignedGrant(format_mutated, signed.signature).verify(
            public, matching_context(format_mutated)
        )
    assert error.value.code is ErrorCode.CRYPTO_SIGNATURE


def test_context_binding_and_time_window_fail_closed() -> None:
    signing_key = generate_private_key()
    grant = sample_grant()
    signed = SignedGrant.create(grant, signing_key)
    public = public_key_from_bytes(public_key_bytes(signing_key))

    for context in (
        matching_context(grant, host_id=HostId("00000000-0000-4000-8000-000000000004")),
        matching_context(grant, ssh_host_key_fingerprint="SHA256:other"),
        matching_context(grant, remote_user="bob"),
        matching_context(grant, now=grant.not_before - 1),
        matching_context(grant, now=grant.expires_at),
    ):
        with pytest.raises(AstralError) as error:
            signed.verify(public, context)
        assert error.value.code is ErrorCode.CRYPTO_CONTEXT


def test_extension_rules_preserve_optional_data_when_policy_allows() -> None:
    signing_key = generate_private_key()
    grant = sample_grant(
        mandatory_extensions={"must-understand": True}, optional_extensions={"future": [1]}
    )
    signed = SignedGrant.create(grant, signing_key)
    public = public_key_from_bytes(public_key_bytes(signing_key))

    with pytest.raises(AstralError) as error:
        signed.verify(public, matching_context(grant))
    assert error.value.code is ErrorCode.GRANT_EXTENSION

    optional_only = sample_grant(optional_extensions={"future": [1]})
    optional_signed = SignedGrant.create(optional_only, signing_key)
    with pytest.raises(AstralError) as error:
        optional_signed.verify(public, matching_context(optional_only))
    assert error.value.code is ErrorCode.GRANT_EXTENSION

    context = matching_context(
        grant,
        known_mandatory_extensions=frozenset({"must-understand"}),
        allow_unknown_optional_extensions=True,
    )
    decoded = SignedGrant.from_cbor(signed.to_cbor())

    assert decoded.verify(public, context).optional_extensions == {"future": [1]}


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SourceIdentity(-1, 1, "ext4", ExportKind.FILE),
        lambda: GrantExport(
            "/source",
            "/source",
            "/target",
            AccessMode.READ_ONLY,
            ExportKind.FILE,
            SourceIdentity(1, 1, "ext4", ExportKind.DIRECTORY),
        ),
        lambda: GrantExport(
            "relative",
            "/source",
            "/target",
            AccessMode.READ_ONLY,
            ExportKind.FILE,
            SourceIdentity(1, 1, "ext4", ExportKind.FILE),
        ),
        lambda: sample_grant(format_version=2),
        lambda: sample_grant(ssh_host_key_fingerprint=""),
        lambda: sample_grant(remote_user=""),
        lambda: sample_grant(issued_at=True),
        lambda: sample_grant(not_before=1_699_999_999),
        lambda: sample_grant(server_policy_hash=b"short"),
        lambda: sample_grant(mandatory_extensions={"": True}),
    ],
)
def test_grant_constructor_rejects_invalid_values(factory: object) -> None:
    with pytest.raises(AstralError):
        factory()  # type: ignore[operator]


def test_grant_parser_helpers_fail_closed() -> None:
    with pytest.raises(AstralError):
        _object_mapping([], "map")
    with pytest.raises(AstralError):
        _mapping({}, "missing")
    with pytest.raises(AstralError):
        _cbor_mapping({"extension": []}, "extension")
    with pytest.raises(AstralError):
        _string_value(1, "text")
    with pytest.raises(AstralError):
        _string({}, "text")
    with pytest.raises(AstralError):
        _integer({}, "number")
    with pytest.raises(AstralError):
        _integer({"number": True}, "number")
    with pytest.raises(AstralError):
        _bytes({}, "bytes")
    with pytest.raises(AstralError):
        _bytes({"bytes": "bad"}, "bytes")
    with pytest.raises(AstralError):
        _optional_bytes({}, "maybe")
    assert _optional_bytes({"maybe": None}, "maybe") is None
    with pytest.raises(AstralError):
        _optional_bytes({"maybe": "bad"}, "maybe")
    with pytest.raises(AstralError):
        _list({}, "array")
    with pytest.raises(AstralError):
        _list({"array": "bad"}, "array")
    with pytest.raises(AstralError):
        _exact_fields({}, {"required"})


def test_signed_grant_parser_rejects_bad_envelope_and_signature() -> None:
    with pytest.raises(AstralError):
        SignedGrant.from_cbor(b"\xa1aa\x01")
    with pytest.raises(AstralError):
        SignedGrant(sample_grant(), b"short")
    with pytest.raises(AstralError):
        SourceIdentity.from_payload(
            {
                "device": 1,
                "inode": 1,
                "mount_id": 1,
                "filesystem_type": "ext4",
                "object_type": "bad",
            }
        )
    with pytest.raises(AstralError):
        GrantExport.from_payload(
            {
                "requested_source": "/x",
                "canonical_source": "/x",
                "virtual_target": "/x",
                "access_mode": "bad",
                "kind": "file",
                "source_identity": {
                    "device": 1,
                    "inode": 1,
                    "mount_id": 1,
                    "filesystem_type": "ext4",
                    "object_type": "file",
                },
            }
        )


def test_grant_rejects_invalid_fields() -> None:
    with pytest.raises(AstralError) as error:
        sample_grant(nonce=b"short")
    assert error.value.code is ErrorCode.GRANT_INVALID

    with pytest.raises(AstralError) as error:
        sample_grant(requested_features=("sftp", "sftp"))
    assert error.value.code is ErrorCode.GRANT_INVALID

    with pytest.raises(AstralError) as error:
        sample_grant(exports=())
    assert error.value.code is ErrorCode.GRANT_INVALID
