"""VM-only root authority artifacts are complete, typed, and deterministic."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from astral_project.broker import authority
from astral_project.broker.authority import AuthorityTomlV1, generate_vm_authority
from astral_project.core.errors import AstralError
from astral_project.core.ids import HostId, IssuerKeyId
from astral_project.crypto.grants import AccessMode, ExportKind
from astral_project.session.ceiling import ServerCeilingV1, SourceRootCeilingV1


def _authority(ceiling_path: Path) -> AuthorityTomlV1:
    return AuthorityTomlV1(
        expected_peer_uid=1001,
        expected_peer_gid=1001,
        host_id=HostId("00000000-0000-4000-8000-000000000002"),
        ssh_host_key_fingerprint="SHA256:test",
        remote_user="aspr-test",
        issuer_keys=((IssuerKeyId("00000000-0000-4000-8000-000000000001"), b"k" * 32),),
        transport_key_ids=("transport",),
        ceiling_path=ceiling_path,
    )


def test_generator_writes_strict_authority_toml_and_canonical_ceiling(tmp_path: Path) -> None:
    issuer = IssuerKeyId("00000000-0000-4000-8000-000000000001")
    ceiling = ServerCeilingV1(
        source_roots=(
            SourceRootCeilingV1("/srv/project", AccessMode.READ_ONLY, (ExportKind.DIRECTORY,)),
        ),
        allowed_issuers=(issuer,),
        forbidden_source_roots=(),
        max_exports=1,
        max_ttl_seconds=60,
        policy_hash=b"p" * 32,
    )
    ceiling_path = tmp_path / "ceiling.cbor"
    authority_path = tmp_path / "authority.toml"
    authority = AuthorityTomlV1(
        expected_peer_uid=1001,
        expected_peer_gid=1001,
        host_id=HostId("00000000-0000-4000-8000-000000000002"),
        ssh_host_key_fingerprint="SHA256:vm-only",
        remote_user="aspr-test",
        issuer_keys=((issuer, b"k" * 32),),
        transport_key_ids=("transport_01",),
        ceiling_path=ceiling_path,
    )

    generate_vm_authority(authority, ceiling, authority_path=authority_path)

    assert ServerCeilingV1.from_cbor(ceiling_path.read_bytes()) == ceiling
    assert tomllib.loads(authority_path.read_text(encoding="utf-8")) == {
        "version": 1,
        "expected_peer_gid": 1001,
        "expected_peer_uid": 1001,
        "host_id": str(authority.host_id),
        "remote_user": "aspr-test",
        "ssh_host_key_fingerprint": "SHA256:vm-only",
        "ceiling_path": str(ceiling_path),
        "transport_key_ids": ["transport_01"],
        "issuer_keys": {str(issuer): "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s="},
    }


def test_authority_rejects_unsafe_typed_values(tmp_path: Path) -> None:
    base = _authority(tmp_path / "ceiling.cbor")
    for kwargs in (
        {"expected_peer_uid": 0},
        {"ssh_host_key_fingerprint": ""},
        {"ceiling_path": Path("relative")},
        {"issuer_keys": ()},
        {"transport_key_ids": ()},
        {
            "issuer_keys": (
                (IssuerKeyId("00000000-0000-4000-8000-000000000002"), b"k" * 32),
                (IssuerKeyId("00000000-0000-4000-8000-000000000001"), b"k" * 32),
            )
        },
        {"issuer_keys": ((IssuerKeyId("00000000-0000-4000-8000-000000000001"), b"k"),)},
        {"transport_key_ids": ("z", "a")},
        {"remote_user": ""},
    ):
        values = {field: getattr(base, field) for field in base.__dataclass_fields__}
        values.update(kwargs)
        with pytest.raises(AstralError):
            AuthorityTomlV1(**values)


def test_authority_atomic_write_translates_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "authority.toml"
    monkeypatch.setattr(
        "astral_project.broker.authority.os.fchmod",
        lambda *_: (_ for _ in ()).throw(OSError("denied")),
    )
    with pytest.raises(AstralError):
        authority._atomic_write(path, b"data", 0o644)


def test_authority_generation_rejects_same_path(tmp_path: Path) -> None:
    authority = _authority(tmp_path / "same")
    ceiling = ServerCeilingV1(
        source_roots=(SourceRootCeilingV1("/srv", AccessMode.READ_ONLY, (ExportKind.DIRECTORY,)),),
        allowed_issuers=(IssuerKeyId("00000000-0000-4000-8000-000000000001"),),
        forbidden_source_roots=(),
        max_exports=1,
        max_ttl_seconds=1,
        policy_hash=b"p" * 32,
    )
    with pytest.raises(AstralError):
        generate_vm_authority(authority, ceiling, authority_path=authority.ceiling_path)
