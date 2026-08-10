"""Broker source pinning tests."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from astral_project.broker.sources import pin_grant_sources
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import AccessMode, ExportKind, Grant, GrantExport, SourceIdentity
from astral_project.server.path_resolver import TrustedRoot, resolve_source
from astral_project.session.ceiling import ServerCeilingV1, SourceRootCeilingV1


def _identity(root: Path, source: Path) -> SourceIdentity:
    with TrustedRoot.open(str(root)) as trusted, resolve_source(trusted, str(source)) as resolved:
        return SourceIdentity(
            device=resolved.identity.device,
            inode=resolved.identity.inode,
            filesystem_type=resolved.identity.filesystem_type,
            object_type=resolved.identity.kind,
        )


def _grant(root: Path, exports: tuple[GrantExport, ...]) -> tuple[Grant, ServerCeilingV1]:
    issuer = IssuerKeyId("00000000-0000-4000-8000-000000000002")
    grant = Grant(
        grant_id=GrantId("00000000-0000-4000-8000-000000000001"),
        issuer_key_id=issuer,
        host_id=HostId("00000000-0000-4000-8000-000000000003"),
        ssh_host_key_fingerprint="SHA256:host",
        remote_user="testuser",
        issued_at=100,
        not_before=100,
        expires_at=200,
        nonce=b"g" * 32,
        exports=exports,
    )
    ceiling = ServerCeilingV1(
        source_roots=(SourceRootCeilingV1(str(root), AccessMode.READ_ONLY, (ExportKind.FILE,)),),
        allowed_issuers=(issuer,),
        forbidden_source_roots=(),
        max_exports=2,
        max_ttl_seconds=100,
        policy_hash=b"p" * 32,
    )
    return grant, ceiling


def _export(source: Path, identity: SourceIdentity, target: str) -> GrantExport:
    return GrantExport(
        requested_source=str(source),
        canonical_source=str(source),
        virtual_target=target,
        access_mode=AccessMode.READ_ONLY,
        kind=ExportKind.FILE,
        source_identity=identity,
    )


def test_pin_grant_sources_keeps_descriptors_in_plan_slot_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("astral_project.broker.sources.linux.clone_mount", os.dup)
    root = tmp_path / "root"
    root.mkdir()
    first, second = root / "first", root / "second"
    first.write_text("first", encoding="utf-8")
    second.write_text("second", encoding="utf-8")
    grant, ceiling = _grant(
        root,
        (
            _export(first, _identity(root, first), "/z"),
            _export(second, _identity(root, second), "/a"),
        ),
    )

    with pin_grant_sources(grant, ceiling) as pinned:
        assert tuple(item.export.descriptor_slot for item in pinned.sources) == (0, 1)
        assert tuple(item.export.virtual_target for item in pinned.sources) == ("/a", "/z")
        assert tuple(os.fstat(item.descriptor).st_ino for item in pinned.sources) == (
            second.stat().st_ino,
            first.stat().st_ino,
        )
        first.unlink()
        assert os.fstat(pinned.sources[1].descriptor).st_nlink == 0


def test_pin_grant_sources_rejects_identity_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("astral_project.broker.sources.linux.clone_mount", os.dup)
    root = tmp_path / "root"
    root.mkdir()
    source = root / "source"
    source.write_text("before", encoding="utf-8")
    identity = _identity(root, source)
    source.rename(root / "original")
    source.write_text("replacement", encoding="utf-8")
    assert source.stat().st_ino != identity.inode
    grant, ceiling = _grant(root, (_export(source, identity, "/project"),))

    with pytest.raises(Exception, match="signed source identity"):
        pin_grant_sources(grant, ceiling)
