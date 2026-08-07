"""Packet 14 pure deterministic namespace planner tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from astral_project.core.errors import AstralError
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import AccessMode, ExportKind, Grant, GrantExport, SourceIdentity
from astral_project.namespace.planner import (
    INTERNAL_STAGING_ROOT,
    NamespacePlan,
    _normalized_target,
    build_namespace_plan,
)

FIXTURE = Path(__file__).parents[1] / "fixtures" / "namespace" / "namespace-plan-v1.cbor"


def _export(target: str, *, inode: int = 1, mode: AccessMode = AccessMode.READ_ONLY) -> GrantExport:
    return GrantExport(
        requested_source=f"/source/{inode}",
        canonical_source=f"/source/{inode}",
        virtual_target=target,
        access_mode=mode,
        kind=ExportKind.DIRECTORY,
        source_identity=SourceIdentity(inode, inode, "ext4", ExportKind.DIRECTORY),
    )


def _grant(exports: tuple[GrantExport, ...]) -> Grant:
    return Grant(
        grant_id=GrantId("00000000-0000-4000-8000-000000000001"),
        issuer_key_id=IssuerKeyId("00000000-0000-4000-8000-000000000002"),
        host_id=HostId("00000000-0000-4000-8000-000000000003"),
        ssh_host_key_fingerprint="SHA256:test",
        remote_user="testuser",
        issued_at=1,
        not_before=1,
        expires_at=2,
        nonce=b"n" * 32,
        exports=exports,
    )


def test_plan_is_deterministic_and_has_no_source_path() -> None:
    first = _grant((_export("/z", inode=2), _export("/a", inode=1)))
    second = replace(first, exports=tuple(reversed(first.exports)))

    plan = build_namespace_plan(first)

    assert plan == build_namespace_plan(second)
    assert [item.virtual_target for item in plan.exports] == ["/a", "/z"]
    assert not any(hasattr(item, "canonical_source") for item in plan.exports)
    assert plan.staging_root == INTERNAL_STAGING_ROOT
    assert plan.workload == "sftp_v1"


def test_plan_cbor_round_trip_and_golden_fixture() -> None:
    plan = build_namespace_plan(_grant((_export("/a"),)))
    encoded = plan.canonical_bytes()

    assert encoded == FIXTURE.read_bytes()
    assert NamespacePlan.from_cbor(encoded) == plan


def test_exact_duplicate_export_is_collapsed() -> None:
    plan = build_namespace_plan(_grant((_export("/same"), _export("/same"))))

    assert len(plan.exports) == 1
    assert plan.exports[0].descriptor_slot == 0


@pytest.mark.parametrize(
    "exports",
    [
        (_export("/same", inode=1), _export("/same", inode=2)),
        (_export("/parent"), _export("/parent/child", inode=2)),
        (_export(f"{INTERNAL_STAGING_ROOT}/bad"),),
        (_export("/.astral-project"),),
        (_export("/.astral-project-runtime/child"),),
        (_export("/" + "a" * 4097),),
        (_export("/"),),
    ],
)
def test_plan_rejects_ambiguous_or_reserved_targets(exports: tuple[GrantExport, ...]) -> None:
    with pytest.raises(AstralError):
        build_namespace_plan(_grant(exports))


def test_target_normalizer_rejects_nul_before_native_plan_encoding() -> None:
    with pytest.raises(AstralError):
        _normalized_target("/bad\x00target")
