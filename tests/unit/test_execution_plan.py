"""Packet 15B sealed worker plan tests."""

from __future__ import annotations

import fcntl
import os
from dataclasses import replace

import pytest

from astral_project.broker.execution_plan import (
    ExecutionPlanV1,
    _kind,
    create_sealed_execution_plan,
)
from astral_project.core.errors import AstralError
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import AccessMode, ExportKind, Grant, GrantExport, SourceIdentity
from astral_project.namespace.planner import build_namespace_plan


def _plan() -> ExecutionPlanV1:
    grant = Grant(
        grant_id=GrantId("00000000-0000-4000-8000-000000000001"),
        issuer_key_id=IssuerKeyId("00000000-0000-4000-8000-000000000002"),
        host_id=HostId("00000000-0000-4000-8000-000000000003"),
        ssh_host_key_fingerprint="SHA256:test",
        remote_user="alice",
        issued_at=1,
        not_before=1,
        expires_at=2,
        nonce=b"n" * 32,
        exports=(
            GrantExport(
                "/secret/source",
                "/secret/source",
                "/project",
                AccessMode.READ_ONLY,
                ExportKind.DIRECTORY,
                SourceIdentity(8, 42, "ext4", ExportKind.DIRECTORY),
            ),
        ),
    )
    return ExecutionPlanV1(build_namespace_plan(grant).exports, (7,))


def test_plan_has_no_source_path_and_uses_fixed_descriptor_slots() -> None:
    payload = _plan().to_bytes()

    assert payload.startswith(b"ASPRPLN1")
    assert b"/secret/source" not in payload
    assert b"/project" in payload


@pytest.mark.parametrize(
    "mount_ids",
    [(), (0,), (1, 2)],
)
def test_plan_rejects_invalid_mount_shape(mount_ids: tuple[int, ...]) -> None:
    with pytest.raises(AstralError):
        ExecutionPlanV1(_plan().exports, mount_ids)


def test_plan_encodes_write_access_and_file_kind() -> None:
    export = replace(
        _plan().exports[0],
        access_mode=AccessMode.READ_WRITE,
        kind=ExportKind.FILE.value,
        identity=SourceIdentity(8, 42, "ext4", ExportKind.FILE),
    )
    payload = ExecutionPlanV1((export,), (7,)).to_bytes()
    assert payload[20] == 2
    assert payload[21] == 1


def test_plan_rejects_unknown_kind() -> None:
    with pytest.raises(AstralError):
        _kind("unknown")


def test_memfd_plan_is_fully_sealed() -> None:
    descriptor = create_sealed_execution_plan(_plan())
    try:
        seals = fcntl.fcntl(descriptor, fcntl.F_GET_SEALS)
        assert seals & fcntl.F_SEAL_WRITE
        assert seals & fcntl.F_SEAL_SHRINK
        assert seals & fcntl.F_SEAL_GROW
        assert seals & fcntl.F_SEAL_SEAL
        with pytest.raises(OSError):
            os.write(descriptor, b"tamper")
    finally:
        os.close(descriptor)
