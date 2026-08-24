"""Shared grant fixtures for lifecycle tests."""

from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    GrantVerificationContext,
    SourceIdentity,
)


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
                "/scratch/alice/project",
                "/scratch/alice/project",
                "/project",
                AccessMode.READ_WRITE,
                ExportKind.DIRECTORY,
                SourceIdentity(8, 42, "ext4", ExportKind.DIRECTORY),
            ),
        ),
        "requested_features": ("sftp",),
        "server_policy_hash": b"p" * 32,
        "mandatory_extensions": {},
        "optional_extensions": {},
    }
    values.update(changes)
    return Grant(**values)  # type: ignore[arg-type]


def matching_context(grant: Grant) -> GrantVerificationContext:
    return GrantVerificationContext(
        host_id=grant.host_id,
        ssh_host_key_fingerprint=grant.ssh_host_key_fingerprint,
        remote_user=grant.remote_user,
        now=grant.not_before,
    )
