#!/usr/bin/env python3
"""Installed revoked-grant operation acceptance probe."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from astral_project.core.errors import AstralError
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    SignedGrant,
    SourceIdentity,
)
from astral_project.crypto.keys import generate_private_key
from astral_project.mounts.lifecycle import MountManager
from astral_project.state.sqlite import StateDatabase


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="aspr-revoked-mount-") as directory:
        root = Path(directory)
        key = generate_private_key()
        grant = Grant(
            GrantId("00000000-0000-4000-8000-000000000001"),
            IssuerKeyId("00000000-0000-4000-8000-000000000002"),
            HostId("00000000-0000-4000-8000-000000000003"),
            "SHA256:host",
            "alice",
            100,
            100,
            200,
            b"g" * 32,
            (
                GrantExport(
                    "/root/project",
                    "/root/project",
                    "/project",
                    AccessMode.READ_WRITE,
                    ExportKind.DIRECTORY,
                    SourceIdentity(1, 2, "ext4", ExportKind.DIRECTORY),
                ),
            ),
        )
        signed = SignedGrant.create(grant, key)
        database = StateDatabase.open(root / "state.sqlite3")
        database.store_signed_grant(
            signed,
            host_key_fingerprint="SHA256:host",
            remote_user="alice",
            host_metadata={},
            stored_at=100,
            issuer_key=key.public_key(),
        )
        database.revoke_grant(str(grant.grant_id), reason="test", revoked_at=120)
        manager = MountManager(database, root / "runtime", clock=lambda: 130)
        try:
            manager.open(
                session_id="session",
                signed_grant=signed,
                mount_path=root / "mount",
                virtual_target="/project",
                host="host",
                identity_file=Path("/dev/null"),
                port=22,
            )
        except AstralError as error:
            result = {
                "operation": "MountManager.open",
                "grant_revoked": database.grant_is_revoked(str(grant.grant_id)),
                "result": "denied",
                "error_code": error.code.string,
            }
        else:
            result = {
                "operation": "MountManager.open",
                "grant_revoked": database.grant_is_revoked(str(grant.grant_id)),
                "result": "succeeded",
                "error_code": None,
            }
    print(json.dumps(result, sort_keys=True))
    return (
        0
        if result
        == {
            "operation": "MountManager.open",
            "grant_revoked": True,
            "result": "denied",
            "error_code": "ASPR_DAEMON_AUTH",
        }
        else 70
    )


if __name__ == "__main__":
    raise SystemExit(main())
