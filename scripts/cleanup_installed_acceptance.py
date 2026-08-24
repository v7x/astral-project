#!/usr/bin/env python3
"""Installed fail-closed close fault-injection acceptance."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, "/usr/lib/astral-project/python")

from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    SignedGrant,
    SourceIdentity,
)
from astral_project.crypto.keys import load_private_key
from astral_project.mounts.lifecycle import MountManager
from astral_project.state.sqlite import StateDatabase


def _record(
    database: StateDatabase, root: Path, grant: SignedGrant, session_id: str, label: str
) -> tuple[str, Path]:
    mount_id = uuid.uuid4().hex
    mount_path = root / f"{label}-mount"
    mount_path.mkdir(mode=0o700)
    cache_path = root / f"{label}-cache"
    cache_path.mkdir(mode=0o700)
    database.create_mount_runtime(
        {
            "mount_id": mount_id,
            "session_id": session_id,
            "grant_id": str(grant.grant.grant_id),
            "mount_path": str(mount_path),
            "state": "ready",
            "mode": "rw",
            "virtual_target": "/project",
            "pid": None,
            "config_path": str(root / f"{label}.conf"),
            "cache_path": str(cache_path),
            "transport_capability": "rclone_sftp_external_ssh_v1",
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
        }
    )
    return mount_id, mount_path


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: cleanup_installed_acceptance.py RCLONE IDENTITY ISSUER_KEY "
            "HOST_ID HOST_FINGERPRINT",
            file=sys.stderr,
        )
        return 64
    rclone, _identity, issuer_text, host_id_text, fingerprint = sys.argv[1:]
    issuer = load_private_key(Path(issuer_text))
    now = int(time.time())
    with tempfile.TemporaryDirectory(prefix="cleanup-installed-") as temporary:
        root = Path(temporary)
        state = StateDatabase.open(root / "state.sqlite3")
        source = root / "source"
        source.mkdir(mode=0o700)
        stat = source.stat()
        grant = Grant(
            GrantId.new(),
            IssuerKeyId("00000000-0000-4000-8000-000000000001"),
            HostId(host_id_text),
            fingerprint,
            "testuser",
            now,
            now,
            now + 300,
            os.urandom(32),
            (
                GrantExport(
                    str(source),
                    str(source),
                    "/project",
                    AccessMode.READ_WRITE,
                    ExportKind.DIRECTORY,
                    SourceIdentity(stat.st_dev, stat.st_ino, "ext4", ExportKind.DIRECTORY),
                ),
            ),
        )
        signed = SignedGrant.create(grant, issuer)
        state.store_signed_grant(
            signed,
            host_key_fingerprint=fingerprint,
            remote_user="testuser",
            host_metadata={"address": "127.0.0.1", "identity_file": "/dev/null", "port": 22},
            stored_at=now,
            issuer_key=issuer.public_key(),
        )
        session_id = state.open_session(str(grant.grant_id))
        manager = MountManager(state, root / "runtime", rclone_binary=Path(rclone))
        ambiguous_id, ambiguous_path = _record(state, root, signed, session_id, "ambiguous")
        with (
            patch.object(manager, "_wait_for_vfs_uploads", lambda *_args: None),
            patch("astral_project.mounts.lifecycle.os.path.ismount", return_value=True),
            patch(
                "astral_project.mounts.lifecycle.subprocess.run",
                return_value=SimpleNamespace(returncode=0, stderr=b""),
            ),
            patch("astral_project.mounts.lifecycle.time.sleep", lambda _seconds: None),
        ):
            ambiguous = manager.close(ambiguous_id, flush_timeout=0.1)
        if ambiguous.state.value != "draining" or not ambiguous_path.exists():
            raise RuntimeError("ambiguous successful unmount did not remain draining and preserved")

        failed_id, failed_path = _record(state, root, signed, session_id, "failed")
        with (
            patch.object(manager, "_wait_for_vfs_uploads", lambda *_args: None),
            patch("astral_project.mounts.lifecycle.os.path.ismount", return_value=True),
            patch(
                "astral_project.mounts.lifecycle.subprocess.run",
                return_value=SimpleNamespace(returncode=1, stderr=b"injected unmount failure"),
            ),
        ):
            failed = manager.close(failed_id, flush_timeout=0.1)
        if failed.state.value != "draining" or not failed_path.exists():
            raise RuntimeError("failed unmount did not remain draining and preserved")

        uncertain_id, uncertain_path = _record(state, root, signed, session_id, "uncertain")
        with patch.object(manager, "_wait_for_vfs_uploads", side_effect=OSError("queue uncertain")):
            uncertain = manager.close(uncertain_id)
        if uncertain.state.value != "draining" or not uncertain_path.exists():
            raise RuntimeError("uncertain close did not remain draining and preserved")
        print(
            json.dumps(
                {
                    "package": "installed",
                    "ambiguous": {
                        "state": ambiguous.state.value,
                        "mount_preserved": ambiguous_path.exists(),
                    },
                    "failed_unmount": {
                        "state": failed.state.value,
                        "mount_preserved": failed_path.exists(),
                    },
                    "uncertain": {
                        "state": uncertain.state.value,
                        "mount_preserved": uncertain_path.exists(),
                    },
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
