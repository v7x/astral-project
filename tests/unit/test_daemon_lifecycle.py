"""Daemon protocol coverage for Packets 20-22 lifecycle operations."""

import base64
import time
from dataclasses import replace
from pathlib import Path

import pytest
from grant_helpers import sample_grant

from astral_project.core.errors import AstralError
from astral_project.core.ids import GrantId, SessionId
from astral_project.crypto.grants import SignedGrant
from astral_project.crypto.keys import generate_private_key
from astral_project.daemon.server import (
    DaemonPaths,
    DaemonServer,
    _mount_payload,
    _select_source_export,
)
from astral_project.mounts.lifecycle import MountState, RemoteMount


def test_daemon_grant_and_session_operations(tmp_path: Path) -> None:
    paths = DaemonPaths(tmp_path / "runtime", tmp_path / "state" / "state.sqlite3")
    server = DaemonServer(paths)
    server.start(apply_hardening=False)
    assert server._database is not None
    base = sample_grant()
    now = int(time.time())
    grant = replace(base, issued_at=now, not_before=now, expires_at=now + 3600)
    signed = SignedGrant.create(grant, generate_private_key())
    server._database.activate_session(
        session_id=SessionId("00000000-0000-4000-8000-000000000010"),
        signed_grant=signed,
        host_id=grant.host_id,
        host_key_fingerprint=grant.ssh_host_key_fingerprint,
        remote_user=grant.remote_user,
        host_metadata={},
        started_at=grant.not_before,
    )
    imported = SignedGrant.create(
        replace(grant, grant_id=GrantId("00000000-0000-4000-8000-000000000011")),
        generate_private_key(),
    )
    assert imported.issuer_public_key is not None
    assert server._response(
        "grant.import",
        {
            "cbor_b64": base64.b64encode(imported.to_cbor()).decode("ascii"),
            "issuer_key_b64": base64.b64encode(
                imported.issuer_public_key.public_bytes_raw()
            ).decode("ascii"),
        },
    )["imported"]
    server._refresh_lifecycle()
    # Active session is present; grant list/show/validate remain available.
    listed = server._response("grant.list", {})
    assert listed["grants"]
    shown = server._response("grant.show", {"grant_id": str(grant.grant_id)})
    assert shown["grant_id"] == str(grant.grant_id)
    assert server._response("grant.validate", {"grant_id": str(grant.grant_id)})[
        "signature_verified"
    ]
    assert server._response("session.list")["sessions"]
    assert (
        server._response("session.show", {"session_id": "00000000-0000-4000-8000-000000000010"})[
            "state"
        ]
        == "active"
    )
    server._database.create_mount_runtime(
        {
            "mount_id": "mount",
            "session_id": "00000000-0000-4000-8000-000000000010",
            "grant_id": str(grant.grant_id),
            "mount_path": "/tmp/mount",
            "state": "ready",
            "mode": "rw",
            "virtual_target": "/project",
            "pid": None,
            "config_path": "/tmp/config",
            "cache_path": "/tmp/cache",
            "transport_capability": "test",
            "created_at": now,
            "updated_at": now,
        }
    )
    server._database.create_mount_runtime(
        {
            "mount_id": "mount-closed",
            "session_id": "00000000-0000-4000-8000-000000000010",
            "grant_id": str(grant.grant_id),
            "mount_path": "/tmp/mount-closed",
            "state": "closed",
            "mode": "rw",
            "virtual_target": "/project",
            "pid": None,
            "config_path": "/tmp/config-closed",
            "cache_path": "/tmp/cache-closed",
            "transport_capability": "test",
            "created_at": now,
            "updated_at": now,
        }
    )
    assert (
        server._response("session.close", {"session_id": "00000000-0000-4000-8000-000000000010"})[
            "state"
        ]
        == "closed"
    )
    assert server._response("session.open", {"grant_id": str(grant.grant_id)})["state"] == "active"
    assert (
        server._response("grant.revoke", {"grant_id": str(grant.grant_id), "reason": "done"})[
            "remote_state"
        ]
        == "pending"
    )
    assert server._response("grant.list", {"include_revoked": True})["grants"]
    server.close()


def test_daemon_lifecycle_missing_payloads_fail_closed(tmp_path: Path) -> None:
    server = DaemonServer(DaemonPaths(tmp_path / "runtime", tmp_path / "state" / "state.sqlite3"))
    server.start(apply_hardening=False)
    for operation in (
        "grant.show",
        "grant.import",
        "grant.validate",
        "grant.revoke",
        "session.open",
        "session.show",
        "session.close",
        "mount.open",
        "mount.show",
        "mount.close",
    ):
        with pytest.raises(AstralError):
            server._response(operation, None)
    with pytest.raises(AstralError, match="envelope"):
        server._response("grant.import", {"cbor_b64": 1})
    with pytest.raises(AstralError, match="issuer key"):
        server._response("grant.import", {"cbor_b64": "%%%"})
    with pytest.raises(AstralError, match="envelope"):
        server._response("grant.import", {"cbor_b64": "%%%", "issuer_key_b64": "%%%"})
    with pytest.raises(AstralError, match="not found"):
        server._response("session.show", {"session_id": "missing"})
    with pytest.raises(AstralError, match="active"):
        server._response(
            "mount.open", {"mount_path": "/tmp/m", "virtual_target": "/project", "mode": "ro"}
        )
    server._mounts = None
    server._refresh_lifecycle()
    original_listener = server._listener
    server._listener = type(
        "TimeoutListener", (), {"accept": lambda _self: (_ for _ in ()).throw(TimeoutError())}
    )()
    server.serve_once()
    server._listener = original_listener
    server._database = None
    server._refresh_lifecycle()
    for operation in ("grant.list", "session.list", "mount.list"):
        with pytest.raises(AstralError):
            server._response(operation)
    server.close()


def test_daemon_source_export_selection_rejects_normalization_and_ambiguity() -> None:
    signed = SignedGrant.create(sample_grant(), generate_private_key())
    with pytest.raises(AstralError, match="normalized"):
        _select_source_export(signed, "/scratch/alice/project/../bad")
    duplicate = replace(signed.grant, exports=(signed.grant.exports[0], signed.grant.exports[0]))
    with pytest.raises(AstralError, match="ambiguous"):
        _select_source_export(
            SignedGrant.create(duplicate, generate_private_key()), "/scratch/alice/project/child"
        )


def test_daemon_mount_open_uses_active_host_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = DaemonPaths(tmp_path / "runtime", tmp_path / "state" / "state.sqlite3")
    server = DaemonServer(paths)
    server.start(apply_hardening=False)
    assert server._database is not None and server._mounts is not None
    now = int(time.time())
    grant = replace(sample_grant(), issued_at=now, not_before=now, expires_at=now + 3600)
    signed = SignedGrant.create(grant, generate_private_key())
    identity = tmp_path / "identity"
    identity.write_bytes(b"key")
    identity.chmod(0o600)
    server._database.activate_session(
        session_id=SessionId("00000000-0000-4000-8000-000000000010"),
        signed_grant=signed,
        host_id=grant.host_id,
        host_key_fingerprint=grant.ssh_host_key_fingerprint,
        remote_user=grant.remote_user,
        host_metadata={"address": "127.0.0.1", "identity_file": str(identity), "port": 22},
        started_at=now,
    )
    mount = RemoteMount(
        "mount",
        "session",
        str(grant.grant_id),
        tmp_path / "mount",
        MountState.READY,
        grant.exports[0].access_mode,
        "/project",
        12,
        tmp_path / "config",
        tmp_path / "cache",
        "test",
    )
    monkeypatch.setattr(server._mounts, "open", lambda **_kwargs: mount)
    assert (
        server._response(
            "mount.open",
            {"mount_path": str(tmp_path / "mount"), "virtual_target": "/project", "mode": "rw"},
        )["mount_id"]
        == "mount"
    )
    assert (
        server._response(
            "mount.open",
            {
                "mount_path": str(tmp_path / "mount"),
                "source_path": "/scratch/alice/project",
                "mode": "rw",
            },
        )["mount_id"]
        == "mount"
    )
    assert (
        server._response(
            "mount.open",
            {
                "mount_path": str(tmp_path / "mount"),
                "source_path": "/scratch/alice/project/descendant",
                "mode": "ro",
            },
        )["mount_id"]
        == "mount"
    )
    with pytest.raises(AstralError, match="signed export"):
        server._response(
            "mount.open",
            {
                "mount_path": str(tmp_path / "mount"),
                "source_path": "/not-signed",
                "mode": "rw",
            },
        )
    with pytest.raises(AstralError, match="source path"):
        server._response(
            "mount.open",
            {
                "mount_path": str(tmp_path / "mount"),
                "source_path": 1,
                "mode": "rw",
            },
        )
    with pytest.raises(AstralError, match="mode"):
        server._response(
            "mount.open",
            {"mount_path": str(tmp_path / "mount"), "virtual_target": "/project", "mode": "bad"},
        )
    with server._database.transaction(write=True) as connection:
        connection.execute("UPDATE hosts SET metadata_json = '{\"address\": 1}'")
    with pytest.raises(AstralError, match="metadata"):
        server._response(
            "mount.open",
            {"mount_path": str(tmp_path / "mount"), "virtual_target": "/project", "mode": "rw"},
        )
    server.close()


def test_daemon_mount_response_shapes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = DaemonPaths(tmp_path / "runtime", tmp_path / "state" / "state.sqlite3")
    server = DaemonServer(paths)
    server.start(apply_hardening=False)
    assert server._mounts is not None
    mount = RemoteMount(
        "mount",
        "session",
        "grant",
        tmp_path / "mount",
        MountState.READY,
        sample_grant().exports[0].access_mode,
        "/project",
        12,
        tmp_path / "config",
        tmp_path / "cache",
        "test",
    )
    monkeypatch.setattr(server._mounts, "_record", lambda _mount_id: mount)
    monkeypatch.setattr(server._mounts, "health", lambda _mount_id: mount)
    monkeypatch.setattr(server._mounts, "close", lambda _mount_id: mount)
    assert server._response("mount.list")["mounts"] == []
    assert server._response("mount.show", {"mount_id": "mount"})["state"] == "ready"
    assert server._response("mount.close", {"mount_id": "mount"})["mount_id"] == "mount"
    with pytest.raises(AstralError):
        _mount_payload("bad")
    server.close()
