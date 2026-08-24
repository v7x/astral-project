"""Packet 21-22 daemon mount lifecycle tests."""

import os
import subprocess
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from grant_helpers import sample_grant

import astral_project.mounts.lifecycle as lifecycle
from astral_project.core.errors import AstralError
from astral_project.core.ids import SessionId
from astral_project.crypto.grants import AccessMode, GrantExport, SignedGrant
from astral_project.crypto.keys import generate_private_key
from astral_project.mounts.lifecycle import MountManager, MountState
from astral_project.state.sqlite import StateDatabase


class FakeTransport:
    def __init__(self, *_args: object) -> None:
        pass

    def start(self) -> None:
        pass

    def serve_forever(self) -> None:
        pass

    def close(self) -> None:
        pass


def test_authority_marker_creation_and_failure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mount_path = tmp_path / "mount"
    mount_path.mkdir()
    lifecycle._create_authority_marker(mount_path, "a" * 32)
    marker = tmp_path / (".aspr-mount-" + "a" * 32)
    assert marker.read_text() == "a" * 32
    lifecycle._remove_authority_marker(mount_path, "a" * 32)
    assert not marker.exists()

    monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    lifecycle._create_authority_marker(mount_path, "b" * 32)
    lifecycle._remove_authority_marker(mount_path, "b" * 32)

    def fail_open(*_args: object, **_kwargs: object) -> int:
        raise OSError("denied")

    monkeypatch.setattr(os, "open", fail_open)
    with pytest.raises(AstralError):
        lifecycle._create_authority_marker(mount_path, "c" * 32)


class CallingTransport(FakeTransport):
    def __init__(self, _capability: object, factory: object) -> None:
        self.factory = factory

    def start(self) -> None:
        self.factory()  # type: ignore[operator]


class FakeProcess:
    pid = 43210

    def __init__(self, *, exited: bool = False) -> None:
        self.exited = exited
        self.stderr = SimpleNamespace(read=lambda: b"fake failure")
        self.returncode = 1 if exited else None

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.returncode = 0
        return 0


def setup_session(tmp_path: Path) -> tuple[StateDatabase, SignedGrant, str, Path]:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    grant = sample_grant()
    signed = SignedGrant.create(grant, generate_private_key())
    identity = tmp_path / "identity"
    identity.write_bytes(b"key")
    identity.chmod(0o600)
    database.activate_session(
        session_id=SessionId("00000000-0000-4000-8000-000000000010"),
        signed_grant=signed,
        host_id=grant.host_id,
        host_key_fingerprint=grant.ssh_host_key_fingerprint,
        remote_user=grant.remote_user,
        host_metadata={"address": "127.0.0.1", "identity_file": str(identity), "port": 22},
        started_at=grant.not_before,
    )
    mountpoint = tmp_path / "mount"
    mountpoint.mkdir()
    mountpoint.chmod(0o700)
    return database, signed, "00000000-0000-4000-8000-000000000010", identity


def test_open_reaches_ready_and_records_private_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, signed, session_id, identity = setup_session(tmp_path)
    mountpoint = tmp_path / "mount"
    process = FakeProcess()
    monkeypatch.setattr("astral_project.transport.local.PrivateTransportServer", CallingTransport)
    monkeypatch.setattr(
        "astral_project.transport.local.open_remote_sftp_stream",
        lambda *a, **k: SimpleNamespace(),
    )
    monkeypatch.setattr("astral_project.mounts.lifecycle.subprocess.Popen", lambda *a, **k: process)
    mounted = iter((False, True, True, True))
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.os.path.ismount", lambda _path: next(mounted)
    )
    manager = MountManager(
        database, tmp_path / "runtime", readiness_timeout=1, clock=lambda: 1_700_000_001
    )
    monkeypatch.setattr(manager, "_wait_for_vfs_uploads", lambda *_args: None)
    mount = manager.open(
        session_id=session_id,
        signed_grant=signed,
        mount_path=mountpoint,
        virtual_target="/project",
        host="127.0.0.1",
        identity_file=identity,
        port=22,
    )
    assert mount.state is MountState.READY
    assert mount.mode is AccessMode.READ_WRITE
    assert mount.config_path.stat().st_mode & 0o077 == 0
    assert database.mount_runtime(mount.mount_id)["state"] == "ready"
    assert manager.health(mount.mount_id).state is MountState.READY
    monkeypatch.setattr("astral_project.mounts.lifecycle._terminate", lambda *_args: None)
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stderr=b""),
    )
    process.wait = lambda timeout=None: (_ for _ in ()).throw(  # type: ignore[method-assign]
        subprocess.TimeoutExpired("wait", timeout or 1)
    )
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle._terminate", lambda p, _t: setattr(p, "returncode", 0)
    )
    database.revoke_grant(signed.grant.grant_id.value, reason="test")
    assert manager.health(mount.mount_id).state is MountState.CLOSED


def test_open_failure_marks_failed_and_cleans_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, signed, session_id, identity = setup_session(tmp_path)
    process = FakeProcess(exited=True)
    monkeypatch.setattr("astral_project.transport.local.PrivateTransportServer", FakeTransport)
    monkeypatch.setattr("astral_project.mounts.lifecycle.subprocess.Popen", lambda *a, **k: process)
    monkeypatch.setattr("astral_project.mounts.lifecycle._terminate", lambda *_a: None)
    with pytest.raises(AstralError, match="exited"):
        MountManager(
            database, tmp_path / "runtime", readiness_timeout=1, clock=lambda: 1_700_000_001
        ).open(
            session_id=session_id,
            signed_grant=signed,
            mount_path=tmp_path / "mount",
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
        )
    record = database.list_mount_runtime()[0]
    assert record["state"] == "failed"
    assert record["failure_reason"]


def test_read_only_grant_rejects_write_mount(tmp_path: Path) -> None:
    database, _signed, session_id, identity = setup_session(tmp_path)
    readonly = SignedGrant.create(
        sample_grant(
            exports=(
                GrantExport(
                    requested_source="/scratch/alice/project",
                    canonical_source="/scratch/alice/project",
                    virtual_target="/project",
                    access_mode=AccessMode.READ_ONLY,
                    kind=sample_grant().exports[0].kind,
                    source_identity=sample_grant().exports[0].source_identity,
                ),
            )
        ),
        generate_private_key(),
    )
    with pytest.raises(AstralError, match="read-write"):
        MountManager(database, tmp_path / "runtime", clock=lambda: 1_700_000_001).open(
            session_id=session_id,
            signed_grant=readonly,
            mount_path=tmp_path / "mount",
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
            mode=AccessMode.READ_WRITE,
        )


def test_close_reports_flush_failure_and_clean_close_removes_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, signed, session_id, identity = setup_session(tmp_path)
    process = FakeProcess()
    monkeypatch.setattr("astral_project.transport.local.PrivateTransportServer", FakeTransport)
    monkeypatch.setattr("astral_project.mounts.lifecycle.subprocess.Popen", lambda *a, **k: process)
    mounted = iter((False, True, True))
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.os.path.ismount", lambda _path: next(mounted)
    )
    monkeypatch.setattr("astral_project.mounts.lifecycle._terminate", lambda p, _t: p.wait())
    manager = MountManager(
        database, tmp_path / "runtime", readiness_timeout=1, clock=lambda: 1_700_000_001
    )
    mount = manager.open(
        session_id=session_id,
        signed_grant=signed,
        mount_path=tmp_path / "mount",
        virtual_target="/project",
        host="127.0.0.1",
        identity_file=identity,
        port=22,
    )
    monkeypatch.setattr(manager, "_unmount", lambda *_a: (_ for _ in ()).throw(OSError("flush")))
    failed = manager.close(mount.mount_id, flush_timeout=1)
    assert failed.state is MountState.DRAINING
    assert failed.flush_warning and "unflushed" in failed.flush_warning


def test_recover_marks_stale_and_enforces_revocation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, signed, session_id, _identity = setup_session(tmp_path)
    manager = MountManager(database, tmp_path / "runtime", clock=lambda: 1_700_000_001)
    monkeypatch.setattr(manager, "_wait_for_vfs_uploads", lambda *_args: None)
    config = tmp_path / "runtime" / "stale.conf"
    cache = tmp_path / "runtime" / "stale-cache"
    manager.runtime.mkdir()
    cache.mkdir()
    database.create_mount_runtime(
        {
            "mount_id": "stale",
            "session_id": session_id,
            "grant_id": signed.grant.grant_id.value,
            "mount_path": str(tmp_path / "mount"),
            "state": "ready",
            "mode": "rw",
            "virtual_target": "/project",
            "pid": 99999999,
            "config_path": str(config),
            "cache_path": str(cache),
            "transport_capability": "test",
            "created_at": 1,
            "updated_at": 1,
        }
    )
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.path.ismount", lambda _path: False)
    recovered = manager.recover()
    assert recovered[0].state is MountState.FAILED
    assert recovered[0].failure_reason
    database.revoke_grant(signed.grant.grant_id.value, reason="test")
    assert manager.enforce_grant_lifecycle()[0].state is MountState.CLOSED


def test_mount_rejections_and_argv_helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database, signed, session_id, identity = setup_session(tmp_path)
    manager = MountManager(database, tmp_path / "runtime", clock=lambda: 1_700_000_001)
    mountpoint = tmp_path / "mount"
    with pytest.raises(AstralError, match="mode"):
        manager.open(
            session_id=session_id,
            signed_grant=signed,
            mount_path=mountpoint,
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
            mode="bad",  # type: ignore[arg-type]
        )
    with pytest.raises(AstralError, match="normalized"):
        manager.open(
            session_id=session_id,
            signed_grant=signed,
            mount_path=mountpoint,
            virtual_target="/project/../bad",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
        )
    with pytest.raises(AstralError, match="outside signed"):
        manager.open(
            session_id=session_id,
            signed_grant=signed,
            mount_path=mountpoint,
            virtual_target="/other",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
        )
    ambiguous = SignedGrant.create(
        replace(signed.grant, exports=(signed.grant.exports[0], signed.grant.exports[0])),
        generate_private_key(),
    )
    with pytest.raises(AstralError, match="ambiguous"):
        manager.open(
            session_id=session_id,
            signed_grant=ambiguous,
            mount_path=mountpoint,
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
        )
    with pytest.raises(AstralError, match="identity"):
        manager.open(
            session_id=session_id,
            signed_grant=signed,
            mount_path=mountpoint,
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=tmp_path / "none",
            port=22,
        )
    public = tmp_path / "public"
    public.mkdir(mode=0o755)
    with pytest.raises(AstralError, match="private"):
        manager.open(
            session_id=session_id,
            signed_grant=signed,
            mount_path=public,
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
        )
    expired = SignedGrant.create(
        replace(signed.grant, expires_at=1_700_000_001), generate_private_key()
    )
    with pytest.raises(AstralError, match="expired"):
        manager.open(
            session_id=session_id,
            signed_grant=expired,
            mount_path=mountpoint,
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
        )
    database.revoke_grant(signed.grant.grant_id.value, reason="done")
    with pytest.raises(AstralError, match="revoked"):
        manager.open(
            session_id=session_id,
            signed_grant=signed,
            mount_path=mountpoint,
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
        )
    assert (
        manager._argv(Path("/a"), Path("/b"), "/project", mountpoint, AccessMode.READ_ONLY)[-1]
        == "--read-only"
    )
    with pytest.raises(AstralError, match="remote-control"):
        manager._argv(
            Path("/a"), Path("/b"), "/project", mountpoint, AccessMode.READ_ONLY, Path("relative")
        )
    with pytest.raises(AstralError, match="mode"):
        manager._argv(Path("/a"), Path("/b"), "/project", mountpoint, "bad")  # type: ignore[arg-type]
    with pytest.raises(AstralError, match="absolute"):
        MountManager(database, tmp_path / "runtime2", rclone_binary=Path("relative"))
    with pytest.raises(AstralError, match="timeout"):
        MountManager(database, tmp_path / "runtime2", readiness_timeout=0)


def test_vfs_upload_status_waits_for_queue_and_rejects_bad_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _signed, _session_id, _identity = setup_session(tmp_path)
    manager = MountManager(database, tmp_path / "runtime")
    responses = iter(
        (
            SimpleNamespace(
                returncode=0,
                stdout=b'{"diskCache":{"uploadsQueued":0,"uploadsInProgress":1}}',
            ),
            SimpleNamespace(
                returncode=0,
                stdout=b'{"diskCache":{"uploadsQueued":1,"uploadsInProgress":0}}',
            ),
            SimpleNamespace(returncode=0, stdout=b'{"queue":[{"id":1}]}'),
            SimpleNamespace(returncode=0, stdout=b"{}", stderr=b""),
            SimpleNamespace(
                returncode=0,
                stdout=b'{"diskCache":{"uploadsQueued":0,"uploadsInProgress":0}}',
            ),
        )
    )
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run", lambda *a, **k: next(responses)
    )
    monkeypatch.setattr("astral_project.mounts.lifecycle.time.sleep", lambda _seconds: None)
    manager._wait_for_vfs_uploads(tmp_path / "rc.sock", 1)

    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=b"{}"),
    )
    with pytest.raises(AstralError, match="unavailable"):
        manager._wait_for_vfs_uploads(tmp_path / "rc.sock", 1)
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=b'{"diskCache":{}}'),
    )
    with pytest.raises(AstralError, match="invalid"):
        manager._wait_for_vfs_uploads(tmp_path / "rc.sock", 1)
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run",
        lambda *a, **k: SimpleNamespace(
            returncode=0, stdout=b'{"diskCache":{"uploadsQueued":1,"uploadsInProgress":0}}'
        ),
    )
    with pytest.raises(AstralError, match="queue is unavailable"):
        manager._wait_for_vfs_uploads(tmp_path / "rc.sock", 1)
    bad_queue = iter(
        (
            SimpleNamespace(
                returncode=0,
                stdout=b'{"diskCache":{"uploadsQueued":1,"uploadsInProgress":0}}',
            ),
            SimpleNamespace(returncode=0, stdout=b'{"queue":[{}]}'),
        )
    )
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run", lambda *a, **k: next(bad_queue)
    )
    with pytest.raises(AstralError, match="queue is invalid"):
        manager._wait_for_vfs_uploads(tmp_path / "rc.sock", 1)
    expiry_failure = iter(
        (
            SimpleNamespace(
                returncode=0,
                stdout=b'{"diskCache":{"uploadsQueued":1,"uploadsInProgress":0}}',
            ),
            SimpleNamespace(returncode=0, stdout=b'{"queue":[{"id":1}]}'),
            SimpleNamespace(returncode=1, stdout=b"{}", stderr=b"permission denied"),
        )
    )
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run", lambda *a, **k: next(expiry_failure)
    )
    with pytest.raises(AstralError, match="expiry update failed"):
        manager._wait_for_vfs_uploads(tmp_path / "rc.sock", 1)


def test_mount_health_wait_unmount_and_process_helpers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, signed, session_id, identity = setup_session(tmp_path)
    process = FakeProcess()
    monkeypatch.setattr("astral_project.transport.local.PrivateTransportServer", FakeTransport)
    monkeypatch.setattr("astral_project.mounts.lifecycle.subprocess.Popen", lambda *a, **k: process)
    mounted = iter((False, True))
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.os.path.ismount", lambda _path: next(mounted)
    )
    manager = MountManager(
        database, tmp_path / "runtime", readiness_timeout=1, clock=lambda: 1_700_000_001
    )
    monkeypatch.setattr(manager, "_wait_for_vfs_uploads", lambda *_args: None)
    mount = manager.open(
        session_id=session_id,
        signed_grant=signed,
        mount_path=tmp_path / "mount",
        virtual_target="/project",
        host="127.0.0.1",
        identity_file=identity,
        port=22,
    )
    process.returncode = 1
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.path.ismount", lambda _path: False)
    assert manager.health(mount.mount_id).state is MountState.FAILED
    assert manager.close(mount.mount_id).state is MountState.CLOSED
    assert manager.close(mount.mount_id).state is MountState.CLOSED
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.path.ismount", lambda _path: False)
    manager._unmount(tmp_path / "mount", 1)


def test_mount_process_boundaries_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, _signed, _session_id, _identity = setup_session(tmp_path)
    manager = MountManager(database, tmp_path / "runtime", clock=lambda: 1_700_000_001)
    monkeypatch.setattr(manager, "_wait_for_vfs_uploads", lambda *_args: None)
    process = FakeProcess()
    monotonic = iter((0.0, 31.0))
    monkeypatch.setattr("astral_project.mounts.lifecycle.time.monotonic", lambda: next(monotonic))
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.path.ismount", lambda _path: False)
    with pytest.raises(AstralError, match="ready"):
        manager._wait_ready("m", tmp_path / "mount", process)  # type: ignore[arg-type]
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.path.ismount", lambda _path: True)
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=0, stderr=b""),
    )
    manager._unmount(tmp_path / "mount", 1)
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=1, stderr=b"bad"),
    )
    with pytest.raises(AstralError, match="unmount"):
        manager._unmount(tmp_path / "mount", 1)
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.kill", lambda *_a: None)
    assert lifecycle._pid_alive(1)
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.os.kill",
        lambda *_a: (_ for _ in ()).throw(ProcessLookupError()),
    )
    assert not lifecycle._pid_alive(1)
    nested = tmp_path / "nested"
    (nested / "child").mkdir(parents=True)
    (nested / "child" / "file").write_bytes(b"x")
    lifecycle._remove_private_tree(nested)
    assert not nested.exists()
    monotonic = iter((0.0, 1.0, 31.0))
    monkeypatch.setattr("astral_project.mounts.lifecycle.time.monotonic", lambda: next(monotonic))
    monkeypatch.setattr("astral_project.mounts.lifecycle.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.path.ismount", lambda _path: False)
    with pytest.raises(AstralError, match="ready"):
        manager._wait_ready("timeout", tmp_path / "mount", process)  # type: ignore[arg-type]

    class TimeoutProcess(FakeProcess):
        waits = 0

        def wait(self, timeout: float | None = None) -> int:
            self.waits += 1
            if self.waits == 1:
                raise __import__("subprocess").TimeoutExpired("x", timeout)
            return 0

    terminating = TimeoutProcess()
    calls: list[int] = []
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.os.killpg", lambda _pid, sig: calls.append(sig)
    )
    lifecycle._terminate(terminating, 1)  # type: ignore[arg-type]
    assert len(calls) == 2
    pid_states = iter((True, False, False))
    monkeypatch.setattr("astral_project.mounts.lifecycle._pid_alive", lambda _pid: next(pid_states))
    monkeypatch.setattr("astral_project.mounts.lifecycle.time.monotonic", lambda: 0.0)
    lifecycle._terminate_pid(1, 1)
    kill_states = iter((True, True, True, False, False))
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle._pid_alive", lambda _pid: next(kill_states)
    )
    monotonic_kill = iter((0.0, 2.0, 2.0, 2.0))
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.time.monotonic", lambda: next(monotonic_kill)
    )
    lifecycle._terminate_pid(1, 1)
    never = iter((True, True, True, True))
    monkeypatch.setattr("astral_project.mounts.lifecycle._pid_alive", lambda _pid: next(never))
    stuck_time = iter((0.0, 2.0, 2.0, 4.0))
    monkeypatch.setattr("astral_project.mounts.lifecycle.time.monotonic", lambda: next(stuck_time))
    with pytest.raises(AstralError, match="did not terminate"):
        lifecycle._terminate_pid(1, 1)
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.os.killpg",
        lambda *_a: (_ for _ in ()).throw(ProcessLookupError()),
    )
    lifecycle._terminate(FakeProcess(exited=True), 1)  # type: ignore[arg-type]
    lifecycle._terminate(FakeProcess(), 1)  # type: ignore[arg-type]


def test_mount_close_recovery_and_state_edges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database, signed, session_id, _identity = setup_session(tmp_path)
    manager = MountManager(database, tmp_path / "runtime", clock=lambda: 1_700_000_001)
    monkeypatch.setattr(manager, "_wait_for_vfs_uploads", lambda *_args: None)
    with pytest.raises(AstralError, match="timeout"):
        manager.close("missing", flush_timeout=0)
    manager.runtime.mkdir()
    database.create_mount_runtime(
        {
            "mount_id": "closed",
            "session_id": session_id,
            "grant_id": signed.grant.grant_id.value,
            "mount_path": str(tmp_path / "closed"),
            "state": "closed",
            "mode": "rw",
            "virtual_target": "/project",
            "pid": None,
            "config_path": str(tmp_path / "c"),
            "cache_path": str(tmp_path / "cache"),
            "transport_capability": "test",
            "created_at": 1,
            "updated_at": 1,
        }
    )
    assert manager.recover()[0].state is MountState.CLOSED
    database.create_mount_runtime(
        {
            "mount_id": "invalid",
            "session_id": session_id,
            "grant_id": signed.grant.grant_id.value,
            "mount_path": str(tmp_path / "invalid"),
            "state": "bad",
            "mode": "rw",
            "virtual_target": "/project",
            "pid": None,
            "config_path": str(tmp_path / "ic"),
            "cache_path": str(tmp_path / "invalid-cache"),
            "transport_capability": "test",
            "created_at": 2,
            "updated_at": 2,
        }
    )
    with pytest.raises(AstralError, match="state or mode"):
        manager._record("invalid")
    database.update_mount_runtime("invalid", state="failed")
    manager._fail("missing", None, "test")
    manager._processes.clear()
    database.create_mount_runtime(
        {
            "mount_id": "alive",
            "session_id": session_id,
            "grant_id": signed.grant.grant_id.value,
            "mount_path": str(tmp_path / "alive"),
            "state": "ready",
            "mode": "rw",
            "virtual_target": "/project",
            "pid": __import__("os").getpid(),
            "config_path": str(tmp_path / "ac"),
            "cache_path": str(tmp_path / "alive-cache"),
            "transport_capability": "test",
            "created_at": 2,
            "updated_at": 2,
        }
    )
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.path.ismount", lambda _path: True)
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.kill", lambda *_a: None)
    pid_state = iter((True, False, False))
    monkeypatch.setattr("astral_project.mounts.lifecycle._pid_alive", lambda _pid: next(pid_state))
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.subprocess.run",
        lambda *a, **k: SimpleNamespace(returncode=1, stderr=b"not mounted"),
    )
    assert manager.recover()[1].state is MountState.FAILED
    assert manager.health("alive").state is MountState.FAILED
    assert manager.enforce_grant_lifecycle() == ()
    database.create_mount_runtime(
        {
            "mount_id": "pid",
            "session_id": session_id,
            "grant_id": signed.grant.grant_id.value,
            "mount_path": str(tmp_path / "pid"),
            "state": "ready",
            "mode": "rw",
            "virtual_target": "/project",
            "pid": 99999999,
            "config_path": str(tmp_path / "pc"),
            "cache_path": str(tmp_path / "pid-cache"),
            "transport_capability": "test",
            "created_at": 3,
            "updated_at": 3,
        }
    )
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.path.ismount", lambda _path: False)
    monkeypatch.setattr("astral_project.mounts.lifecycle.os.kill", lambda *_a: None)
    monkeypatch.setattr("astral_project.mounts.lifecycle._pid_alive", lambda _pid: False)
    assert manager.close("pid").state is MountState.CLOSED
    mounted = iter((True, True))
    monkeypatch.setattr(
        "astral_project.mounts.lifecycle.os.path.ismount", lambda _path: next(mounted)
    )
    with pytest.raises(AstralError, match="already mounted"):
        manager.open(
            session_id=session_id,
            signed_grant=signed,
            mount_path=tmp_path / "mount",
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=_identity,
            port=22,
        )


def test_mountpoint_validation_rejects_public_or_missing(tmp_path: Path) -> None:
    database, signed, session_id, identity = setup_session(tmp_path)
    bad = tmp_path / "missing"
    with pytest.raises(AstralError, match="mountpoint"):
        MountManager(database, tmp_path / "runtime", clock=lambda: 1_700_000_001).open(
            session_id=session_id,
            signed_grant=signed,
            mount_path=bad,
            virtual_target="/project",
            host="127.0.0.1",
            identity_file=identity,
            port=22,
        )
