"""Attack-specific Packet 39 checks; these are semantic, not inventory checks."""

from __future__ import annotations

import errno
import json
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from io import BytesIO, StringIO
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from astral_project.audit import AuditLog
from astral_project.core.errors import AstralError
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    GrantVerificationContext,
    SignedGrant,
    SourceIdentity,
)
from astral_project.crypto.keys import generate_private_key
from astral_project.homed.overlay import OverlayBackend, OverlayStateError
from astral_project.homed.private import PrivateStateError, PrivateWritableBackend
from astral_project.profile import Profile
from astral_project.runtime.closure import RuntimeInput, RuntimeManifestV1, verify_runtime_closure
from astral_project.sandbox.environment import close_unlisted_fds, inherited_fd_inventory
from astral_project.server.entry import run_audit_export_entry
from astral_project.server.path_resolver import TrustedRoot, resolve_source
from astral_project.session.listing import SessionListingScope
from astral_project.state.sqlite import StateDatabase


def _signed_grant(*, expires_at: int = 200) -> tuple[SignedGrant, Ed25519PublicKey]:
    key = generate_private_key()
    grant = Grant(
        GrantId("00000000-0000-4000-8000-000000000001"),
        IssuerKeyId("00000000-0000-4000-8000-000000000002"),
        HostId("00000000-0000-4000-8000-000000000003"),
        "SHA256:host",
        "alice",
        100,
        100,
        expires_at,
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
    return SignedGrant.create(grant, key), key.public_key()


def test_r01_dotdot_traversal_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with TrustedRoot.open(str(root)) as trusted, pytest.raises(AstralError):
        resolve_source(trusted, str(root / ".." / "outside"))


@pytest.mark.parametrize("target", ["/etc/passwd", "../outside"])
def test_r02_r03_symlink_escapes_are_rejected(tmp_path: Path, target: str) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(target)
    with TrustedRoot.open(str(root)) as trusted, pytest.raises(AstralError):
        resolve_source(trusted, str(root / "link"))


def test_r04_symlink_swap_race_never_returns_indirected_source(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    safe = root / "safe"
    safe.write_text("safe", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    stop = threading.Event()

    def swap() -> None:
        while not stop.is_set():
            try:
                safe.unlink(missing_ok=True)
                safe.symlink_to(outside)
                safe.unlink(missing_ok=True)
                safe.write_text("safe", encoding="utf-8")
            except FileNotFoundError:
                pass

    thread = threading.Thread(target=swap)
    thread.start()
    try:
        with TrustedRoot.open(str(root)) as trusted:
            for _ in range(40):
                try:
                    with resolve_source(trusted, str(safe)) as resolved:
                        assert os.fstat(resolved.descriptor).st_ino == resolved.identity.inode
                except AstralError:
                    pass
    finally:
        stop.set()
        thread.join()


def test_r05_r06_rename_and_source_replacement_are_pinned(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    source = root / "source"
    source.write_text("safe", encoding="utf-8")
    with TrustedRoot.open(str(root)) as trusted, resolve_source(trusted, str(source)) as resolved:
        source.unlink()
        source.write_text("attacker", encoding="utf-8")
        assert os.fstat(resolved.descriptor).st_ino == resolved.identity.inode


def test_r07_proc_fd_magic_link_is_rejected() -> None:
    with TrustedRoot.open("/proc") as trusted, pytest.raises(AstralError):
        resolve_source(trusted, "/proc/self/fd/0")


def test_r08_inherited_fd_is_closed_before_use() -> None:
    descriptor = os.open("/dev/null", os.O_RDONLY)
    try:
        assert descriptor in inherited_fd_inventory()
        child = os.fork()
        if child == 0:
            close_unlisted_fds()
            try:
                os.fstat(descriptor)
            except OSError:
                os._exit(0)
            os._exit(1)
        _, status = os.waitpid(child, 0)
        assert os.waitstatus_to_exitcode(status) == 0
    finally:
        with suppress(OSError):
            os.close(descriptor)


def test_r09_nested_mount_metadata_is_advisory(tmp_path: Path) -> None:
    root = tmp_path / "root"
    (root / "project").mkdir(parents=True)
    with (
        TrustedRoot.open(str(root)) as trusted,
        resolve_source(trusted, str(root / "project")) as resolved,
    ):
        assert isinstance(resolved.nested_mounts, tuple)


def test_r10_r11_wrong_context_replays_are_rejected() -> None:
    signed, public = _signed_grant()
    grant = signed.grant
    for context in (
        GrantVerificationContext(
            HostId("00000000-0000-4000-8000-000000000009"), "SHA256:host", "alice", 150
        ),
        GrantVerificationContext(grant.host_id, "SHA256:host", "mallory", 150),
    ):
        with pytest.raises(AstralError):
            signed.verify(public, context)


def test_r12_expired_grant_is_rejected() -> None:
    signed, public = _signed_grant(expires_at=150)
    with pytest.raises(AstralError):
        signed.verify(
            public, GrantVerificationContext(signed.grant.host_id, "SHA256:host", "alice", 150)
        )


def test_r13_revoked_grant_is_unusable(tmp_path: Path) -> None:
    signed, public = _signed_grant()
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    database.store_signed_grant(
        signed,
        host_key_fingerprint="SHA256:host",
        remote_user="alice",
        host_metadata={},
        stored_at=100,
        issuer_key=public,
    )
    database.revoke_grant(signed.grant.grant_id.value, reason="attack", revoked_at=120)
    assert database.grant_is_revoked(signed.grant.grant_id.value)


def test_r14_runtime_bundle_extra_file_is_rejected(tmp_path: Path) -> None:
    destinations = ("etc/group", "etc/nsswitch.conf", "etc/passwd", "ld.so", "sftp-server")
    for destination in destinations:
        path = tmp_path / destination
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(destination.encode())
    manifest = RuntimeManifestV1(
        "x86_64", "glibc", tuple(RuntimeInput(item, tmp_path / item) for item in destinations)
    )
    (tmp_path / "manifest.cbor").write_bytes(manifest.canonical_bytes())
    (tmp_path / "manifest.toml").write_bytes(manifest.toml_bytes())
    (tmp_path / "unexplained").write_bytes(b"leak")
    with pytest.raises(AstralError):
        verify_runtime_closure(tmp_path, manifest)


def test_r15_multi_connection_scope_cannot_cross_grants() -> None:
    scope = SessionListingScope("grant-a", ("/project",))
    with pytest.raises(AstralError):
        scope.authorize("grant-b:/project")


def test_r16_private_hardlink_alias_is_rejected(tmp_path: Path) -> None:
    profile = Profile.from_toml(
        'version = 1\nid = "private"\nname = "private"\n'
        '[[home.rules]]\npath = ".cache"\nscope = "subtree"\nmode = "private-rw"\nlist = true\n'
    )
    with PrivateWritableBackend(tmp_path / "state", profile) as backend:
        backend.mkdir(".cache")
        handle = backend.open(".cache/file", os.O_RDWR | os.O_CREAT)
        backend.release(handle)
        backing = tmp_path / "state" / "private" / ".cache" / "file"
        os.link(backing, backing.with_name("alias"))
        with pytest.raises(PrivateStateError):
            backend.open(".cache/alias")


def test_r17_runtime_alias_and_r18_concurrent_alias_creation_are_rejected(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "source").write_bytes(b"source")
    with OverlayBackend(lower, tmp_path / "upper") as backend:

        def attempt(_: int) -> int:
            try:
                backend.link("source", "alias")
            except OverlayStateError as error:
                return error.errno or errno.EIO
            return 0

        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(32)))
        assert results == [errno.EOPNOTSUPP] * 32
        assert not (tmp_path / "upper" / "alias").exists()


def test_r20_forced_command_rejects_shell_marker(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.log")
    stdout = BytesIO()
    result = run_audit_export_entry(
        "transport",
        stdin=BytesIO(b"{}"),
        stdout=stdout,
        stderr=StringIO(),
        environment={"SSH_ORIGINAL_COMMAND": "sh -c id"},
        audit_log=log,
    )
    assert result == 70
    assert json.loads(stdout.getvalue())["ok"] is False
