"""Durable SQLite state tests."""

from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, HostId, IssuerKeyId, SessionId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    SignedGrant,
    SourceIdentity,
)
from astral_project.state.sqlite import INITIAL_MIGRATION, Migration, StateDatabase

FIXTURE = Path(__file__).parents[1] / "fixtures" / "state" / "v1-state.sqlite3"
EXPECTED_TABLES = {
    "approvals",
    "audit_events",
    "grants",
    "hosts",
    "mounts",
    "profile_metadata",
    "revocations",
    "schema_migrations",
    "sessions",
    "state_meta",
}


def table_names(database: StateDatabase) -> set[str]:
    with database.transaction() as connection:
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    return {str(row[0]) for row in rows}


def insert_host(database: StateDatabase, host_id: str = "host-1") -> None:
    with database.transaction(write=True) as connection:
        connection.execute(
            "INSERT INTO hosts(host_id, host_key_fingerprint, remote_user, metadata_json, "
            "created_at, updated_at) VALUES (?, 'fingerprint', 'alice', '{}', 0, 0)",
            (host_id,),
        )


def test_active_listing_scope_is_bound_to_one_active_grant(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    assert database.active_listing_scope() is None
    grant_id = GrantId("00000000-0000-4000-8000-000000000001")
    host_id = HostId("00000000-0000-4000-8000-000000000002")
    grant = Grant(
        grant_id,
        IssuerKeyId("00000000-0000-4000-8000-000000000003"),
        host_id,
        "SHA256:test",
        "alice",
        1,
        1,
        2,
        b"n" * 32,
        (
            GrantExport(
                "/source",
                "/source",
                "/project",
                AccessMode.READ_ONLY,
                ExportKind.DIRECTORY,
                SourceIdentity(8, 42, "ext4", ExportKind.DIRECTORY),
            ),
        ),
    )
    signed = SignedGrant.create(grant, Ed25519PrivateKey.generate())
    with database.transaction(write=True) as connection:
        connection.execute(
            "INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?)",
            (str(host_id), "SHA256:test", "alice", "{}", 1, 1),
        )
        connection.execute(
            "INSERT INTO grants VALUES (?, ?, ?, ?, ?)",
            (str(grant_id), str(host_id), signed.to_cbor(), 1, 2),
        )
        connection.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
            ("00000000-0000-4000-8000-000000000004", str(grant_id), "active", 1, None),
        )
    scope = database.active_listing_scope()
    assert scope is not None
    assert (
        scope.authorize("00000000-0000-4000-8000-000000000001:/project") == "aspr-session:/project"
    )
    with database.transaction(write=True) as connection:
        connection.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
            ("00000000-0000-0000-0000-000000000005", str(grant_id), "active", 2, None),
        )
    with pytest.raises(AstralError):
        database.active_listing_scope()
    with database.transaction(write=True) as connection:
        connection.execute("DELETE FROM sessions WHERE session_id LIKE '00000000-0000-0000-%'")
        connection.execute("UPDATE grants SET grant_cbor = ?", (b"invalid",))
    with pytest.raises(AstralError):
        database.active_listing_scope()
    with database.transaction(write=True) as connection:
        connection.execute("UPDATE grants SET grant_cbor = ?", (signed.to_cbor(),))
        connection.execute("UPDATE hosts SET metadata_json = ?", ("[]",))
    with pytest.raises(AstralError):
        database.active_listing_scope()


def test_activate_session_binds_signed_grant_and_host(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    host_id = HostId("00000000-0000-4000-8000-000000000002")
    grant = Grant(
        GrantId("00000000-0000-4000-8000-000000000001"),
        IssuerKeyId("00000000-0000-4000-8000-000000000003"),
        host_id,
        "SHA256:test",
        "alice",
        1,
        1,
        2,
        b"n" * 32,
        (
            GrantExport(
                "/source",
                "/source",
                "/project",
                AccessMode.READ_ONLY,
                ExportKind.DIRECTORY,
                SourceIdentity(8, 42, "ext4", ExportKind.DIRECTORY),
            ),
        ),
    )
    issuer_key = Ed25519PrivateKey.generate()
    signed = SignedGrant.create(grant, issuer_key)
    session_id = SessionId("00000000-0000-4000-8000-000000000004")
    database.activate_session(
        session_id=session_id,
        signed_grant=signed,
        host_id=host_id,
        host_key_fingerprint="SHA256:test",
        remote_user="alice",
        host_metadata={"address": "127.0.0.1", "identity_file": "/tmp/id", "port": 22},
        started_at=1,
    )
    changed_grant = replace(
        grant,
        grant_id=GrantId("00000000-0000-4000-8000-000000000007"),
        ssh_host_key_fingerprint="SHA256:new",
    )
    database.store_signed_grant(
        SignedGrant.create(changed_grant, issuer_key),
        host_key_fingerprint="SHA256:new",
        remote_user="alice",
        host_metadata={"address": "127.0.0.1", "identity_file": "/tmp/id", "port": 22},
        stored_at=2,
    )
    active = database.active_listing_session()
    assert active is not None
    assert active.session_id == str(session_id)
    assert active.signed_grant.grant.grant_id == grant.grant_id
    assert active.host_metadata["address"] == "127.0.0.1"
    assert database.retire_expired_sessions(now=2) == 1
    assert database.active_listing_session() is None
    with pytest.raises(AstralError):
        database.activate_session(
            session_id=SessionId("00000000-0000-4000-8000-000000000005"),
            signed_grant=signed,
            host_id=HostId("00000000-0000-4000-8000-000000000006"),
            host_key_fingerprint="SHA256:test",
            remote_user="alice",
            host_metadata={},
            started_at=1,
        )
    with pytest.raises(AstralError):
        database.activate_session(
            session_id=SessionId("00000000-0000-4000-8000-000000000005"),
            signed_grant=signed,
            host_id=host_id,
            host_key_fingerprint="SHA256:test",
            remote_user="alice",
            host_metadata={"bad": object()},
            started_at=1,
        )


def test_create_empty_database_and_reopen(tmp_path: Path) -> None:
    path = tmp_path / "state" / "state.sqlite3"
    database = StateDatabase.open(path)

    assert database.state_version == 1
    assert table_names(database) >= EXPECTED_TABLES
    assert path.stat().st_mode & 0o077 == 0
    with database.transaction() as connection:
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    insert_host(database)
    reopened = StateDatabase.open(path)
    with reopened.transaction() as connection:
        assert connection.execute("SELECT host_id FROM hosts").fetchone()[0] == "host-1"


def test_migrate_from_fixture(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    shutil.copy2(FIXTURE, path)
    path.chmod(0o600)

    def add_marker(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE fixture_marker (value TEXT NOT NULL)")

    migration = Migration(2, "fixture-marker", "CREATE TABLE fixture_marker", add_marker)
    database = StateDatabase.open(path, (INITIAL_MIGRATION, migration))

    assert database.state_version == 2
    assert "fixture_marker" in table_names(database)


def test_failed_migration_rolls_back(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    StateDatabase.open(path)

    def fail_after_ddl(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE should_rollback (value TEXT)")
        raise sqlite3.DatabaseError("injected migration failure")

    migration = Migration(2, "failing", "CREATE TABLE should_rollback", fail_after_ddl)
    with pytest.raises(AstralError) as error:
        StateDatabase.open(path, (INITIAL_MIGRATION, migration))
    assert error.value.code is ErrorCode.STATE_MIGRATION

    reopened = StateDatabase.open(path)
    assert reopened.state_version == 1
    assert "should_rollback" not in table_names(reopened)


def test_destructive_migration_writes_backup_before_change(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    StateDatabase.open(path)

    def remove_audit_table(connection: sqlite3.Connection) -> None:
        connection.execute("DROP TABLE audit_events")

    migration = Migration(
        2, "remove-audit", "DROP TABLE audit_events", remove_audit_table, destructive=True
    )
    upgraded = StateDatabase.open(path, (INITIAL_MIGRATION, migration))
    backup = path.parent / "state-before-v2.sqlite3"

    assert "audit_events" not in table_names(upgraded)
    assert backup.exists()
    backup.chmod(0o600)
    backup_database = StateDatabase.open(backup)
    assert "audit_events" in table_names(backup_database)


@pytest.mark.parametrize("mode", [0o640, 0o644])
def test_open_rejects_loose_database_mode(tmp_path: Path, mode: int) -> None:
    path = tmp_path / "state.sqlite3"
    StateDatabase.open(path)
    path.chmod(mode)

    with pytest.raises(AstralError) as error:
        StateDatabase.open(path)
    assert error.value.code is ErrorCode.PERMISSION_INSECURE_MODE


def test_concurrent_read_uses_snapshot(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")

    with database.transaction() as reader:
        assert reader.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0
        insert_host(database)
        assert reader.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0

    with database.transaction() as fresh_reader:
        assert fresh_reader.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1


def test_crash_during_transaction_leaves_valid_database(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    StateDatabase.open(path)
    script = (
        "import os, sqlite3, sys; "
        "connection = sqlite3.connect(sys.argv[1]); "
        "connection.execute('BEGIN IMMEDIATE'); "
        "connection.execute('CREATE TABLE crash_partial (value TEXT)'); "
        "os._exit(91)"
    )

    result = subprocess.run([sys.executable, "-c", script, str(path)], check=False)

    assert result.returncode == 91
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'crash_partial'"
            ).fetchone()[0]
            == 0
        )
    finally:
        connection.close()


def test_newer_or_invalid_migration_registry_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"

    def marker(connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE marker (value TEXT)")

    migration = Migration(2, "marker", "CREATE TABLE marker", marker)
    StateDatabase.open(path, (INITIAL_MIGRATION, migration))
    with pytest.raises(AstralError) as error:
        StateDatabase.open(path)
    assert error.value.code is ErrorCode.STATE_VERSION

    with pytest.raises(AstralError) as error:
        StateDatabase(path, (Migration(2, "gap", "", marker),))
    assert error.value.code is ErrorCode.STATE_VERSION

    with pytest.raises(AstralError) as error:
        StateDatabase(
            path,
            (INITIAL_MIGRATION, Migration(2, INITIAL_MIGRATION.name, "duplicate", marker)),
        )
    assert error.value.code is ErrorCode.STATE_VERSION


def test_transaction_rollback_and_missing_state_version_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    database = StateDatabase.open(path)

    with pytest.raises(RuntimeError), database.transaction(write=True) as connection:
        connection.execute(
            "INSERT INTO hosts(host_id, host_key_fingerprint, remote_user, metadata_json, "
            "created_at, updated_at) VALUES ('rolled-back', 'fingerprint', 'alice', '{}', 0, 0)"
        )
        raise RuntimeError("rollback")
    with database.transaction() as connection:
        assert connection.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0

    connection = sqlite3.connect(path)
    try:
        connection.execute("DELETE FROM state_meta WHERE key = 'state_version'")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AstralError) as error:
        _ = database.state_version
    assert error.value.code is ErrorCode.STATE_CORRUPT


def test_history_and_open_failures_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    StateDatabase.open(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("UPDATE schema_migrations SET checksum = 'changed' WHERE version = 1")
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AstralError) as error:
        StateDatabase.open(path)
    assert error.value.code is ErrorCode.STATE_CORRUPT

    invalid = tmp_path / "invalid.sqlite3"
    invalid.write_bytes(b"not sqlite")
    invalid.chmod(0o600)
    with pytest.raises(AstralError) as error:
        StateDatabase.open(invalid)
    assert error.value.code is ErrorCode.STATE_OPEN

    with pytest.raises(AstralError) as error:
        StateDatabase.open(tmp_path)
    assert error.value.code is ErrorCode.STATE_OPEN


def test_destructive_backup_failure_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "state.sqlite3"
    StateDatabase.open(path)

    def remove_audit_table(connection: sqlite3.Connection) -> None:
        connection.execute("DROP TABLE audit_events")

    migration = Migration(
        2, "remove-audit", "DROP TABLE audit_events", remove_audit_table, destructive=True
    )
    monkeypatch.setattr(
        os, "replace", lambda source, destination: (_ for _ in ()).throw(OSError("full"))
    )
    with pytest.raises(AstralError) as error:
        StateDatabase.open(path, (INITIAL_MIGRATION, migration))
    assert error.value.code is ErrorCode.STATE_MIGRATION


def test_missing_history_state_version_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    StateDatabase.open(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("DELETE FROM state_meta WHERE key = 'state_version'")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AstralError) as error:
        StateDatabase.open(path)
    assert error.value.code is ErrorCode.STATE_CORRUPT


def test_state_version_history_disagreement_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "state.sqlite3"
    StateDatabase.open(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute("UPDATE state_meta SET value = '9' WHERE key = 'state_version'")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(AstralError) as error:
        StateDatabase.open(path)
    assert error.value.code is ErrorCode.STATE_CORRUPT
