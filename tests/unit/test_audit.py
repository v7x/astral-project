"""Packet 37 audit event and private storage tests."""

from __future__ import annotations

import json
import multiprocessing
import sqlite3
import stat
from pathlib import Path
from typing import Protocol

import pytest

import astral_project.audit.events as audit_events
from astral_project.audit import (
    AUDIT_MAX_EVENT_BYTES,
    AuditEvent,
    AuditEventError,
    AuditLog,
    AuditRetentionBoundary,
    PathMode,
    validate_chain,
)
from astral_project.core.errors import AstralError
from astral_project.daemon.server import DaemonPaths, DaemonServer
from astral_project.state.sqlite import StateDatabase


class _BarrierLike(Protocol):
    def wait(self) -> object: ...


def _concurrent_append(
    path: str, barrier: _BarrierLike, index: int, retention: int = 10_000
) -> None:
    log = AuditLog(Path(path), retention=retention)
    barrier.wait()
    log.append("concurrent", "worker", str(index), {}, occurred_at=index)


def test_event_round_trip_and_path_export_modes() -> None:
    event = AuditEvent.create(
        "session.started",
        "session",
        "s1",
        {"path": "/secret/home", "root": "/runtime", "revision": 2},
        occurred_at=4,
    )
    restored = AuditEvent.from_dict(event.to_dict())
    assert restored == event
    assert restored.to_dict(path_mode=PathMode.REDACT)["payload"] == {
        "path": "<redacted>",
        "root": "<redacted>",
        "revision": 2,
    }
    hashed = restored.to_dict(path_mode=PathMode.HASH)
    hashed_payload = hashed["payload"]
    assert isinstance(hashed_payload, dict)
    assert str(hashed_payload["path"]).startswith("sha256:")
    restored_hashed = AuditEvent.from_dict(hashed)
    assert hashed_payload["path"] == restored_hashed.payload["path"]


def test_path_bearing_schema_fields_are_redacted_and_hashed() -> None:
    event = AuditEvent.create(
        "mediation.requested",
        "session",
        "s1",
        {
            "path_component": ".private",
            "remote_home": "/home/alice/private",
            "device": "/dev/null",
            "destination": "/srv/secret-name",
        },
    )

    redacted = event.to_dict(path_mode=PathMode.REDACT)["payload"]
    assert redacted == {
        "path_component": "<redacted>",
        "remote_home": "<redacted>",
        "device": "<redacted>",
        "destination": "<redacted>",
    }
    hashed = event.to_dict(path_mode=PathMode.HASH)["payload"]
    assert isinstance(hashed, dict)
    assert all(str(value).startswith("sha256:") for value in hashed.values())
    assert hashed == event.to_dict(path_mode=PathMode.HASH)["payload"]


def test_event_rejects_bad_payload_shape_and_previous_type() -> None:
    event = AuditEvent.create("kind", "subject", "id", {})
    raw = event.to_dict()
    raw["payload"] = []
    with pytest.raises(AuditEventError, match="payload"):
        AuditEvent.from_dict(raw)
    raw = event.to_dict()
    raw["previous_event_id"] = 3
    with pytest.raises(AuditEventError, match="previous"):
        AuditEvent.from_dict(raw)


def test_event_rejects_bad_envelope_and_sensitive_payload() -> None:
    with pytest.raises(AuditEventError, match="fields"):
        AuditEvent.from_dict({})
    event = AuditEvent.create("kind", "subject", "id", {})
    raw = event.to_dict()
    raw["payload"] = {"private_key": "x"}
    with pytest.raises(AuditEventError, match="secret"):
        AuditEvent.from_dict(raw)
    with pytest.raises(AuditEventError, match="arguments"):
        AuditEvent.create("kind", "subject", "id", {"command": ["tool", "secret"]})
    with pytest.raises(AuditEventError, match="timestamp"):
        AuditEvent("e", -1, "kind", "subject", "id", {})
    with pytest.raises(AuditEventError, match="schema"):
        AuditEvent("e", 0, "kind", "subject", "id", {}, schema_version=2)
    with pytest.raises(AuditEventError, match="payload"):
        AuditEvent.create("kind", "subject", "id", {"bad": object()})


def test_audit_log_append_read_diagnostics_and_chain(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.log")
    first = log.append("one", "session", "s1", {"path": "/one"}, occurred_at=1)
    second = log.append("two", "session", "s1", {}, occurred_at=2)
    assert second.previous_event_id == first.event_id
    assert log.read() == (first, second)
    assert log.diagnostics() == ()
    with log.path.open("a", encoding="utf-8") as stream:
        stream.write("not-json\n")
        stream.write(json.dumps({"wrong": True}) + "\n")
        stream.write(json.dumps([]) + "\n")
    assert log.read() == (first, second)
    assert log.diagnostics() == (
        "malformed audit row skipped",
        "malformed audit row skipped",
        "malformed audit row skipped",
    )
    assert validate_chain(log.read()) == ()
    assert "<redacted>" in log.export()
    assert "sha256:" in log.export(path_mode=PathMode.HASH)


def test_audit_event_size_limit_applies_to_both_stores(tmp_path: Path) -> None:
    huge = {"result": "x" * (64 * 1024)}
    with pytest.raises(AuditEventError, match="size limit"):
        AuditLog(tmp_path / "huge.log").append("kind", "subject", "id", huge)
    database = StateDatabase.open(tmp_path / "huge.sqlite3")
    with pytest.raises(AuditEventError, match="size limit"):
        database.record_audit("kind", "subject", "id", huge)


def test_audit_log_rejects_zero_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = AuditLog(tmp_path / "audit.log")
    monkeypatch.setattr("astral_project.audit.events.os.write", lambda *_args: 0)
    with pytest.raises(OSError, match="no progress"):
        log.append("kind", "subject", "id", {})


def test_audit_log_rotation_and_limits(tmp_path: Path) -> None:
    AuditLog(tmp_path / "default-rotate.log").rotate()
    with pytest.raises(ValueError):
        AuditLog(tmp_path / "audit.log", max_bytes=0)
    with pytest.raises(ValueError):
        AuditLog(tmp_path / "audit.log", retain=0)
    log = AuditLog(tmp_path / "audit.log", max_bytes=1, retain=1)
    log.append("one", "x", "1", {})
    log.rotate()
    log.rotate()
    log.append("two", "x", "2", {})
    assert (tmp_path / "audit.log.1").exists()
    assert [event.kind for event in log.read()] == ["one", "two"]
    assert validate_chain(log.read()) == ()
    assert stat.S_IMODE((tmp_path / "audit.log.1").stat().st_mode) == 0o600


def test_audit_payload_schema_rejects_untyped_and_non_path_lists() -> None:
    with pytest.raises(AuditEventError, match="lists"):
        audit_events._validate_payload(["/path"])
    with pytest.raises(AuditEventError, match="JSON-safe"):
        audit_events._validate_payload({"revision": object()})
    with pytest.raises(AuditEventError, match="strings"):
        AuditEvent.create("kind", "subject", "id", {"paths": [1]})


def test_audit_log_automatic_count_retention_is_immutable(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "retained.log", retention=2)
    log.append("one", "subject", "1", {}, occurred_at=1)
    log.append("two", "subject", "2", {}, occurred_at=2)
    second_line = log.path.read_text(encoding="utf-8").splitlines(keepends=True)[1]
    log.append("three", "subject", "3", {}, occurred_at=3)
    retained_lines = log.path.read_text(encoding="utf-8").splitlines(keepends=True)
    assert second_line in retained_lines
    assert [event.kind for event in log.read()] == ["two", "three"]
    assert log.chain_errors() == ()
    assert log.boundary_path.stat().st_mode & 0o777 == 0o600
    log.boundary_path.write_text("corrupt\\n", encoding="utf-8")
    assert log.chain_errors() == ("retention-boundary",)


def test_audit_log_combines_byte_and_count_retention(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "combined.log", max_bytes=1, retain=5, retention=2)
    for number in range(6):
        log.append("event", "subject", str(number), {}, occurred_at=number)
    assert [event.subject_id for event in log.read()] == ["4", "5"]
    assert log.chain_errors() == ()
    assert log.boundary_path.exists()


def test_audit_log_auto_rotation_and_existing_generations(tmp_path: Path) -> None:
    automatic = AuditLog(tmp_path / "automatic.log", max_bytes=1, retain=1)
    automatic.append("one", "subject", "1", {})
    automatic.append("two", "subject", "2", {})
    assert (tmp_path / "automatic.log.1").exists()
    assert automatic.chain_errors() == ()
    assert not (tmp_path / "automatic.log.boundary").exists()
    for index in range(3):
        automatic.append("more", "subject", str(index), {})
    assert automatic.chain_errors() == ()
    assert len((tmp_path / "automatic.log.boundary").read_text(encoding="utf-8").splitlines()) == 3
    boundary_log = AuditLog(tmp_path / "boundary.log")
    boundary_log._record_pruning_boundary_unlocked((), ())
    boundary = AuditRetentionBoundary.create("pruned", "first")
    boundary_log._append_boundary_unlocked(boundary)
    boundary_log._append_boundary_unlocked(boundary)
    with pytest.raises(AuditEventError, match="not linear"):
        boundary_log._append_boundary_unlocked(AuditRetentionBoundary.create("wrong", "next"))
    boundary_log.boundary_path.write_text("", encoding="utf-8")
    with pytest.raises(AuditEventError, match="invalid"):
        boundary_log._read_boundaries_unlocked()
    boundary_log.boundary_path.unlink()
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr("astral_project.audit.events.os.write", lambda *_args: 0)
    try:
        with pytest.raises(OSError, match="no progress"):
            boundary_log._append_boundary_unlocked(boundary)
    finally:
        monkeypatch.undo()

    log = AuditLog(tmp_path / "generations.log", max_bytes=1, retain=2)
    log.append("current", "subject", "0", {})
    for index in (0, 1, 2):
        generation = tmp_path / f"generations.log.{index}"
        generation.write_text("old", encoding="utf-8")
        generation.chmod(0o600)
    log.rotate()
    assert (tmp_path / "generations.log.1").exists()
    assert (tmp_path / "generations.log.2").exists()
    assert [event.kind for event in log.read()] == ["current"]


def test_audit_log_concurrent_append_is_linear(tmp_path: Path) -> None:
    path = tmp_path / "concurrent.log"
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(8)
    workers = [
        context.Process(target=_concurrent_append, args=(str(path), barrier, i)) for i in range(8)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert worker.exitcode == 0
    log = AuditLog(path)
    events = log.read()
    assert len(events) == 8
    assert len({event.event_id for event in events}) == 8
    assert validate_chain(events) == ()
    assert log.lock_path.exists()
    assert stat.S_IMODE(log.lock_path.stat().st_mode) == 0o600


def test_retention_boundary_validation_is_strict() -> None:
    boundary = AuditRetentionBoundary.create("pruned", "first")
    with pytest.raises(AuditEventError):
        AuditRetentionBoundary.from_dict({})
    with pytest.raises(AuditEventError):
        AuditRetentionBoundary.from_dict({**boundary.to_dict(), "digest": "tampered"})
    with pytest.raises(AuditEventError):
        AuditRetentionBoundary.from_dict({**boundary.to_dict(), "digest": 1})
    event = AuditEvent("other", 1, "kind", "subject", "id", {})
    assert validate_chain((event,), boundary=boundary) == ("retention-boundary",)
    other = AuditRetentionBoundary.create("different", "next")
    assert validate_chain((event,), boundaries=(boundary, other)) == ("retention-boundary",)


def test_audit_log_atomic_retention_failures_and_malformed_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert AuditLog(tmp_path / "no-boundary.log").chain_errors() == ()
    log = AuditLog(tmp_path / "retention-errors.log", retention=1)
    log.path.write_text("[]\nnot-json\n", encoding="utf-8")
    log.path.chmod(0o600)
    original_read_private_text = audit_events._read_private_text
    monkeypatch.setattr(
        audit_events,
        "_read_private_text",
        lambda *_args: (_ for _ in ()).throw(OSError("read")),
    )
    log._apply_retention_unlocked()
    monkeypatch.setattr(audit_events, "_read_private_text", original_read_private_text)
    log._apply_retention_unlocked()
    log.boundary_path.write_text("[]\n", encoding="utf-8")
    log.boundary_path.chmod(0o600)
    assert log.chain_errors() == ("retention-boundary",)
    log.boundary_path.write_text("{}\n\n", encoding="utf-8")
    assert log.chain_errors() == ("retention-boundary",)
    monkeypatch.setattr("astral_project.audit.events.os.write", lambda *_args: 0)
    with pytest.raises(OSError, match="atomic write"):
        log._atomic_replace(log.path, b"x")


def test_audit_log_concurrent_append_with_retention_is_bounded(tmp_path: Path) -> None:
    path = tmp_path / "concurrent-retained.log"
    context = multiprocessing.get_context("fork")
    barrier = context.Barrier(4)
    workers = [
        context.Process(target=_concurrent_append, args=(str(path), barrier, i, 2))
        for i in range(4)
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
        assert worker.exitcode == 0
    log = AuditLog(path, retention=2)
    assert len(log.read()) == 2
    assert log.chain_errors() == ()


def test_failure_recorder_appends_after_read_only_wall(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "failure.log")
    first = log.append("probe.started", "process", "probe", {})
    with log.prepare_failure_recorder() as recorder:
        failure = recorder.append(
            "hardening.failure", "process", "remote-audit", {"error_code": "probe"}
        )
    assert failure.previous_event_id == first.event_id
    assert [event.kind for event in log.read()] == ["probe.started", "hardening.failure"]


def test_failure_recorder_rejects_closed_oversized_and_stalled_writes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    log = AuditLog(tmp_path / "failure.log")
    log.append("probe.started", "process", "probe", {})
    recorder = log.prepare_failure_recorder()
    recorder.close()
    recorder.close()
    with pytest.raises(OSError, match="closed"):
        recorder.append("hardening.failure", "process", "remote-audit", {"error_code": "probe"})

    recorder = log.prepare_failure_recorder()
    with pytest.raises(AuditEventError, match="serialized size"):
        recorder.append(
            "hardening.failure",
            "process",
            "remote-audit",
            {"result": "x" * AUDIT_MAX_EVENT_BYTES},
        )
    monkeypatch.setattr("astral_project.audit.events.os.write", lambda *_args: 0)
    with pytest.raises(OSError, match="no progress"):
        recorder.append("hardening.failure", "process", "remote-audit", {"error_code": "probe"})
    recorder.close()


def test_failure_recorder_rejects_symlinked_log(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "failure.log")
    log.append("probe.started", "process", "probe", {})
    replacement = tmp_path / "replacement.log"
    replacement.write_text("", encoding="utf-8")
    log.path.unlink()
    log.path.symlink_to(replacement)
    with pytest.raises(OSError):
        log.prepare_failure_recorder()


def test_audit_log_rejects_symlink_lock(tmp_path: Path) -> None:
    path = tmp_path / "locked.log"
    path.parent.mkdir(mode=0o700, exist_ok=True)
    path.with_name("locked.log.lock").symlink_to(path)
    with pytest.raises(PermissionError):
        AuditLog(path)


def test_audit_log_read_handles_storage_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.log"
    path.write_text("", encoding="utf-8")
    path.chmod(0o600)
    monkeypatch.setattr(
        Path, "open", lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("read"))
    )
    log = AuditLog(path)
    assert log.read() == ()
    assert log.diagnostics() == ()


def test_audit_log_rejects_unsafe_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "audit.log"
    path.write_text("", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(PermissionError):
        AuditLog(path)


def test_payload_lists_and_invalid_keys_are_rejected() -> None:
    with pytest.raises(AuditEventError, match="payload key"):
        AuditEvent.create("kind", "subject", "id", {"bad\x00key": "x"})
    with pytest.raises(AuditEventError, match="schema"):
        AuditEvent.create("kind", "subject", "id", {"items": [object()]})
    event = AuditEvent.create("kind", "subject", "id", {"paths": ["/one", "/two"], "revision": 1})
    assert event.to_dict(path_mode=PathMode.REDACT)["payload"] == {
        "paths": ["<redacted>", "<redacted>"],
        "revision": 1,
    }
    with pytest.raises(AuditEventError, match="secret-bearing audit value"):
        AuditEvent.create(
            "kind", "subject", "id", {"reason": "-----BEGIN PRIVATE KEY-----\\nsecret"}
        )
    with pytest.raises(AuditEventError, match="schema"):
        AuditEvent.create("kind", "subject", "id", {"output": "file contents"})
    with pytest.raises(AuditEventError, match="reason"):
        AuditEvent.create("kind", "subject", "id", {"reason": "untrusted file contents"})
    for value in ("token: abc", "password = abc"):
        with pytest.raises(AuditEventError, match="secret-bearing audit value"):
            AuditEvent.create("kind", "subject", "id", {"message": value})


def test_chain_detects_duplicate_and_forward_reference() -> None:
    first = AuditEvent("same", 1, "a", "s", "1", {})
    forward = AuditEvent("later", 2, "b", "s", "2", {}, previous_event_id="missing")
    duplicate = AuditEvent("same", 3, "c", "s", "3", {}, previous_event_id="same")
    assert validate_chain((first, forward, duplicate)) == ("later", "same")
    fork = AuditEvent("fork", 4, "d", "s", "4", {}, previous_event_id="same")
    assert validate_chain(
        (first, AuditEvent("a", 2, "b", "s", "2", {}, previous_event_id="same"), fork)
    ) == ("fork",)


def test_state_database_audit_api_reads_legacy_and_new_rows(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    with database.transaction(write=True) as connection:
        connection.execute(
            "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
            ("legacy", 1, "legacy.kind", "subject", "id", '{"path":"/old"}'),
        )
        connection.execute(
            "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
            ("broken", 2, "broken", "subject", "id", "not-json"),
        )
        connection.execute(
            "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
            ("list", 3, "list", "subject", "id", "[]"),
        )
        connection.execute(
            "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
            (
                "envelope-list",
                4,
                "envelope",
                "subject",
                "id",
                '{"payload":[],"previous_event_id":null,"schema_version":1}',
            ),
        )
    events = database.list_audit_events()
    assert len(events) == 1
    assert events[0].event_id == "legacy"
    assert "<redacted>" in database.export_audit()
    assert database.audit_chain_errors() == ()
    database.record_audit("after-malformed", "subject", "new", {}, occurred_at=5)
    assert database.list_audit_events()[-1].previous_event_id == "legacy"


def test_state_database_host_transport_rejects_missing_and_bad_records(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="retention"):
        StateDatabase.open(tmp_path / "invalid.sqlite3", retention_limit=0)
    database = StateDatabase.open(tmp_path / "host.sqlite3")
    with pytest.raises(AstralError, match="host"):
        database.host_transport("missing")
    with database.transaction(write=True) as connection:
        connection.execute(
            "INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?)",
            ("bad", "fp", "user", "[]", 1, 1),
        )
    with pytest.raises(AstralError, match="metadata"):
        database.host_transport("bad")
    with database.transaction(write=True) as connection:
        connection.execute(
            "UPDATE hosts SET metadata_json = ? WHERE host_id = ?", ('{"address":"x"}', "bad")
        )
    assert database.host_transport("bad")[0] == "user"


def test_state_database_automatic_retention_is_immutable(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "retained.sqlite3", retention_limit=2)
    database.record_audit("one", "subject", "1", {}, occurred_at=1)
    database.record_audit("two", "subject", "2", {}, occurred_at=2)
    second = database.list_audit_events()[1]
    with database.transaction() as connection:
        original = connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_id = ?", (second.event_id,)
        ).fetchone()[0]
    database.record_audit("three", "subject", "3", {}, occurred_at=3)
    assert [event.kind for event in database.list_audit_events()] == ["two", "three"]
    assert database.audit_chain_errors() == ()
    with database.transaction() as connection:
        retained = connection.execute(
            "SELECT payload_json FROM audit_events WHERE event_id = ?", (second.event_id,)
        ).fetchone()[0]
    assert retained == original
    with database.transaction(write=True) as connection:
        connection.execute("DELETE FROM audit_retention_boundary WHERE id = 1")
    assert database.audit_chain_errors() == (second.event_id,)


def test_state_database_migrates_single_boundary_to_segments(tmp_path: Path) -> None:
    path = tmp_path / "legacy-boundary.sqlite3"
    StateDatabase.open(path)
    boundary = AuditRetentionBoundary.create("pruned", "first")
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE audit_retention_boundary")
        connection.execute(
            """CREATE TABLE audit_retention_boundary (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_version INTEGER NOT NULL,
                pruned_through_event_id TEXT NOT NULL,
                first_retained_event_id TEXT NOT NULL,
                digest TEXT NOT NULL
            )"""
        )
        connection.execute(
            "INSERT INTO audit_retention_boundary VALUES (1, ?, ?, ?, ?)",
            (
                boundary.schema_version,
                boundary.pruned_through_event_id,
                boundary.first_retained_event_id,
                boundary.digest,
            ),
        )
    migrated = StateDatabase.open(path)
    with migrated.transaction() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM audit_retention_boundary").fetchone()[0] == 1
        )


def test_state_database_audit_rotation_retains_chain(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    database.record_audit("one", "subject", "1", {}, occurred_at=1)
    database.record_audit("two", "subject", "2", {}, occurred_at=2)
    database.rotate_audit(retain=2)
    database.record_audit("three", "subject", "3", {}, occurred_at=3)
    database.rotate_audit(retain=2)
    events = database.list_audit_events()
    assert [event.kind for event in events] == ["two", "three"]
    assert events[0].previous_event_id is not None
    assert database.audit_chain_errors() == ()
    with database.transaction() as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM audit_retention_boundary").fetchone()[0] == 1
        )
    with database.transaction(write=True) as connection:
        connection.execute("UPDATE audit_retention_boundary SET digest = 'tampered' WHERE id = 1")
    assert database.audit_chain_errors() == ("retention-boundary",)
    with pytest.raises(ValueError):
        database.rotate_audit(retain=0)
    legacy = StateDatabase.open(tmp_path / "legacy.sqlite3")
    with legacy.transaction(write=True) as connection:
        for number in range(4):
            payload = "not-json" if number == 1 else "{}"
            connection.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
                (f"legacy-{number}", number, "legacy", "subject", str(number), payload),
            )
    legacy.rotate_audit(retain=3)
    assert legacy.audit_chain_errors() == ()
    combined = StateDatabase.open(tmp_path / "combined.sqlite3")
    with combined.transaction(write=True) as connection:
        connection.executemany(
            "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
            (
                (
                    "old",
                    1,
                    "kind",
                    "subject",
                    "old",
                    '{"payload":{},"previous_event_id":null,"schema_version":1}',
                ),
                ("list", 2, "kind", "subject", "list", "[]"),
                ("bad", 3, "kind", "subject", "bad", "not-json"),
                (
                    "new",
                    4,
                    "kind",
                    "subject",
                    "new",
                    '{"payload":{},"previous_event_id":"old","schema_version":1}',
                ),
            ),
        )
    combined.rotate_audit(retain=3)
    assert combined.audit_chain_errors() == ()
    assert combined.list_audit_events()[-1].previous_event_id == "old"


def test_state_database_rejects_secret_audit_payload(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    with pytest.raises(AuditEventError), database.transaction(write=True) as connection:
        database._audit(connection, "bad", "subject", "id", {"token": "x"}, 1)


def test_daemon_audit_operations_require_started_database(tmp_path: Path) -> None:
    server = DaemonServer(DaemonPaths(tmp_path / "runtime", tmp_path / "state.sqlite3"))
    for operation, payload in (
        ("audit.list", None),
        ("audit.show", {}),
        ("audit.export", {}),
    ):
        with pytest.raises(AstralError, match=r"state database|payload"):
            server._response(operation, payload)


def test_daemon_audit_operations_use_redaction_and_hashing(tmp_path: Path) -> None:
    server = DaemonServer(DaemonPaths(tmp_path / "runtime", tmp_path / "state.sqlite3"))
    server.start()
    try:
        assert server._database is not None
        with server._database.transaction(write=True) as connection:
            connection.execute(
                "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
                ("event-1", 1, "kind", "subject", "id", '{"path":"/secret"}'),
            )
        listed = server._response("audit.list")
        assert listed["chain_errors"] == []
        events = listed["events"]
        assert isinstance(events, list)
        event = next(item for item in events if item["event_id"] == "event-1")
        assert event["payload"] == {"path": "<redacted>"}
        assert server._response("audit.show", {"event_id": "event-1"})["payload"] == {
            "path": "<redacted>"
        }
        exported = server._response("audit.export", {"path_mode": "hash"})
        assert "sha256:" in str(exported["export"])
        with pytest.raises(AstralError, match="path mode"):
            server._response("audit.export", {"path_mode": "bad"})
        with pytest.raises(AstralError, match="not found"):
            server._response("audit.show", {"event_id": "missing"})
    finally:
        server.close()


def test_audit_log_missing_path_and_invalid_previous(tmp_path: Path) -> None:
    event = AuditEvent("e", 0, "kind", "subject", "id", {}, previous_event_id="previous")
    assert event.previous_event_id == "previous"
    assert AuditLog(tmp_path / "missing.log").read() == ()
    with pytest.raises(AuditEventError, match="previous"):
        AuditEvent("e", 0, "kind", "subject", "id", {}, previous_event_id="")
    with pytest.raises(AuditEventError, match="invalid audit event_id"):
        AuditEvent("", 0, "kind", "subject", "id", {})
    with pytest.raises(AuditEventError, match="unsupported audit schema"):
        AuditEvent.from_dict(
            {
                "event_id": "e",
                "occurred_at": 0,
                "kind": "kind",
                "subject_type": "s",
                "subject_id": "id",
                "payload": {},
                "previous_event_id": None,
                "schema_version": True,
            }
        )
