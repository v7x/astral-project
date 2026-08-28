"""Packet 37 audit event and private storage tests."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

import astral_project.audit.events as audit_events
from astral_project.audit import AuditEvent, AuditEventError, AuditLog, PathMode, validate_chain
from astral_project.core.errors import AstralError
from astral_project.daemon.server import DaemonPaths, DaemonServer
from astral_project.state.sqlite import StateDatabase


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


def test_audit_log_rejects_zero_write(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = AuditLog(tmp_path / "audit.log")
    monkeypatch.setattr("astral_project.audit.events.os.write", lambda *_args: 0)
    with pytest.raises(OSError, match="no progress"):
        log.append("kind", "subject", "id", {})


def test_audit_log_rotation_and_limits(tmp_path: Path) -> None:
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


def test_audit_log_rotation_resets_oldest_predecessor(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "chain.log", retain=1)
    log.append("one", "subject", "1", {})
    log.append("two", "subject", "2", {})
    log.rotate()
    assert validate_chain(log.read()) == ()
    assert log.read()[0].previous_event_id is None


def test_audit_log_reset_handles_empty_and_malformed_storage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = AuditLog(tmp_path / "reset.log")
    log._reset_oldest_predecessor()
    generation = log.path.with_name("reset.log.1")
    generation.write_text("[]\n", encoding="utf-8")
    generation.chmod(0o600)
    log._reset_oldest_predecessor()
    first = AuditEvent.create("first", "subject", "1", {}, occurred_at=1)
    second = AuditEvent.create(
        "second", "subject", "2", {}, previous_event_id=first.event_id, occurred_at=2
    )
    generation.write_text(json.dumps(second.to_dict()) + "\n", encoding="utf-8")
    generation.chmod(0o600)
    log._reset_oldest_predecessor()
    assert (
        AuditEvent.from_dict(json.loads(generation.read_text().splitlines()[0])).previous_event_id
        is None
    )
    monkeypatch.setattr(
        audit_events, "_read_private_text", lambda *_args: (_ for _ in ()).throw(OSError("read"))
    )
    monkeypatch.setattr(log, "_read_paths", lambda: iter((generation,)))
    log._reset_oldest_predecessor()


def test_audit_log_skips_malformed_oldest_generation(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "generations.log", retain=2)
    oldest = log.path.with_name("generations.log.2")
    next_generation = log.path.with_name("generations.log.1")
    oldest.write_text("not-json\n", encoding="utf-8")
    next_generation.write_text(
        json.dumps(
            AuditEvent(
                "event", 1, "kind", "subject", "id", {}, previous_event_id="deleted"
            ).to_dict()
        )
        + "\n",
        encoding="utf-8",
    )
    oldest.chmod(0o600)
    next_generation.chmod(0o600)
    log._reset_oldest_predecessor()
    assert AuditEvent.from_dict(json.loads(next_generation.read_text())).previous_event_id is None


def test_audit_rotation_write_failure_closes_private_temp(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = AuditLog(tmp_path / "write-failure.log")
    generation = log.path.with_name("write-failure.log.1")
    event = AuditEvent("event", 1, "kind", "subject", "id", {}, previous_event_id="old")
    generation.write_text(json.dumps(event.to_dict()) + "\n", encoding="utf-8")
    generation.chmod(0o600)
    monkeypatch.setattr("astral_project.audit.events.os.write", lambda *_args: 0)
    with pytest.raises(OSError, match="no progress"):
        log._reset_oldest_predecessor()


def test_audit_payload_schema_rejects_untyped_and_non_path_lists() -> None:
    with pytest.raises(AuditEventError, match="lists"):
        audit_events._validate_payload(["/path"])
    with pytest.raises(AuditEventError, match="JSON-safe"):
        audit_events._validate_payload({"revision": object()})
    with pytest.raises(AuditEventError, match="strings"):
        AuditEvent.create("kind", "subject", "id", {"paths": [1]})


def test_audit_log_auto_rotation_and_existing_generations(tmp_path: Path) -> None:
    automatic = AuditLog(tmp_path / "automatic.log", max_bytes=1, retain=1)
    automatic.append("one", "subject", "1", {})
    automatic.append("two", "subject", "2", {})
    assert (tmp_path / "automatic.log.1").exists()

    log = AuditLog(tmp_path / "generations.log", retain=2)
    log.append("current", "subject", "0", {})
    for index in (0, 1, 2):
        generation = tmp_path / f"generations.log.{index}"
        generation.write_text("old", encoding="utf-8")
        generation.chmod(0o600)
    log.rotate()
    assert (tmp_path / "generations.log.1").exists()
    assert (tmp_path / "generations.log.2").exists()
    assert [event.kind for event in log.read()] == ["current"]


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


def test_state_database_audit_rotation_retains_chain(tmp_path: Path) -> None:
    database = StateDatabase.open(tmp_path / "state.sqlite3")
    database.record_audit("one", "subject", "1", {}, occurred_at=1)
    database.record_audit("two", "subject", "2", {}, occurred_at=2)
    database.rotate_audit(retain=2)
    database.record_audit("three", "subject", "3", {}, occurred_at=3)
    database.rotate_audit(retain=2)
    events = database.list_audit_events()
    assert [event.kind for event in events] == ["two", "three"]
    assert events[0].previous_event_id is None
    assert database.audit_chain_errors() == ()
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
    assert combined.list_audit_events()[-1].previous_event_id is None


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
