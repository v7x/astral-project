from __future__ import annotations

import sys
from pathlib import Path

import pytest

import astral_project.server.entry as entry
from astral_project.audit import AuditLog


def test_standalone_entry_dispatches_audit_export(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    observed: dict[str, object] = {}

    def fake(key: str, **kwargs: object) -> int:
        observed["key"] = key
        observed["kwargs"] = kwargs
        return 0

    monkeypatch.setattr(entry, "run_audit_export_entry", fake)
    monkeypatch.setattr(
        entry,
        "_default_audit_log",
        lambda _environment: AuditLog(tmp_path / "audit.log"),
    )
    monkeypatch.setenv("SSH_ORIGINAL_COMMAND", entry.SSH_ORIGINAL_AUDIT_COMMAND)
    monkeypatch.setattr(sys, "argv", ["aspr-server", "--transport-key", "transport-gate"])
    with pytest.raises(SystemExit) as result:
        entry.main()
    assert result.value.code == 0
    assert observed["key"] == "transport-gate"


def test_standalone_entry_accepts_enrollment_command_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake(key: str, **kwargs: object) -> int:
        observed["key"] = key
        observed["kwargs"] = kwargs
        return 0

    monkeypatch.setattr(entry, "run_ssh_entry", fake)
    monkeypatch.setattr(
        sys, "argv", ["aspr-server", "server", "ssh-entry", "--transport-key", "transport-gate"]
    )
    with pytest.raises(SystemExit) as result:
        entry.main()
    assert result.value.code == 0
    assert observed["key"] == "transport-gate"
