from __future__ import annotations

import sys

import pytest

import astral_project.server.entry as entry


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
