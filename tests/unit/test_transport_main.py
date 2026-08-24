from __future__ import annotations

import sys

import pytest

from astral_project.transport import main as transport_main


def test_installed_transport_entrypoint_delegates(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, object] = {}

    def fake(*args: object, **kwargs: object) -> int:
        called["args"] = args
        called["kwargs"] = kwargs
        return 7

    monkeypatch.setattr(transport_main, "run_transport", fake)
    monkeypatch.setattr(sys, "argv", ["aspr-transport", "-s", "sftp"])
    with pytest.raises(SystemExit) as result:
        transport_main.main()
    assert result.value.code == 7
    assert called["args"] == (["-s", "sftp"],)
