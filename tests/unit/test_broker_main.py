"""Fixed broker executable orchestration tests."""

from __future__ import annotations

import runpy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from astral_project.broker import main as broker_main


def test_module_entrypoint_calls_main(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.broker.main.sys.argv", ["aspr-broker", "--unsafe"])
    with pytest.raises(SystemExit) as error:
        runpy.run_module("astral_project.broker.main", run_name="__main__")
    assert error.value.code == 64


def test_main_rejects_caller_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.broker.main.sys.argv", ["aspr-broker", "--unsafe"])
    with pytest.raises(SystemExit) as error:
        broker_main.main()
    assert error.value.code == 64


def test_main_builds_server_and_closes_on_shutdown(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "astral_project.broker.main.sys.argv", ["aspr-broker", "--socket-activation"]
    )
    config = SimpleNamespace(
        authority_path=Path("/authority"),
        runtime_root=Path("/runtime"),
        runtime_manifest_digest="a" * 64,
        mount_worker=Path("/mount"),
        socket_path=Path("/socket"),
    )
    authority = SimpleNamespace(server_ceiling=Mock())
    server = Mock()
    server.serve_once.side_effect = KeyboardInterrupt
    monkeypatch.setattr(broker_main, "load_broker_install_config", lambda: config)
    monkeypatch.setattr(broker_main, "load_broker_authority", lambda _path: authority)
    monkeypatch.setattr(broker_main, "load_active_runtime_closure", lambda *_args: Mock())
    monkeypatch.setattr(broker_main, "ActiveSessionRegistry", Mock)
    monkeypatch.setattr(broker_main, "BrokerSessionExecutor", Mock)
    monkeypatch.setattr(broker_main, "MappingWorker", Mock)
    monkeypatch.setattr(broker_main, "BrokerServer", Mock(return_value=server))
    monkeypatch.setattr(broker_main, "take_systemd_listener", lambda: 3)

    with pytest.raises(KeyboardInterrupt):
        broker_main.main()

    server.start.assert_called_once_with(inherited_listener=3)
    server.close.assert_called_once_with()
