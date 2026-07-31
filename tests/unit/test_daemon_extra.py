from __future__ import annotations

import socket
import threading
from io import StringIO
from pathlib import Path

import pytest

from astral_project import cli
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.daemon.client import DaemonClient
from astral_project.daemon.protocol import Response, encode, parse_request
from astral_project.daemon.server import DaemonLock, DaemonPaths, DaemonServer


def _error(code: ErrorCode) -> AstralError:
    return AstralError(code, "bad", "rejected", "unsafe", "fix")


def test_daemon_paths_from_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "runtime"))
    paths = cli._daemon_paths()
    assert paths.runtime == tmp_path / "runtime" / "astral-project"
    assert paths.state == tmp_path / ".local" / "state" / "astral-project" / "state.sqlite3"


def test_cli_doctor_and_daemon_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    paths = DaemonPaths(tmp_path / "runtime", tmp_path / "state.sqlite3")
    monkeypatch.setattr(cli, "_daemon_paths", lambda: paths)
    monkeypatch.setattr(DaemonClient, "request", lambda self, **kwargs: {"alive": True})
    stdout = StringIO()
    assert cli.run(["doctor"], stdout=stdout, stderr=StringIO()) == 0
    assert stdout.getvalue() == '{"alive":true}\n'

    monkeypatch.setattr(
        DaemonClient,
        "request",
        lambda self, **kwargs: (_ for _ in ()).throw(_error(ErrorCode.DAEMON_UNAVAILABLE)),
    )
    assert cli.run(["doctor"], stdout=StringIO(), stderr=StringIO()) == 70

    class FakeDaemon:
        def __init__(self, value: DaemonPaths) -> None:
            assert value is paths

        def start(self) -> None:
            pass

        def serve_forever(self) -> None:
            raise _error(ErrorCode.DAEMON_STARTUP)

        def close(self) -> None:
            pass

    monkeypatch.setattr(cli, "DaemonServer", FakeDaemon)
    assert cli.run(["__internal", "daemon"], stdout=StringIO(), stderr=StringIO()) == 70


def test_client_rejects_unavailable_and_bad_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = DaemonClient(tmp_path / "missing.sock")
    with pytest.raises(AstralError) as error:
        client.request(request_id="a", cancellation_id="b", operation="ping")
    assert error.value.code is ErrorCode.DAEMON_UNAVAILABLE

    path = tmp_path / "daemon.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen()
    for response in (
        {"kind": "response", "request_id": "wrong", "ok": True, "result": {}},
        {"kind": "response", "request_id": "a", "ok": False, "result": {}},
    ):
        thread = threading.Thread(
            target=lambda response=response: listener.accept()[0].sendall(encode(response))
        )
        thread.start()
        with pytest.raises(AstralError):
            DaemonClient(path).request(request_id="a", cancellation_id="b", operation="ping")
        thread.join(timeout=1)
    listener.close()


def test_protocol_identifier_and_server_lock_failures(tmp_path: Path) -> None:
    for payload in (
        {
            "cancellation_id": "b",
            "kind": "request",
            "operation": "ping",
            "request_id": "é",
            "version": 1,
        },
        {
            "cancellation_id": "b",
            "kind": "request",
            "operation": "ping",
            "request_id": 1,
            "version": 1,
        },
        {
            "cancellation_id": "b",
            "kind": "request",
            "operation": "bad",
            "request_id": "a",
            "version": 1,
        },
    ):
        with pytest.raises(AstralError):
            parse_request(payload)
    with pytest.raises(AstralError):
        encode({"data": "x" * 70000})
    assert Response("a", "b", True, {}).request_id == "a"

    lock = DaemonLock(tmp_path / "lock")
    lock.acquire()
    contender = DaemonLock(tmp_path / "lock")
    with pytest.raises(AstralError):
        contender.acquire()
    lock.close()


def test_server_state_and_socket_failure_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = DaemonPaths(tmp_path / "runtime", tmp_path / "state.sqlite3")
    server = DaemonServer(paths)
    with pytest.raises(AstralError):
        server.serve_once()
    paths.runtime.mkdir(mode=0o700)
    paths.socket.write_text("not socket")
    paths.socket.chmod(0o600)
    with pytest.raises(AstralError):
        server.start()
    server.close()

    clean = DaemonServer(DaemonPaths(tmp_path / "second", tmp_path / "second.sqlite3"))
    with pytest.raises(AstralError):
        clean._response("status")
    assert clean._response("cancel") == {"cancelled": True}
    with pytest.raises(AstralError):
        clean._response("bad")
    monkeypatch.setattr(clean, "serve_once", lambda: (_ for _ in ()).throw(RuntimeError("stop")))
    with pytest.raises(RuntimeError):
        clean.serve_forever()

    socket_path = tmp_path / "daemon.sock"
    active = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    active.bind(str(socket_path))
    socket_path.chmod(0o600)
    active.listen()
    with pytest.raises(AstralError):
        DaemonServer(DaemonPaths(tmp_path, tmp_path / "third.sqlite3"))._repair_stale_socket()
    active.close()
