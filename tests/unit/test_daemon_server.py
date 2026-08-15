from __future__ import annotations

import json
import socket
import threading
from pathlib import Path

import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.daemon.client import DaemonClient
from astral_project.daemon.protocol import encode, receive
from astral_project.daemon.server import DaemonPaths, DaemonServer


def _paths(tmp_path: Path) -> DaemonPaths:
    return DaemonPaths(runtime=tmp_path / "runtime", state=tmp_path / "state" / "state.sqlite3")


def _serve(server: DaemonServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_once)
    thread.start()
    return thread


def test_same_uid_ping_status_restart_and_database_persistence(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    server = DaemonServer(paths)
    server.start()
    try:
        thread = _serve(server)
        assert DaemonClient(paths.socket).request(
            request_id="ping-1", cancellation_id="cancel-1", operation="ping"
        ) == {"alive": True}
        thread.join(timeout=1)
        assert not thread.is_alive()
    finally:
        server.close()

    restarted = DaemonServer(paths)
    restarted.start()
    try:
        thread = _serve(restarted)
        assert DaemonClient(paths.socket).request(
            request_id="status-1", cancellation_id="cancel-2", operation="status"
        ) == {"alive": True, "state_version": 1}
        thread.join(timeout=1)
        assert not thread.is_alive()
    finally:
        restarted.close()


def test_stale_socket_repaired_and_two_starts_do_not_race(tmp_path: Path) -> None:
    paths = _paths(tmp_path)
    paths.runtime.mkdir(mode=0o700)
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(paths.socket))
    paths.socket.chmod(0o600)
    stale.close()

    server = DaemonServer(paths)
    server.start()
    try:
        assert paths.socket.exists()
        contender = DaemonServer(paths)
        with pytest.raises(AstralError) as error:
            contender.start()
        assert error.value.code is ErrorCode.DAEMON_STARTUP
    finally:
        server.close()


def test_daemon_translates_protocol_error_to_error_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = DaemonServer(_paths(tmp_path))

    class Connection:
        def __init__(self) -> None:
            self.payload: bytes | None = None

        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def sendall(self, payload: bytes) -> None:
            self.payload = payload

    connection = Connection()
    server._listener = type("Listener", (), {"accept": lambda _self: (connection, None)})()
    monkeypatch.setattr(
        "astral_project.daemon.server.peer_uid", lambda _connection: __import__("os").getuid()
    )
    monkeypatch.setattr(
        "astral_project.daemon.server.receive",
        lambda _connection: (_ for _ in ()).throw(
            AstralError(ErrorCode.DAEMON_PROTOCOL, "bad", "bad", "bad", "bad")
        ),
    )
    server.serve_once()
    assert connection.payload is not None
    assert json.loads(connection.payload[4:])["kind"] == "error"


def test_other_uid_and_bad_frames_do_not_crash_daemon(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    server = DaemonServer(paths)
    server.start()
    try:
        monkeypatch.setattr("astral_project.daemon.server.peer_uid", lambda connection: -1)
        thread = _serve(server)
        rejected = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        rejected.connect(str(paths.socket))
        rejected.sendall(b"ignored")
        rejected.close()
        thread.join(timeout=1)
        assert not thread.is_alive()

        monkeypatch.undo()
        thread = _serve(server)
        malformed = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        malformed.connect(str(paths.socket))
        malformed.sendall(encode({"kind": "wrong", "version": 1}))
        assert receive(malformed)["kind"] == "error"
        malformed.close()
        thread.join(timeout=1)
        assert not thread.is_alive()
    finally:
        server.close()
