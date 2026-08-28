from __future__ import annotations

import socket
import threading
from dataclasses import replace
from io import StringIO
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project import cli
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    SignedGrant,
    SourceIdentity,
)
from astral_project.daemon.client import DaemonClient
from astral_project.daemon.protocol import Response, encode, parse_request
from astral_project.daemon.server import DaemonLock, DaemonPaths, DaemonServer
from astral_project.sandbox.hardening import HardeningStatus
from astral_project.session.listing import SessionListingScope
from astral_project.state.sqlite import ActiveListingSession, StateDatabase


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


def test_daemon_start_fails_closed_without_landlock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "astral_project.daemon.server.hardening_status",
        lambda required: HardeningStatus(False, None, required, False, "missing ABI"),
    )
    server = DaemonServer(DaemonPaths(tmp_path / "runtime", tmp_path / "state.sqlite3"))
    with pytest.raises(AstralError) as error:
        server.start()
    assert error.value.code is ErrorCode.HARDENING_UNAVAILABLE
    assert not server.paths.socket.exists()
    database = StateDatabase.open(server.paths.state)
    assert database.list_audit_events()[-1].kind == "hardening.failure"


def test_default_daemon_binds_active_grant_to_listing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import astral_project.rclone.listing as listing_module

    grant = Grant(
        GrantId("00000000-0000-4000-8000-000000000001"),
        IssuerKeyId("00000000-0000-4000-8000-000000000002"),
        HostId("00000000-0000-4000-8000-000000000003"),
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
    signing_key = Ed25519PrivateKey.generate()
    active = ActiveListingSession(
        "00000000-0000-4000-8000-000000000004",
        SignedGrant.create(grant, signing_key),
        str(grant.host_id),
        "SHA256:test",
        "alice",
        {"address": "127.0.0.1", "identity_file": str(tmp_path / "id"), "port": 22},
    )

    class FakeDatabase:
        def active_listing_session(self) -> ActiveListingSession:
            return active

        def record_audit(self, *_args: object, **_kwargs: object) -> None:
            return None

    monkeypatch.setattr(
        "astral_project.daemon.server.StateDatabase.open",
        staticmethod(lambda _path: FakeDatabase()),
    )
    monkeypatch.setattr(
        listing_module,
        "daemon_bound_listing_handler",
        lambda payload, **_kwargs: {"target": payload["target"]},
    )
    server = DaemonServer(DaemonPaths(tmp_path / "runtime", tmp_path / "state.sqlite3"))
    server.start()
    try:
        payload = {
            "filters": [],
            "json_output": False,
            "max_depth": None,
            "no_header": False,
            "raw_output": False,
            "recursive": False,
            "reverse": False,
            "sort": "path",
            "stat": False,
            "target": "00000000-0000-4000-8000-000000000001:/project",
            "timeout_seconds": None,
        }
        assert server._response("ls", payload) == {"target": "aspr-session:/project"}
        monkeypatch.setattr(
            listing_module,
            "daemon_bound_listing_handler",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("transport down")),
        )
        with pytest.raises(RuntimeError, match="transport down"):
            server._default_listing_handler(payload)
    finally:
        server.close()
    server._database = None
    monkeypatch.setattr(
        listing_module,
        "daemon_bound_listing_handler",
        lambda payload, **_kwargs: {"target": payload["target"]},
    )
    assert server._default_listing_handler(payload) == {
        "target": "00000000-0000-4000-8000-000000000001:/project"
    }
    monkeypatch.setattr(
        listing_module,
        "daemon_bound_listing_handler",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("transport down")),
    )
    with pytest.raises(RuntimeError, match="transport down"):
        server._default_listing_handler(payload)
    server._listing_session = None
    with pytest.raises(AstralError):
        server._default_listing_handler(payload)
    server._listing_session = replace(active, host_metadata={"address": "127.0.0.1"})
    with pytest.raises(AstralError):
        server._default_listing_handler(payload)
    mismatched_host = replace(grant, host_id=HostId("00000000-0000-4000-8000-000000000005"))
    server._listing_session = replace(
        active, signed_grant=SignedGrant.create(mismatched_host, signing_key)
    )
    with pytest.raises(AstralError):
        server._default_listing_handler(payload)
    mismatched_user = replace(grant, remote_user="bob")
    server._listing_session = replace(
        active, signed_grant=SignedGrant.create(mismatched_user, signing_key)
    )
    with pytest.raises(AstralError):
        server._default_listing_handler(payload)


def test_client_sends_optional_listing_payload(tmp_path: Path) -> None:
    path = tmp_path / "daemon.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen()
    observed: dict[str, object] = {}

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            from astral_project.daemon.protocol import receive

            observed.update(receive(connection))
            connection.sendall(
                encode(
                    {
                        "kind": "response",
                        "request_id": "a",
                        "ok": True,
                        "result": {},
                    }
                )
            )

    thread = threading.Thread(target=serve)
    thread.start()
    assert (
        DaemonClient(path).request(
            request_id="a", cancellation_id="b", operation="ls", payload={"target": "grant:/"}
        )
        == {}
    )
    thread.join(timeout=1)
    listener.close()
    assert observed["payload"] == {"target": "grant:/"}


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
        {
            "kind": "response",
            "request_id": "a",
            "ok": False,
            "result": {"message": "bad", "dependency_error": "dep"},
        },
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
    with pytest.raises(AstralError):
        parse_request(
            {
                "cancellation_id": "b",
                "kind": "request",
                "operation": "ping",
                "payload": {},
                "request_id": "a",
                "version": 1,
            }
        )
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
    with pytest.raises(AstralError):
        clean._response("ls", {"invalid": True})
    assert clean._response("cancel") == {"cancelled": True}
    listed = DaemonServer(
        DaemonPaths(tmp_path / "listing", tmp_path / "listing.sqlite3"),
        listing_handler=lambda payload: {"target": payload["target"]},
    )
    assert listed._response("ls", {"target": "grant:/"}) == {"target": "grant:/"}
    scoped = DaemonServer(
        DaemonPaths(tmp_path / "scoped", tmp_path / "scoped.sqlite3"),
        listing_handler=lambda payload: {"target": payload["target"]},
        listing_scope=SessionListingScope("grant", ("/project",)),
    )
    scoped_payload = {
        "filters": [],
        "json_output": False,
        "max_depth": None,
        "no_header": False,
        "raw_output": False,
        "recursive": False,
        "reverse": False,
        "sort": "path",
        "stat": False,
        "target": "grant:/project",
        "timeout_seconds": None,
    }
    assert scoped._response("ls", scoped_payload) == {"target": "aspr-session:/project"}
    scoped_payload["target"] = "other:/project"
    with pytest.raises(AstralError):
        scoped._response("ls", scoped_payload)
    default_scoped = DaemonServer(
        DaemonPaths(tmp_path / "default", tmp_path / "default.sqlite3"),
        listing_scope=SessionListingScope("grant", ("/project",)),
    )
    monkeypatch.setattr(
        default_scoped,
        "_default_listing_handler",
        lambda payload: {"target": payload["target"]},
    )
    scoped_payload["target"] = "grant:/project"
    assert default_scoped._response("ls", scoped_payload) == {"target": "aspr-session:/project"}
    default_scoped.start()
    default_scoped.close()
    with pytest.raises(AstralError):
        listed._response("ls")
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
