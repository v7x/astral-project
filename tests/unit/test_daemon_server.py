from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

import astral_project.daemon.server as daemon_server
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.daemon.client import DaemonClient
from astral_project.daemon.protocol import encode, receive
from astral_project.daemon.server import DaemonPaths, DaemonServer
from astral_project.sandbox.hardening import (
    HardeningError,
    HardeningPolicy,
    HardeningStatus,
    RootRole,
)
from astral_project.state.sqlite import StateDatabase


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
        result = DaemonClient(paths.socket).request(
            request_id="status-1", cancellation_id="cancel-2", operation="status"
        )
        assert result["alive"] is True
        assert result["state_version"] == 1
        hardening = result["hardening"]
        assert isinstance(hardening, dict)
        assert hardening["landlock_available"] is True
        assert hardening["required"] is True
        thread.join(timeout=1)
        assert not thread.is_alive()
    finally:
        restarted.close()


def test_daemon_applies_hardening_at_trusted_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    observed: list[object] = []

    def apply(policy: object) -> HardeningStatus:
        observed.append(policy)
        return HardeningStatus(True, 4, True, True, "enforced")

    monkeypatch.setattr("astral_project.daemon.server.enforce", apply)
    server = DaemonServer(paths)
    server.start()
    try:
        assert len(observed) == 1
        policy = observed[0]
        assert isinstance(policy, HardeningPolicy)
        roots = dict(policy.allowed_roots)
        socket_root = paths.runtime.with_name(f"{paths.runtime.name}-sockets")
        assert roots[paths.runtime] is RootRole.REGULAR_WRITABLE
        assert roots[socket_root] is RootRole.SOCKET_RUNTIME
        assert socket_root.parent == paths.runtime.parent
        thread = _serve(server)
        result = DaemonClient(paths.socket).request(
            request_id="status-hardening", cancellation_id="cancel-hardening", operation="status"
        )
        assert result["hardening"] == {
            "landlock_abi": 4,
            "landlock_available": True,
            "landlock_required_abi": 3,
            "required": True,
            "enforced": True,
            "reason": "enforced",
        }
        thread.join(timeout=1)
    finally:
        server.close()


def test_bounded_remote_audit_run_reads_successful_output() -> None:
    returncode, output = daemon_server._bounded_remote_audit_run(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write(b'ok')",
        ],
        input_data=b"request",
        env={"PATH": "/usr/bin:/bin"},
        timeout=5,
    )
    assert (returncode, output) == (0, b"ok")


def test_bounded_remote_audit_run_rejects_oversized_output() -> None:
    with pytest.raises(ValueError, match="too large"):
        daemon_server._bounded_remote_audit_run(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 1048577)"],
            input_data=b"",
            env={"PATH": "/usr/bin:/bin"},
            timeout=5,
        )


def test_bounded_remote_audit_run_times_out_before_output() -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        daemon_server._bounded_remote_audit_run(
            [sys.executable, "-c", "import time; time.sleep(1)"],
            input_data=b"",
            env={"PATH": "/usr/bin:/bin"},
            timeout=0,
        )


def test_bounded_remote_audit_run_times_out_while_waiting() -> None:
    with pytest.raises(subprocess.TimeoutExpired):
        daemon_server._bounded_remote_audit_run(
            [sys.executable, "-c", "import time; time.sleep(1)"],
            input_data=b"",
            env={"PATH": "/usr/bin:/bin"},
            timeout=0.01,
        )


def test_daemon_remote_audit_export_uses_fixed_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    server = DaemonServer(_paths(tmp_path))
    server.start()
    try:
        assert server._database is not None
        monkeypatch.setattr(
            server._database,
            "host_transport",
            lambda _host_id: (
                "testuser",
                {"address": "remote.example", "identity_file": "/home/testuser/.ssh/key"},
            ),
        )
        observed: dict[str, object] = {}

        def run(argv: list[str], **kwargs: object) -> tuple[int, bytes]:
            observed["argv"] = argv
            observed["input"] = kwargs["input_data"]
            return 0, b'{"version":1,"ok":true,"export":"{\\"path\\":\\"<redacted>\\"}\\n"}'

        monkeypatch.setattr("astral_project.daemon.server._bounded_remote_audit_run", run)
        result = server._response("audit.remote.export", {"host_id": "host-1"})
        assert result["host_id"] == "host-1"
        assert result["path_mode"] == "redact"
        assert result["export"]
        assert observed["argv"][-1] == "aspr-audit-export-v1"  # type: ignore[index]
    finally:
        server.close()


def test_daemon_remote_audit_export_rejects_bad_transport_responses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    unstarted = DaemonServer(_paths(tmp_path / "unstarted"))
    with pytest.raises(AstralError, match="state database"):
        unstarted._response("audit.remote.export", {})
    with pytest.raises(AstralError, match="state database"):
        unstarted._remote_audit_export({"host_id": "h"})
    server = DaemonServer(_paths(tmp_path))
    server.start()
    try:
        with pytest.raises(AstralError, match="payload"):
            server._response("audit.remote.export")
        assert server._database is not None
        monkeypatch.setattr(
            server._database,
            "host_transport",
            lambda _id: ("user", {"address": "remote.example", "identity_file": "/home/user/key"}),
        )
        with pytest.raises(AstralError, match="fields"):
            server._remote_audit_export({"host_id": 1})
        with pytest.raises(AstralError, match="path mode"):
            server._remote_audit_export({"host_id": "h", "path_mode": "raw"})
        monkeypatch.setattr(
            server._database, "host_transport", lambda _id: ("user", {"address": 1})
        )
        with pytest.raises(AstralError, match="metadata"):
            server._remote_audit_export({"host_id": "h"})
        monkeypatch.setattr(
            server._database,
            "host_transport",
            lambda _id: ("user", {"address": "remote.example", "identity_file": "/home/user/key"}),
        )
        monkeypatch.setattr(
            "astral_project.daemon.server._bounded_remote_audit_run",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                daemon_server._RemoteAuditOutputTooLarge("large")
            ),
        )
        with pytest.raises(AstralError, match="response"):
            server._remote_audit_export({"host_id": "h"})
        monkeypatch.setattr(
            "astral_project.daemon.server._bounded_remote_audit_run",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("ssh")),
        )
        with pytest.raises(AstralError, match="transport"):
            server._remote_audit_export({"host_id": "h"})

        monkeypatch.setattr(
            "astral_project.daemon.server._bounded_remote_audit_run",
            lambda *_args, **_kwargs: (1, b""),
        )
        with pytest.raises(AstralError, match="rejected"):
            server._remote_audit_export({"host_id": "h"})

        monkeypatch.setattr(
            "astral_project.daemon.server._bounded_remote_audit_run",
            lambda *_args, **_kwargs: (0, b"not-json"),
        )
        with pytest.raises(AstralError, match="response"):
            server._remote_audit_export({"host_id": "h"})

        monkeypatch.setattr(
            "astral_project.daemon.server._bounded_remote_audit_run",
            lambda *_args, **_kwargs: (0, b'{"version":1,"ok":true,"export":1}'),
        )
        with pytest.raises(AstralError, match="response"):
            server._remote_audit_export({"host_id": "h"})
    finally:
        server.close()


def test_daemon_client_accepts_authorized_remote_audit_export_wire_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    server = DaemonServer(paths)
    server.start()
    try:
        assert server._database is not None

        def host_transport(host_id: str) -> tuple[str, dict[str, object]]:
            if host_id != "host-1":
                raise AstralError(
                    code=ErrorCode.STATE_CORRUPT,
                    message="host is not enrolled",
                    security_result="rejected",
                    unsafe_reason="test host is not enrolled",
                    next_action="enroll host",
                )
            return "testuser", {
                "address": "remote.example",
                "identity_file": "/home/testuser/.ssh/key",
                "known_hosts": "/home/testuser/.ssh/known_hosts",
                "port": 22,
            }

        monkeypatch.setattr(server._database, "host_transport", host_transport)
        observed: dict[str, object] = {}

        def bounded(argv: list[str], **kwargs: object) -> tuple[int, bytes]:
            observed["argv"] = argv
            observed["input"] = kwargs["input_data"]
            return 0, b'{"version":1,"ok":true,"export":"{}\\n"}'

        monkeypatch.setattr(daemon_server, "_bounded_remote_audit_run", bounded)
        thread = _serve(server)
        result = DaemonClient(paths.socket).request(
            request_id="remote-audit-wire",
            cancellation_id="cancel-remote-audit-wire",
            operation="audit.remote.export",
            payload={"host_id": "host-1"},
        )
        assert result == {"host_id": "host-1", "path_mode": "redact", "export": "{}\n"}
        assert observed["argv"][-1] == "aspr-audit-export-v1"  # type: ignore[index]
        thread.join(timeout=1)
        assert not thread.is_alive()

        unauthorized = _serve(server)
        with pytest.raises(AstralError, match="rejected"):
            DaemonClient(paths.socket).request(
                request_id="remote-audit-unauthorized",
                cancellation_id="cancel-remote-audit-unauthorized",
                operation="audit.remote.export",
                payload={"host_id": "not-enrolled"},
            )
        unauthorized.join(timeout=1)
        assert not unauthorized.is_alive()
    finally:
        server.close()


def test_daemon_records_audit_record_operation(tmp_path: Path) -> None:
    server = DaemonServer(_paths(tmp_path))
    server.start()
    try:
        assert server._response(
            "audit.record",
            {
                "kind": "sandbox.launch",
                "subject_type": "sandbox",
                "subject_id": "s1",
                "payload": {"path": "/tmp/work"},
            },
        ) == {"recorded": True}
        assert server._database is not None
        assert server._database.list_audit_events()[-1].kind == "sandbox.launch"
        with pytest.raises(AstralError):
            server._response("audit.record")
        with pytest.raises(AstralError):
            server._response("audit.record", {"kind": "bad"})
    finally:
        server.close()


def test_daemon_audits_hardening_startup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _paths(tmp_path)
    failure = HardeningError(
        code=ErrorCode.HARDENING_APPLY,
        message="rule load failed",
        security_result="daemon rejected",
        unsafe_reason="hardening is mandatory",
        next_action="repair hardening",
    )

    def fail(_policy: object) -> None:
        raise failure

    monkeypatch.setattr("astral_project.daemon.server.enforce", fail)
    with pytest.raises(HardeningError):
        DaemonServer(paths).start()
    database = StateDatabase.open(paths.state)
    assert database.list_audit_events()[-1].kind == "hardening.failure"


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

    connection2 = Connection()
    server._listener = type("Listener", (), {"accept": lambda _self: (connection2, None)})()
    monkeypatch.setattr(
        "astral_project.daemon.server.receive",
        lambda _connection: {
            "cancellation_id": "cancel",
            "kind": "request",
            "operation": "status",
            "request_id": "request",
            "version": 1,
        },
    )
    server.serve_once()
    assert connection2.payload is not None
    decoded = json.loads(connection2.payload[4:])
    assert decoded["kind"] == "response"
    assert decoded["ok"] is False


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
