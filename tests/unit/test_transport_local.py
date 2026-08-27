from __future__ import annotations

import io
import socket
import struct
import subprocess
import threading
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from astral_project.core.errors import AstralError
from astral_project.crypto.cbor import canonical_dumps
from astral_project.transport.local import (
    MAX_TRANSPORT_FRAME,
    PrivateTransportServer,
    ProcessStream,
    TransportCapability,
    TransportEnvironment,
    _bridge_socket_stream,
    _bridge_stdio,
    _read_frame,
    _write_frame,
    fixed_ssh_argv,
    open_remote_sftp_stream,
    parse_external_ssh_argv,
    run_transport,
)


def test_transport_argv_and_capability(tmp_path: Path) -> None:
    assert parse_external_ssh_argv(["-s", "sftp"]) == ("-s", "sftp")
    with pytest.raises(AstralError):
        parse_external_ssh_argv(["-s", "ssh"])
    capability = TransportCapability.create(tmp_path)
    assert capability.environment.socket_path.parent == tmp_path
    assert capability.environment.as_dict()["ASPR_TRANSPORT_TOKEN"]
    assert (
        fixed_ssh_argv(
            ssh_binary=Path("/usr/bin/ssh"),
            identity_file=Path("/tmp/key"),
            host="host",
            remote_user="alice",
            port=2222,
        )[-1]
        == "aspr-channel-v1"
    )
    with pytest.raises(AstralError):
        fixed_ssh_argv(
            ssh_binary=Path("ssh"), identity_file=Path("/tmp/key"), host="host", remote_user="alice"
        )


def test_transport_bounds_and_process_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(AstralError):
        TransportEnvironment(Path("relative"), "token")
    with pytest.raises(AstralError):
        TransportEnvironment(tmp_path / "socket", "")
    with pytest.raises(AstralError):
        fixed_ssh_argv(
            ssh_binary=Path("/usr/bin/ssh"),
            identity_file=Path("/tmp/key"),
            host="host name",
            remote_user="alice",
        )
    with pytest.raises(AstralError):
        fixed_ssh_argv(
            ssh_binary=Path("/usr/bin/ssh"),
            identity_file=Path("/tmp/key"),
            host="host",
            remote_user="alice",
            port=0,
        )
    bad_factory = cast(Callable[[], object], lambda: None)
    server = PrivateTransportServer(
        TransportCapability.create(tmp_path),
        bad_factory,  # type: ignore[arg-type]
    )
    with pytest.raises(AstralError):
        server.serve_once()
    server.close()
    with pytest.raises(AstralError):
        server.serve_forever()

    class ClosedListener:
        def accept(self) -> object:
            raise OSError("closed")

    server._listener = ClosedListener()  # type: ignore[assignment]
    server.serve_forever()

    class OneConnection:
        count = 0

        def accept(self) -> tuple[object, None]:
            if self.count:
                raise OSError("closed")
            self.count += 1
            return object(), None

    class InlineThread:
        def __init__(
            self, *, target: Callable[..., object], args: tuple[object, ...], daemon: bool
        ) -> None:
            self.target = target
            self.args = args
            _ = daemon

        def start(self) -> None:
            self.target(*self.args)

    monkeypatch.setattr(threading, "Thread", InlineThread)
    server._listener = OneConnection()  # type: ignore[assignment]
    server._serve_connection = lambda _connection: setattr(server, "_listener", None)  # type: ignore[assignment]
    server.serve_forever()
    monkeypatch.undo()
    server._listener = None
    with pytest.raises(AstralError):
        server.serve_forever()
    process_with_missing_pipes = type("Process", (), {"stdin": None, "stdout": None})()
    with pytest.raises(AstralError):
        ProcessStream(process_with_missing_pipes)
    assert (
        run_transport(
            ["-s", "sftp"],
            environment={"ASPR_TRANSPORT_SOCKET": "relative", "ASPR_TRANSPORT_TOKEN": "x"},
            stdin=io.BytesIO(),
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
        )
        == 70
    )
    assert (
        run_transport(
            ["-s", "sftp"],
            environment={"ASPR_TRANSPORT_SOCKET": str(tmp_path / "missing")},
            stdin=io.BytesIO(),
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
        )
        == 70
    )
    assert (
        run_transport(
            ["-s", "sftp"],
            environment={
                "ASPR_TRANSPORT_SOCKET": str(tmp_path / "missing"),
                "ASPR_TRANSPORT_TOKEN": "x",
            },
            stdin=io.BytesIO(),
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
        )
        == 70
    )
    left, right = socket.socketpair()
    right.close()
    with pytest.raises(AstralError):
        _read_frame(left)
    left.close()

    long_parent = tmp_path / ("x" * 100)
    long_parent.mkdir()
    long_parent.chmod(0o700)
    bad_capability = TransportCapability(TransportEnvironment(long_parent / ("y" * 30), "token"))
    with pytest.raises(OSError):
        PrivateTransportServer(bad_capability, lambda: socket.socketpair()[0]).start()

    with pytest.raises(AstralError):
        _write_frame(socket.socketpair()[0], {"payload": "x" * (MAX_TRANSPORT_FRAME + 1)})

    class FakeEndpoint:
        def __init__(self, *, fail_recv: bool = False) -> None:
            self.fail_recv = fail_recv

        def recv(self, _length: int) -> bytes:
            if self.fail_recv:
                raise OSError("closed")
            return b""

        def sendall(self, _data: bytes) -> None:
            return None

        def shutdown_write(self) -> None:
            return None

    _bridge_socket_stream(FakeEndpoint(fail_recv=True), FakeEndpoint())  # type: ignore[arg-type]
    _bridge_socket_stream(FakeEndpoint(), FakeEndpoint(fail_recv=True))  # type: ignore[arg-type]

    class BadInput:
        def read(self, _length: int) -> bytes:
            raise ValueError("closed")

    left, right = socket.socketpair()
    right.close()
    _bridge_stdio(left, stdin=BadInput(), stdout=io.BytesIO())  # type: ignore[arg-type]

    class Process:
        def __init__(self, stdin: object, stdout: object) -> None:
            self.stdin = stdin
            self.stdout = stdout
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float) -> None:
            _ = timeout

    class ReadOnly:
        def read(self, _length: int) -> bytes:
            return b""

        def close(self) -> None:
            return None

    process = Process(io.BytesIO(), ReadOnly())
    adapter = ProcessStream(process)  # type: ignore[arg-type]
    adapter.sendall(b"x")
    assert adapter.write(b"y") == 1
    adapter.flush()
    adapter.shutdown_write()
    assert adapter.recv(1) == b""
    assert adapter.read(1) == b""
    adapter.close()
    assert process.terminated

    class ReadOne(ReadOnly):
        def read1(self, _length: int) -> bytes:
            return b""

    process_with_read1 = Process(io.BytesIO(), ReadOne())
    assert ProcessStream(process_with_read1).recv(1) == b""  # type: ignore[arg-type]


def test_private_transport_server_rejects_bad_frames(tmp_path: Path) -> None:
    capability = TransportCapability.create(tmp_path)
    server = PrivateTransportServer(capability, lambda: socket.socketpair()[0])
    server.start()
    serving = threading.Thread(target=server.serve_once)
    serving.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(capability.environment.socket_path))
    _write_frame(client, {"version": 1, "operation": "bad", "token": "x"})
    client.close()
    serving.join(timeout=2)
    server.close()

    for body in (b"not-json", b"[]"):
        left, right = socket.socketpair()
        left.sendall(struct.pack(">I", len(body)) + body)
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(AstralError):
            _read_frame(right)
        left.close()
        right.close()
    left, right = socket.socketpair()
    left.sendall(struct.pack(">I", MAX_TRANSPORT_FRAME + 1))
    left.shutdown(socket.SHUT_WR)
    with pytest.raises(AstralError):
        _read_frame(right)
    left.close()
    right.close()


def test_private_transport_bridges_only_authenticated_stream(tmp_path: Path) -> None:
    capability = TransportCapability.create(tmp_path)

    def factory() -> socket.socket:
        left, right = socket.socketpair()

        def remote() -> None:
            right.sendall(b"remote-reply")
            assert right.recv(64) == b"client-request"
            right.close()

        threading.Thread(target=remote, daemon=True).start()
        return left

    server = PrivateTransportServer(capability, factory)
    server.start()
    serving = threading.Thread(target=server.serve_once)
    serving.start()
    environment = capability.environment.as_dict()
    output = io.BytesIO()
    assert (
        run_transport(
            ["-s", "sftp"],
            environment=environment,
            stdin=io.BytesIO(b"client-request"),
            stdout=output,
            stderr=io.BytesIO(),
        )
        == 0
    )
    serving.join(timeout=2)
    server.close()
    assert output.getvalue() == b"remote-reply"


def test_open_remote_stream_consumes_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    ready = canonical_dumps({"status": "ready", "version": 1})

    class Request:
        def canonical_bytes(self) -> bytes:
            return b"request"

    class Process:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(struct.pack(">I", len(ready)) + ready)
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float) -> None:
            _ = timeout

    process = Process()
    captured: dict[str, object] = {}

    def fake_popen(*args: object, **kwargs: object) -> Process:
        captured.update(kwargs)
        return process

    monkeypatch.setenv("LANG", "C")
    monkeypatch.delenv("TERM", raising=False)
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "must-not-appear")
    monkeypatch.setenv("PATH", "/not-visible")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    stream = open_remote_sftp_stream(
        Request(),  # type: ignore[arg-type]
        ssh_binary=Path("/usr/bin/ssh"),
        identity_file=Path("/tmp/key"),
        host="host",
        remote_user="alice",
    )
    assert process.stdin.getvalue()
    child_environment = captured["env"]
    assert isinstance(child_environment, dict)
    assert child_environment == {"LANG": "C"}
    stream.close()


def test_open_remote_stream_rejection_closes_process(monkeypatch: pytest.MonkeyPatch) -> None:
    rejection = canonical_dumps({"status": "rejected", "version": 1})

    class Request:
        def canonical_bytes(self) -> bytes:
            return b"request"

    class Process:
        def __init__(self) -> None:
            self.stdin = io.BytesIO()
            self.stdout = io.BytesIO(struct.pack(">I", len(rejection)) + rejection)
            self.terminated = False

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: float) -> None:
            _ = timeout

    process = Process()
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: process)
    with pytest.raises(AstralError):
        open_remote_sftp_stream(
            Request(),  # type: ignore[arg-type]
            ssh_binary=Path("/usr/bin/ssh"),
            identity_file=Path("/tmp/key"),
            host="host",
            remote_user="alice",
        )
    assert process.terminated


def test_transport_rejects_missing_token_and_bad_server(tmp_path: Path) -> None:
    capability = TransportCapability.create(tmp_path)
    server = PrivateTransportServer(capability, lambda: (_ for _ in ()).throw(AssertionError()))
    server.start()
    serving = threading.Thread(target=server.serve_once)
    serving.start()
    environment = {
        "ASPR_TRANSPORT_SOCKET": str(capability.environment.socket_path),
        "ASPR_TRANSPORT_TOKEN": "wrong",
    }
    stderr = io.BytesIO()
    assert (
        run_transport(
            ["-s", "sftp"],
            environment=environment,
            stdin=io.BytesIO(),
            stdout=io.BytesIO(),
            stderr=stderr,
        )
        == 70
    )
    serving.join(timeout=2)
    server.close()
    assert b"private transport" in stderr.getvalue()

    assert (
        run_transport(
            ["--help"], environment={}, stdin=io.BytesIO(), stdout=io.BytesIO(), stderr=io.BytesIO()
        )
        == 70
    )
