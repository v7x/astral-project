from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path
from typing import cast

import pytest
from grant_helpers import sample_grant

from astral_project.cli import run
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import AccessMode, SignedGrant
from astral_project.crypto.keys import generate_private_key
from astral_project.sandbox.command import (
    _close_session,
    _ensure_session,
    _list_maps,
    _load_grant,
    _mounts_healthy,
    _parse_remote,
    _session_show,
    _string,
    parse_arguments,
    run_sandbox,
)
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode, RemoteBinding
from astral_project.sandbox.runner import _terminate, run_plan
from astral_project.sandbox.session_api import SessionApiServer, _read_line


def test_parse_sandbox_arguments_and_fixed_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parsed = parse_arguments(
        [
            "sandbox",
            "--network",
            "none",
            "--grant",
            "g1",
            "--remote",
            "/source=/workspace:ro",
            "--remote",
            "g1:/other=/data:rw",
            "--",
            "/bin/sh",
            "-c",
            "true",
        ]
    )
    assert parsed.network is NetworkMode.NONE
    assert parsed.grant_id == "g1"
    assert parsed.remotes[0].mode is AccessMode.READ_ONLY
    assert parsed.remotes[1].mode is AccessMode.READ_WRITE
    inferred = parse_arguments(["sandbox", "--network", "inherit", "--remote", "g1:/src=/remote"])
    assert inferred.grant_id == "g1"
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)
    binding = RemoteBinding("mount", tmp_path, "/workspace", AccessMode.READ_ONLY)
    plan = LocalSandboxPlan(("/bin/sh",), NetworkMode.NONE, (binding,))
    argv = plan.argv()
    assert argv[0:9] == [
        "/usr/bin/bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind",
        "/usr",
        "/usr",
    ]
    assert "--unshare-net" in argv
    assert "--cap-drop" in argv and argv[-2:] == ["--", "/bin/sh"]
    assert "--bind" not in argv
    assert plan.launcher_argv() == ["/usr/libexec/astral-project/aspr-bwrap-launch"]
    assert plan.plan_bytes().startswith(b"ASPRSB01")
    session_file = tmp_path / "session.sock"
    session_file.write_text("")
    with_session = LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, (binding,), session_file)
    assert "/run/astral-project/session.sock" in with_session.argv()
    assert str(session_file).encode() in with_session.plan_bytes()

    bad_binding = object.__new__(RemoteBinding)
    object.__setattr__(bad_binding, "mount_id", "m")
    object.__setattr__(bad_binding, "host_path", Path("/" + "x" * 4096))
    object.__setattr__(bad_binding, "target", "/bad")
    object.__setattr__(bad_binding, "mode", AccessMode.READ_ONLY)
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, (bad_binding,)).plan_bytes()
    too_long_socket = LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT)
    object.__setattr__(too_long_socket, "session_socket", Path("/" + "s" * 4096))
    with pytest.raises(AstralError):
        too_long_socket.plan_bytes()


def test_sandbox_argument_and_plan_rejections(tmp_path: Path) -> None:
    for args in (
        ["sandbox"],
        ["sandbox", "--network", "bad"],
        ["sandbox", "--network", "inherit", "--"],
        ["sandbox", "--network", "inherit", "--grant", "g"],
        ["sandbox", "--network", "inherit", "--remote", "g1:/a=/x", "--remote", "g2:/b=/y"],
        ["sandbox", "--network", "inherit", "--remote", "/a=/x"],
        ["sandbox", "--network", "inherit", "positional"],
    ):
        with pytest.raises(AstralError):
            parse_arguments(args)
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, bwrap_binary=Path("/bad"))
    with pytest.raises(AstralError):
        LocalSandboxPlan((), NetworkMode.INHERIT)
    with pytest.raises(AstralError):
        LocalSandboxPlan(
            ("/bin/sh",),
            NetworkMode.INHERIT,
            launcher_binary=Path("/tmp/launcher"),
        )
    assert (
        "--ro-bind"
        not in LocalSandboxPlan(("/bin/sh", "--ro-bind"), NetworkMode.INHERIT).launcher_argv()
    )


def test_plan_bytes_rejects_oversized_fields_and_plan() -> None:
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh", "x" * 4097), NetworkMode.INHERIT).plan_bytes()
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh",) + ("x" * 1024,) * 64, NetworkMode.INHERIT).plan_bytes()


def test_runner_rejects_missing_or_broken_launcher_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NoStdin:
        stdin = None

        def poll(self) -> int:
            return 0

    with pytest.raises(AstralError):
        run_plan(
            LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT),
            popen=lambda *_args, **_kwargs: NoStdin(),  # type: ignore[arg-type]
        )

    class BrokenStdin:
        def write(self, _value: bytes) -> None:
            raise BrokenPipeError()

        def close(self) -> None:
            return None

    class BrokenProcess:
        pid = 1
        stdin = BrokenStdin()

        def poll(self) -> int | None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            return 0

    monkeypatch.setattr("astral_project.sandbox.runner.os.killpg", lambda *_args: None)
    with pytest.raises(AstralError):
        run_plan(
            LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT),
            popen=lambda *_args, **_kwargs: BrokenProcess(),  # type: ignore[arg-type]
        )


def test_runner_executes_and_terminates_on_health_loss(monkeypatch: pytest.MonkeyPatch) -> None:
    class Process:
        pid = 123
        returncode = 0

        def __init__(self) -> None:
            self.calls = 0
            self.stdin = self

        def write(self, _value: bytes) -> None:
            return None

        def close(self) -> None:
            return None

        def poll(self) -> int | None:
            self.calls += 1
            return None if self.calls == 1 else 0

        def wait(self, timeout: float | None = None) -> int:
            return 0

    process = Process()
    monkeypatch.setattr("astral_project.sandbox.runner.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("astral_project.sandbox.runner.os.killpg", lambda *_args: None)
    with pytest.raises(AstralError, match="remote view"):
        run_plan(
            LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT),
            health_check=lambda: False,
            popen=lambda *_args, **_kwargs: process,  # type: ignore[arg-type]
        )
    process = Process()
    assert (
        run_plan(
            LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT),
            popen=lambda *_args, **_kwargs: process,  # type: ignore[arg-type]
        )
        == 0
    )


def test_session_socket_allows_only_narrow_same_session_api(tmp_path: Path) -> None:
    path = tmp_path / "session.sock"
    server = SessionApiServer(
        path,
        session_id="s1",
        describe=lambda: {"session_id": "s1"},
        mounts=lambda: [{"mount_id": "m1"}],
        expiry=lambda: 99,
        close=lambda: {"state": "closed"},
    )
    server.start()
    try:

        def request(method: str, session_id: str = "s1") -> dict[str, object]:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(path))
                client.sendall(
                    json.dumps({"method": method, "session_id": session_id}).encode() + b"\n"
                )
                return cast(dict[str, object], json.loads(client.recv(4096)))

        assert request("DescribeSession")["ok"] is True
        assert request("GetRemoteMounts")["ok"] is True
        assert request("GetExpiry")["ok"] is True
        assert request("CloseOwnSession")["ok"] is True
        assert request("CreateMount")["ok"] is False
        assert request("GetExpiry", "other")["ok"] is False
    finally:
        server.close()


def test_sandbox_remote_orchestration_closes_owned_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)
    calls: list[tuple[str, object]] = []

    def request(operation: str, payload: object = None) -> dict[str, object]:
        calls.append((operation, payload))
        if operation == "session.list":
            return {"sessions": []}
        if operation == "session.open":
            return {"session_id": "s1"}
        if operation == "grant.show":
            import base64

            return {"cbor_b64": base64.b64encode(grant_bytes).decode()}
        if operation == "mount.open":
            return {"mount_id": "m1", "state": "ready"}
        if operation == "mount.list":
            return {"mounts": [{"mount_id": "m1", "session_id": "s1"}]}
        if operation == "mount.show":
            return {"mount_id": "m1", "state": "ready"}
        if operation == "session.show":
            return {"session_id": "s1"}
        return {"state": "closed"}

    grant_bytes = SignedGrant.create(sample_grant(), generate_private_key()).to_cbor()
    monkeypatch.setattr("astral_project.sandbox.command.run_plan", lambda *args, **kwargs: 0)
    assert (
        run_sandbox(
            [
                "sandbox",
                "--network",
                "inherit",
                "--grant",
                "g1",
                "--remote",
                "/scratch/alice/project=/remote",
            ],
            daemon_request=request,
            runtime=tmp_path,
        )
        == 0
    )
    assert [name for name, _ in calls].count("mount.close") == 1
    assert [name for name, _ in calls].count("session.close") == 1

    reused_calls: list[str] = []

    def reused(operation: str, _payload: object = None) -> dict[str, object]:
        reused_calls.append(operation)
        if operation == "session.list":
            return {"sessions": [{"state": "active", "grant_id": "g1", "session_id": "s1"}]}
        if operation == "grant.show":
            import base64

            return {"cbor_b64": base64.b64encode(grant_bytes).decode()}
        if operation == "mount.open":
            return {"mount_id": "m1", "state": "ready"}
        if operation == "mount.show":
            return {"state": "ready"}
        return {"mounts": []}

    assert (
        run_sandbox(
            [
                "sandbox",
                "--network",
                "inherit",
                "--grant",
                "g1",
                "--remote",
                "/scratch/alice/project=/remote",
            ],
            daemon_request=reused,
            runtime=tmp_path,
        )
        == 0
    )
    assert "session.open" not in reused_calls and "session.close" not in reused_calls


def test_sandbox_private_helpers_and_rejections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for value in ("", "x/y", "bad=/target", ":/source=/target", "source=/target", "/source=target"):
        with pytest.raises(AstralError):
            _parse_remote(value)
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--grant"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--remote"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network", "inherit", "--foo"])
    with pytest.raises(AstralError):
        parse_arguments(
            ["sandbox", "--network", "inherit", "--remote", "g1:/a=/x", "--grant", "g2"]
        )
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)
    with pytest.raises(AstralError):
        RemoteBinding("", tmp_path, "/x", AccessMode.READ_ONLY)
    with pytest.raises(AstralError):
        RemoteBinding("m", tmp_path / "missing", "/x", AccessMode.READ_ONLY)
    with pytest.raises(AstralError):
        RemoteBinding("m", tmp_path, "/x", "bad")  # type: ignore[arg-type]
    with pytest.raises(AstralError):
        RemoteBinding("m", tmp_path, "/", AccessMode.READ_ONLY)
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh",), "bad")  # type: ignore[arg-type]
    first = RemoteBinding("m1", tmp_path, "/x", AccessMode.READ_ONLY)
    second = RemoteBinding("m2", tmp_path, "/x", AccessMode.READ_ONLY)
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, (first, second))
    nested = RemoteBinding("m2", tmp_path, "/x/y", AccessMode.READ_WRITE)
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, (first, nested))
    third = RemoteBinding("m3", tmp_path, "/z", AccessMode.READ_ONLY)
    LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, (first, third))
    with pytest.raises(AstralError):
        LocalSandboxPlan(
            ("/bin/sh",), NetworkMode.INHERIT, session_socket=tmp_path / "missing.sock"
        )
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: False)
    with pytest.raises(AstralError):
        RemoteBinding("m", tmp_path, "/x", AccessMode.READ_ONLY)


def test_sandbox_command_error_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.sandbox.command.run_plan", lambda *_args, **_kwargs: 0)
    assert (
        run_sandbox(
            ["sandbox", "--network", "inherit"], daemon_request=lambda *_args: {}, runtime=tmp_path
        )
        == 0
    )
    import base64

    encoded = base64.b64encode(
        SignedGrant.create(sample_grant(), generate_private_key()).to_cbor()
    ).decode()

    def request(operation: str, payload: object = None) -> dict[str, object]:
        if operation == "session.list":
            return {"sessions": []}
        if operation == "session.open":
            return {"session_id": "s"}
        if operation == "grant.show":
            return {"cbor_b64": encoded}
        if operation == "session.close":
            return {"state": "closed"}
        if operation == "mount.open":
            return {"mount_id": "m", "state": "creating"}
        return {"state": "creating"}

    with pytest.raises(AstralError, match="outside"):
        run_sandbox(
            ["sandbox", "--network", "inherit", "--grant", "g", "--remote", "/missing=/x"],
            daemon_request=request,
            runtime=tmp_path,
        )
    with pytest.raises(AstralError, match="ready"):
        run_sandbox(
            [
                "sandbox",
                "--network",
                "inherit",
                "--grant",
                "g",
                "--remote",
                "/scratch/alice/project=/x",
            ],
            daemon_request=request,
            runtime=tmp_path,
        )
    assert _session_show("s", lambda *_args: {"session_id": "s"})["session_id"] == "s"
    assert _close_session("s", lambda *_args: {"state": "closed"})["state"] == "closed"


def test_command_helpers_and_session_reuse(tmp_path: Path) -> None:
    with pytest.raises(AstralError):
        _list_maps({}, "items")
    with pytest.raises(AstralError):
        _string({}, "value")
    with pytest.raises(AstralError):
        _load_grant("g", lambda *_args: {"cbor_b64": "%%%"})
    with pytest.raises(AstralError):
        _load_grant("g", lambda *_args: {})
    assert _ensure_session(
        "g",
        lambda *_args: {"sessions": [{"state": "active", "grant_id": "g", "session_id": "s"}]},
    ) == ("s", False)
    with pytest.raises(AstralError):
        _ensure_session(
            "g",
            lambda *_args: {
                "sessions": [
                    {"state": "active", "grant_id": "other", "session_id": "s"},
                    {"state": "active", "grant_id": "other", "session_id": "s2"},
                ]
            },
        )
    states = iter(("ready", "failed"))
    assert _mounts_healthy(["m"], lambda *_args: {"state": next(states)}) is True
    assert _mounts_healthy(["m"], lambda *_args: {"state": next(states)}) is False
    assert (
        _mounts_healthy(
            ["m"],
            lambda *_args: (_ for _ in ()).throw(
                AstralError(ErrorCode.DAEMON_AUTH, "x", "x", "x", "x")
            ),
        )
        is False
    )


def test_runner_error_and_kill_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(AstralError):
        run_plan(LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT), poll_seconds=0)

    def fail(*_args: object, **_kwargs: object) -> object:
        raise OSError("missing")

    with pytest.raises(AstralError, match="could not start"):
        run_plan(LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT), popen=fail)  # type: ignore[arg-type]

    class Stuck:
        pid = 1
        returncode = -15
        waits = 0

        def __init__(self) -> None:
            self.stdin = self

        def write(self, _value: bytes) -> None:
            return None

        def close(self) -> None:
            return None

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            self.waits += 1
            if self.waits == 1:
                raise subprocess.TimeoutExpired("x", timeout or 1.0)
            return 0

    monkeypatch.setattr("astral_project.sandbox.runner.os.killpg", lambda *_args: None)
    stuck = Stuck()
    with pytest.raises(AstralError):
        run_plan(
            LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT),
            health_check=lambda: False,
            popen=lambda *_args, **_kwargs: stuck,  # type: ignore[arg-type]
        )

    attempts = 0

    def killpg(*_args: object) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 2:
            raise ProcessLookupError()

    monkeypatch.setattr("astral_project.sandbox.runner.os.killpg", killpg)

    class TimeoutLive:
        pid = 1

        def poll(self) -> None:
            return None

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired("x", timeout or 1.0)

    _terminate(TimeoutLive())  # type: ignore[arg-type]

    class Gone:
        pid = 1

        def poll(self) -> int:
            return 0

    _terminate(Gone())  # type: ignore[arg-type]
    monkeypatch.setattr(
        "astral_project.sandbox.runner.os.killpg",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
    )

    class Live:
        pid = 1

        def poll(self) -> None:
            return None

    _terminate(Live())  # type: ignore[arg-type]


def test_session_socket_malformed_requests(tmp_path: Path) -> None:
    unstarted = SessionApiServer(
        tmp_path / "unstarted",
        session_id="s",
        describe=lambda: {},
        mounts=lambda: [],
        expiry=lambda: 1,
        close=lambda: {},
    )
    unstarted.close()
    with pytest.raises(AstralError):
        SessionApiServer(
            Path("relative"),
            session_id="s",
            describe=lambda: {},
            mounts=lambda: [],
            expiry=lambda: 1,
            close=lambda: {},
        )
    with pytest.raises(AstralError):
        SessionApiServer(
            tmp_path / "bad",
            session_id="",
            describe=lambda: {},
            mounts=lambda: [],
            expiry=lambda: 1,
            close=lambda: {},
        )
    server = SessionApiServer(
        tmp_path / "socket",
        session_id="s",
        describe=lambda: {},
        mounts=lambda: [],
        expiry=lambda: 1,
        close=lambda: {},
    )
    server._serve()
    left, right = socket.socketpair()
    try:
        left.sendall(b"{}\n")
        server._handle(right)
        assert json.loads(left.recv(4096))["ok"] is False
        left.sendall(b"not-json\n")
        server._handle(right)
        assert json.loads(left.recv(4096))["ok"] is False
    finally:
        left.close()
        right.close()
    unread, closed = socket.socketpair()
    closed.close()
    try:
        with pytest.raises(AstralError):
            _read_line(unread)
    finally:
        unread.close()

    class Chunks:
        def __init__(self) -> None:
            self.values = [b"a" * 4096, b"\n"]

        def recv(self, _size: int) -> bytes:
            return self.values.pop(0)

    assert _read_line(Chunks()) == "a" * 4096  # type: ignore[arg-type]

    class Huge:
        def recv(self, _size: int) -> bytes:
            return b"x" * 4096

    with pytest.raises(AstralError):
        _read_line(Huge())  # type: ignore[arg-type]


def test_cli_dispatches_sandbox(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.cli.run_sandbox", lambda *_args, **_kwargs: 17)
    assert (
        run(
            ["sandbox", "--network", "inherit"],
            stdout=__import__("io").StringIO(),
            stderr=__import__("io").StringIO(),
        )
        == 17
    )

    def invokes_request(*_args: object, daemon_request: object, **_kwargs: object) -> int:
        assert callable(daemon_request)
        assert daemon_request("status", None) == {"ok": True}
        return 0

    monkeypatch.setattr("astral_project.cli.run_sandbox", invokes_request)
    monkeypatch.setattr("astral_project.cli._daemon_request", lambda *_args: {"ok": True})
    assert (
        run(
            ["sandbox", "--network", "inherit"],
            stdout=__import__("io").StringIO(),
            stderr=__import__("io").StringIO(),
        )
        == 0
    )

    def fails(*_args: object, **_kwargs: object) -> int:
        raise AstralError(ErrorCode.DAEMON_AUTH, "bad", "bad", "bad", "bad")

    monkeypatch.setattr("astral_project.cli.run_sandbox", fails)
    assert (
        run(
            ["sandbox", "--network", "inherit"],
            stdout=__import__("io").StringIO(),
            stderr=__import__("io").StringIO(),
        )
        == 70
    )
