from __future__ import annotations

import json
import os
import socket
import subprocess
import threading
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest
from grant_helpers import sample_grant

from astral_project.approval.terminal import ApprovalController, TerminalControllerError
from astral_project.cli import run
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import AccessMode, SignedGrant
from astral_project.crypto.keys import generate_private_key
from astral_project.homed.fuse import FuseUnavailable
from astral_project.homed.mediation import UnknownPathMediator
from astral_project.profile import (
    Profile,
    Rule,
    RuleMode,
    RuleScope,
    Sensitivity,
    SocketRule,
    WarningLevel,
)
from astral_project.sandbox.command import (
    _approval_endpoint,
    _cleanup_remote_mounts,
    _close_session,
    _ensure_session,
    _host_rx_target,
    _list_maps,
    _load_grant,
    _mounts_healthy,
    _parse_remote,
    _projected_home_inputs,
    _remove_host_rx_directory,
    _select_export,
    _session_description,
    _session_mounts,
    _session_run_ls,
    _session_show,
    _string,
    _write_host_rx_manifest,
    parse_arguments,
    run_sandbox,
)
from astral_project.sandbox.environment import EnvironmentPolicy
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode, RemoteBinding
from astral_project.sandbox.runner import _terminate, run_plan
from astral_project.sandbox.session_api import SessionApiClient, SessionApiServer, _read_line


def test_approval_endpoint_is_private_and_ephemeral(tmp_path: Path) -> None:
    socket_path, directory = _approval_endpoint(tmp_path, None)
    assert directory is not None
    assert socket_path.parent == directory
    assert directory.stat().st_mode & 0o077 == 0
    assert _approval_endpoint(tmp_path, tmp_path / "external.sock") == (
        tmp_path / "external.sock",
        None,
    )
    import shutil

    shutil.rmtree(directory)


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
    writable = parse_arguments(
        [
            "sandbox",
            "--network",
            "inherit",
            "--profile",
            "/tmp/profile.toml",
            "--home-root",
            "/tmp/home",
            "--private-root",
            "/tmp/private",
        ]
    )
    assert writable.private_root == Path("/tmp/private")
    assert writable.overlay_root is None
    composite = parse_arguments(
        [
            "sandbox",
            "--network",
            "inherit",
            "--profile",
            "/tmp/profile.toml",
            "--home-root",
            "/tmp/home",
            "--private-root",
            "/tmp/private",
            "--overlay-root",
            "/tmp/overlay",
        ]
    )
    assert composite.private_root == Path("/tmp/private")
    assert composite.overlay_root == Path("/tmp/overlay")
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network", "inherit", "--private-root"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network", "inherit", "--private-root", "/tmp/private"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network", "inherit", "--private-root", "relative"])
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
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, (binding,), session_file)
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, session_id="session-1")
    socket_path = tmp_path / "approved.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    try:
        socket_plan = LocalSandboxPlan(
            ("/bin/sh",), NetworkMode.INHERIT, socket_paths=(socket_path,)
        )
        socket_argv = socket_plan.argv()
        assert ["--bind", str(socket_path), str(socket_path)] == socket_argv[
            socket_argv.index("--bind", 20) : socket_argv.index("--bind", 20) + 3
        ]
        assert str(socket_path).encode() in socket_plan.plan_bytes()
    finally:
        listener.close()
    invalid_socket = LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT)
    object.__setattr__(invalid_socket, "socket_paths", (tmp_path / "missing.sock",))
    with pytest.raises(AstralError):
        invalid_socket.__post_init__()
    too_long_socket_path = Path("/" + "s" * 4096)
    too_long_socket = LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT)
    object.__setattr__(too_long_socket, "socket_paths", (too_long_socket_path,))
    with pytest.raises(AstralError):
        too_long_socket.plan_bytes()
    invalid_mutability = LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT)
    object.__setattr__(invalid_mutability, "projected_home_writable", "yes")
    with pytest.raises(AstralError):
        invalid_mutability.__post_init__()
    with pytest.raises(AstralError):
        LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, projected_home_writable=True)
    with_session = LocalSandboxPlan(
        ("/bin/sh",), NetworkMode.INHERIT, (binding,), session_file, "session-1"
    )
    assert "/run/astral-project/session.sock" in with_session.argv()
    assert "ASPR_SESSION_ID" in with_session.argv()
    assert str(session_file).encode() in with_session.plan_bytes()

    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)
    projected = LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, projected_home=tmp_path)
    assert ["--ro-bind", str(tmp_path), "/home/sandbox"] == projected.argv()[
        projected.argv().index("--ro-bind", 10) : projected.argv().index("--ro-bind", 10) + 3
    ]
    assert str(tmp_path).encode() in projected.plan_bytes()
    writable_projected = LocalSandboxPlan(
        ("/bin/sh",),
        NetworkMode.INHERIT,
        projected_home=tmp_path,
        projected_home_writable=True,
    )
    assert "--bind" in writable_projected.argv()
    assert (
        "--ro-bind"
        not in writable_projected.argv()[writable_projected.argv().index(str(tmp_path)) - 1]
    )
    assert writable_projected.plan_bytes().endswith(b"\x01\x00")
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: False)
    with pytest.raises(AstralError, match="projected home"):
        LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT, projected_home=tmp_path)

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
    too_long_projected = LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT)
    object.__setattr__(too_long_projected, "projected_home", Path("/" + "p" * 4096))
    with pytest.raises(AstralError):
        too_long_projected.plan_bytes()


def test_host_rx_requires_profile_authorization_and_private_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = Profile(
        version=1,
        profile_id="host-rx",
        name="host-rx",
        rules=(Rule("tool", RuleScope.EXACT, RuleMode.HOST_RX),),
    )
    target = _host_rx_target(profile, ("/home/sandbox/tool", "--flag"))
    assert target == "/home/sandbox/tool"
    assert _write_host_rx_manifest(tmp_path, None) == (None, None)
    with pytest.raises(AstralError, match="host-rx"):
        _host_rx_target(profile, ("/home/sandbox/other",))
    with pytest.raises(AstralError, match="explicit profile"):
        _host_rx_target(None, ("/home/sandbox/tool",))

    manifest, directory = _write_host_rx_manifest(tmp_path, target)
    assert manifest is not None and directory is not None
    try:
        assert manifest.read_text(encoding="utf-8") == "/home/sandbox/tool\n"
        assert manifest.stat().st_mode & 0o777 == 0o644
        monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)
        plan = LocalSandboxPlan(
            (target, "--flag"),
            NetworkMode.INHERIT,
            projected_home=tmp_path,
            host_rx_manifest=manifest,
        )
        assert str(manifest).encode() in plan.plan_bytes()
        assert ["--ro-bind", str(manifest), "/tmp/aspr-host-rx.allow"] == plan.argv()[
            plan.argv().index(str(manifest)) - 1 : plan.argv().index(str(manifest)) + 2
        ]
        with pytest.raises(AstralError, match="manifest is unavailable"):
            LocalSandboxPlan(
                (target,),
                NetworkMode.INHERIT,
                projected_home=tmp_path,
                host_rx_manifest=tmp_path / "missing.allow",
            )
        with pytest.raises(AstralError, match="manifest is unsafe"):
            LocalSandboxPlan(
                ("/bin/true",),
                NetworkMode.INHERIT,
                projected_home=tmp_path,
                host_rx_manifest=manifest,
            )
        object.__setattr__(plan, "host_rx_manifest", Path("/" + "m" * 4096))
        with pytest.raises(AstralError, match="manifest path is too long"):
            plan.plan_bytes()
    finally:
        import shutil

        shutil.rmtree(directory)
    orphan = tmp_path / "orphan"
    orphan.mkdir()
    _remove_host_rx_directory(orphan)
    assert not orphan.exists()
    _remove_host_rx_directory(None)
    monkeypatch.setattr("astral_project.sandbox.command.os.write", lambda *_args: 0)
    with pytest.raises(AstralError, match="could not be written"):
        _write_host_rx_manifest(tmp_path, target)


def test_sandbox_argument_and_plan_rejections(tmp_path: Path) -> None:
    for args in (
        ["sandbox"],
        ["sandbox", "--network", "bad"],
        ["sandbox", "--network", "inherit", "--"],
        ["sandbox", "--network", "inherit", "--grant"],
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
        run_ls=lambda payload: {"echo": payload["target"]},
    )
    server.start()
    try:

        def request(
            method: str, session_id: str = "s1", payload: dict[str, object] | None = None
        ) -> dict[str, object]:
            body: dict[str, object] = {"method": method, "session_id": session_id}
            if payload is not None:
                body["payload"] = payload
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(path))
                client.sendall(json.dumps(body).encode() + b"\n")
                return cast(dict[str, object], json.loads(client.recv(4096)))

        def raw(body: object) -> dict[str, object]:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(str(path))
                client.sendall(json.dumps(body).encode() + b"\n")
                return cast(dict[str, object], json.loads(client.recv(4096)))

        assert raw([])["ok"] is False
        assert raw({"method": "RunLs", "session_id": "s1"})["ok"] is False
        assert (
            raw({"method": "RunLs", "session_id": "s1", "payload": [], "extra": 1})["ok"] is False
        )
        assert request("DescribeSession")["ok"] is True
        assert request("RunLs", payload={"target": "/docs"})["ok"] is True
        assert request("GetRemoteMounts")["ok"] is True
        assert request("GetExpiry")["ok"] is True
        assert request("CloseOwnSession")["ok"] is True
        client = SessionApiClient(path, session_id="s1", timeout=1)
        assert client.request("RunLs", {"target": "/docs"})["echo"] == "/docs"
        with pytest.raises(AstralError):
            client.request("RunLs")
        with pytest.raises(AstralError):
            client.request("GetExpiry", {"unexpected": True})
        assert request("CreateMount")["ok"] is False
        assert request("RunLs")["ok"] is False
        assert request("GetExpiry", payload={"unexpected": True})["ok"] is False
        assert request("GetExpiry", "other")["ok"] is False
    finally:
        server.close()
    with pytest.raises(AstralError):
        SessionApiClient(tmp_path / "missing.sock", session_id="s1", timeout=1).request("GetExpiry")
    with pytest.raises(AstralError):
        SessionApiClient(Path("relative.sock"), session_id="s1")
    unavailable_path = tmp_path / "unavailable.sock"
    unavailable = SessionApiServer(
        unavailable_path,
        session_id="s1",
        describe=lambda: {},
        mounts=lambda: [],
        expiry=lambda: 1,
        close=lambda: {},
    )
    unavailable.start()
    try:
        with pytest.raises(AstralError, match="unavailable"):
            SessionApiClient(unavailable_path, session_id="s1", timeout=1).request(
                "RunLs", {"target": "/docs"}
            )
    finally:
        unavailable.close()

    def client_response(response: bytes) -> None:
        response_path = tmp_path / f"response-{len(response)}.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(response_path))
        listener.listen(1)

        def serve() -> None:
            connection, _ = listener.accept()
            with connection:
                connection.recv(4096)
                connection.sendall(response)
            listener.close()
            response_path.unlink(missing_ok=True)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            client = SessionApiClient(response_path, session_id="s1", timeout=1)
            yield_error = None
            try:
                client.request("GetExpiry")
            except AstralError as error:
                yield_error = error
            assert yield_error is not None
        finally:
            thread.join(timeout=1)

    client_response(b"not-json\n")
    client_response(b'{"ok":false,"error":{"message":"rejected"}}\n')
    client_response(b'{"ok":true,"result":[]}\n')


def test_cleanup_never_traverses_uncertain_remote_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mount_path = tmp_path / "mounted"
    mount_path.mkdir()
    content = mount_path / "remote-file"
    content.write_text("must survive", encoding="utf-8")
    monkeypatch.setattr(Path, "is_mount", lambda _path: True)

    def failed_close(_operation: str, _payload: object = None) -> dict[str, object]:
        raise AstralError(ErrorCode.DAEMON_UNAVAILABLE, "close failed", "x", "x", "x")

    error = _cleanup_remote_mounts(["rw-mount"], [mount_path], failed_close)
    assert error is not None
    assert "close failed" in error.message
    assert content.read_text(encoding="utf-8") == "must survive"
    assert mount_path.is_dir()


def test_cleanup_removes_only_verified_detached_directory(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _cleanup_remote_mounts([], [empty], lambda *_args: {}) is None
    assert not empty.exists()

    missing = tmp_path / "missing"
    assert _cleanup_remote_mounts([], [missing], lambda *_args: {}) is None

    nonempty = tmp_path / "nonempty"
    nonempty.mkdir()
    (nonempty / "local").write_text("x", encoding="utf-8")
    error = _cleanup_remote_mounts([], [nonempty], lambda *_args: {})
    assert error is not None
    assert nonempty.exists()


def test_cleanup_reports_mount_state_probe_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mount_path = tmp_path / "unknown"
    mount_path.mkdir()
    monkeypatch.setattr(
        Path,
        "is_mount",
        lambda _path: (_ for _ in ()).throw(OSError("mount probe failed")),
    )
    error = _cleanup_remote_mounts([], [mount_path], lambda *_args: {})
    assert error is not None
    assert "cannot verify" in error.message
    assert mount_path.exists()


def test_sandbox_remote_orchestration_closes_owned_resources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)
    monkeypatch.setattr(Path, "is_mount", lambda _path: False)
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

    class Projected:
        mountpoint = tmp_path / "projected"
        closed = False

        def close(self) -> None:
            self.closed = True

    projected = Projected()
    projected.mountpoint.mkdir()
    home_root = tmp_path / "home"
    home_root.mkdir()
    profile_path = tmp_path / "profile.toml"
    profile_path.write_text('version = 1\nid = "p"\nname = "p"\n', encoding="utf-8")
    monkeypatch.setattr(
        "astral_project.sandbox.command._start_projected_home",
        lambda *_args, **_kwargs: projected,
    )
    monkeypatch.setattr("astral_project.sandbox.command.run_plan", lambda *args, **kwargs: 0)
    assert (
        run_sandbox(
            [
                "sandbox",
                "--network",
                "inherit",
                "--grant",
                "g1",
                "--profile",
                str(profile_path),
                "--home-root",
                str(home_root),
                "--approval-socket",
                str(tmp_path / "approval.sock"),
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
    assert projected.closed

    calls.clear()
    assert (
        run_sandbox(
            ["sandbox", "--network", "inherit", "--grant", "g1"],
            daemon_request=request,
            runtime=tmp_path,
        )
        == 0
    )
    shorthand_mount = next(payload for name, payload in calls if name == "mount.open")
    assert isinstance(shorthand_mount, dict)
    assert shorthand_mount["source_path"] == "/scratch/alice/project"
    assert shorthand_mount["virtual_target"] == "/project"

    calls.clear()
    assert (
        run_sandbox(
            [
                "sandbox",
                "--network",
                "inherit",
                "--grant",
                "g1",
                "--remote",
                "/scratch/alice/project/src=/src",
            ],
            daemon_request=request,
            runtime=tmp_path,
        )
        == 0
    )
    descendant_mount = next(payload for name, payload in calls if name == "mount.open")
    assert isinstance(descendant_mount, dict)
    assert descendant_mount["virtual_target"] == "/project/src"

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
    monkeypatch.setattr(Path, "is_mount", lambda _path: True)
    with pytest.raises(AstralError, match="remains attached"):
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


def test_sandbox_private_helpers_and_rejections(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for value in ("", "x/y", "bad=/target", ":/source=/target", "source=/target", "/source=target"):
        with pytest.raises(AstralError):
            _parse_remote(value)
    for value in ("/source/../child=/target", "/source=/target/"):
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
        parse_arguments(["sandbox", "--network", "inherit", "--approval-socket", "relative"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network", "inherit", "--approval-socket"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network", "inherit", "--profile"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network", "inherit", "--profile", "relative.toml"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network", "inherit", "--home-root"])
    with pytest.raises(AstralError):
        parse_arguments(["sandbox", "--network", "inherit", "--home-root", "relative"])
    parsed = parse_arguments(
        ["sandbox", "--network", "inherit", "--approval-socket", "/run/user/approval.sock"]
    )
    assert parsed.approval_socket == Path("/run/user/approval.sock")
    profile_args = parse_arguments(
        [
            "sandbox",
            "--network",
            "inherit",
            "--profile",
            "/tmp/profile.toml",
            "--home-root",
            "/tmp/home",
        ]
    )
    assert profile_args.profile_path == Path("/tmp/profile.toml")
    assert profile_args.home_root == Path("/tmp/home")
    with pytest.raises(AstralError, match="provided together"):
        parse_arguments(["sandbox", "--network", "inherit", "--profile", "/tmp/profile.toml"])
    home_root = tmp_path / "home"
    home_root.mkdir()
    profile_path = tmp_path / "profile.toml"
    profile_path.write_text('version = 1\nid = "p"\nname = "p"\n', encoding="utf-8")
    raw_profile = tmp_path / "raw-profile.toml"
    raw_profile.write_text(
        'version = 1\nid = "raw"\nname = "raw"\nraw_socket = true\n', encoding="utf-8"
    )

    def empty_daemon_request(
        _operation: str, _payload: Mapping[str, object] | None = None
    ) -> dict[str, object]:
        return {}

    with pytest.raises(AstralError, match="raw socket"):
        run_sandbox(
            [
                "sandbox",
                "--network",
                "inherit",
                "--profile",
                str(raw_profile),
                "--home-root",
                str(home_root),
            ],
            daemon_request=empty_daemon_request,
            runtime=tmp_path,
        )
    projected_args = parse_arguments(
        [
            "sandbox",
            "--network",
            "inherit",
            "--profile",
            str(profile_path),
            "--home-root",
            str(home_root),
        ]
    )
    loaded_profile, loaded_root = _projected_home_inputs(projected_args)
    assert loaded_profile is not None and loaded_root == home_root
    with pytest.raises(AstralError, match="home root"):
        _projected_home_inputs(
            parse_arguments(
                [
                    "sandbox",
                    "--network",
                    "inherit",
                    "--profile",
                    str(profile_path),
                    "--home-root",
                    str(tmp_path / "missing"),
                ]
            )
        )
    profile_path.write_text("not valid = [", encoding="utf-8")
    with pytest.raises(AstralError, match="profile"):
        _projected_home_inputs(
            parse_arguments(
                [
                    "sandbox",
                    "--network",
                    "inherit",
                    "--profile",
                    str(profile_path),
                    "--home-root",
                    str(home_root),
                ]
            )
        )
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


def test_run_plan_approval_controller_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = LocalSandboxPlan(("/bin/sh",), NetworkMode.INHERIT)
    controller = ApprovalController(session_id="s", mediator=UnknownPathMediator())
    monkeypatch.setattr(controller, "run", lambda *_args, **_kwargs: 4)
    assert run_plan(plan, approval=controller) == 4
    with pytest.raises(AstralError):
        run_plan(plan, approval=object())

    def fail(*_args: object, **_kwargs: object) -> int:
        raise TerminalControllerError("broken terminal")

    monkeypatch.setattr(controller, "run", fail)
    with pytest.raises(AstralError) as error:
        run_plan(plan, approval=controller)
    assert error.value.code is ErrorCode.DAEMON_UNAVAILABLE


def test_sandbox_command_error_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.sandbox.command.run_plan", lambda *_args, **_kwargs: 0)

    class FakeProjected:
        mountpoint = tmp_path / "projected"
        closed = False

        def close(self) -> None:
            self.closed = True

    fake = FakeProjected()
    fake.mountpoint.mkdir()
    started: dict[str, object] = {}
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)

    def start(_runtime: Path, **kwargs: object) -> FakeProjected:
        started.update(kwargs)
        return fake

    profile_path = tmp_path / "profile.toml"
    profile_path.write_text('version = 1\nid = "p"\nname = "p"\n', encoding="utf-8")
    monkeypatch.setattr("astral_project.sandbox.command.ProjectedHomeProcess.start", start)
    assert (
        run_sandbox(
            ["sandbox", "--network", "inherit"], daemon_request=lambda *_args: {}, runtime=tmp_path
        )
        == 0
    )
    assert fake.closed
    private_root = tmp_path / "private-root"
    assert (
        run_sandbox(
            [
                "sandbox",
                "--network",
                "inherit",
                "--profile",
                str(profile_path),
                "--home-root",
                str(tmp_path),
                "--private-root",
                str(private_root),
            ],
            daemon_request=lambda *_args: {},
            runtime=tmp_path,
        )
        == 0
    )
    assert started["storage_root"] == private_root
    profile_path.write_text(
        'version = 1\nid = "p"\nname = "p"\n[environment]\nallow = ["LANG"]\nunset = ["TERM"]\n',
        encoding="utf-8",
    )
    assert (
        run_sandbox(
            [
                "sandbox",
                "--network",
                "inherit",
                "--profile",
                str(profile_path),
                "--home-root",
                str(tmp_path),
            ],
            daemon_request=lambda *_args: {},
            runtime=tmp_path,
        )
        == 0
    )
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: False)

    def unavailable(_runtime: Path, **_kwargs: object) -> object:
        raise FuseUnavailable("missing")

    monkeypatch.setattr("astral_project.sandbox.command.ProjectedHomeProcess.start", unavailable)
    assert (
        run_sandbox(
            ["sandbox", "--network", "inherit"], daemon_request=lambda *_args: {}, runtime=tmp_path
        )
        == 0
    )
    home_root = tmp_path / "home-root"
    home_root.mkdir()
    with pytest.raises(AstralError, match="projected home"):
        run_sandbox(
            [
                "sandbox",
                "--network",
                "inherit",
                "--profile",
                str(profile_path),
                "--home-root",
                str(home_root),
            ],
            daemon_request=lambda *_args: {},
            runtime=tmp_path,
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


def test_session_helpers_bind_scope_and_hide_host_fields() -> None:
    signed = SignedGrant.create(sample_grant(), generate_private_key())
    export, virtual = _select_export(signed, "/scratch/alice/project/child")
    assert export.requested_source == "/scratch/alice/project"
    assert virtual == "/project/child"
    root_export = replace(
        signed.grant.exports[0],
        requested_source="/",
        canonical_source="/",
        virtual_target="/",
    )
    root_signed = SignedGrant.create(
        replace(signed.grant, exports=(root_export,)), generate_private_key()
    )
    assert _select_export(root_signed, "/child")[1] == "/child"
    assert _select_export(root_signed, "/child/grandchild")[1] == "/child/grandchild"
    with pytest.raises(AstralError):
        _select_export(signed, "/not-granted")
    with pytest.raises(AstralError):
        _parse_remote("/child/../other=/target")
    duplicate = replace(signed.grant, exports=(signed.grant.exports[0], signed.grant.exports[0]))
    with pytest.raises(AstralError, match="ambiguous"):
        _select_export(
            SignedGrant.create(duplicate, generate_private_key()), "/scratch/alice/project/child"
        )
    _root, root_target = _select_export(root_signed, "/")
    assert root_target == "/"

    mount_values = _session_mounts(
        "s1",
        lambda *_args: {
            "mounts": [
                {"session_id": "other", "mount_id": "hidden", "state": "ready"},
                {
                    "session_id": "s1",
                    "mount_id": "hidden",
                    "state": "ready",
                    "mode": "ro",
                    "virtual_target": "/project",
                    "config_path": "/secret",
                },
            ]
        },
    )
    assert mount_values == [{"state": "ready", "mode": "ro", "virtual_target": "/project"}]
    description = _session_description(
        "s1",
        lambda *_args: {
            "session_id": "s1",
            "grant_id": "g1",
            "state": "active",
            "expires_at": 10,
            "host_metadata": {"identity_file": "/secret"},
        },
    )
    assert description == {
        "session_id": "s1",
        "grant_id": "g1",
        "state": "active",
        "expires_at": 10,
    }
    observed: dict[str, object] = {}
    result = _session_run_ls(
        signed,
        {
            "target": "/project/child",
            "filters": [],
            "json_output": False,
            "max_depth": None,
            "no_header": False,
            "raw_output": False,
            "recursive": False,
            "reverse": False,
            "sort": "path",
            "stat": False,
            "timeout_seconds": None,
        },
        lambda operation, payload: (
            observed.update(operation=operation, payload=payload) or {"ok": True}
        ),
    )
    assert result == {"ok": True}
    assert observed["operation"] == "ls"
    assert str(signed.grant.grant_id) in str(observed["payload"])


def test_grant_shorthand_rejects_multiple_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    signed = SignedGrant.create(
        replace(sample_grant(), exports=(sample_grant().exports[0], sample_grant().exports[0])),
        generate_private_key(),
    )
    monkeypatch.setattr("astral_project.sandbox.command._load_grant", lambda *_args: signed)
    with pytest.raises(AstralError, match="exactly one"):
        run_sandbox(
            ["sandbox", "--network", "inherit", "--grant", "g"],
            daemon_request=lambda *_args: {},
            runtime=tmp_path,
        )


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


def test_run_sandbox_host_rx_creates_then_removes_exact_manifest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    profile_path = tmp_path / "profile.toml"
    profile_path.write_text(
        Profile(
            1,
            "host-rx-run",
            "host-rx-run",
            rules=(Rule("tool", RuleScope.EXACT, RuleMode.HOST_RX),),
        ).to_toml(),
        encoding="utf-8",
    )
    mountpoint = tmp_path / "mountpoint"
    mountpoint.mkdir()

    class Projected:
        def close(self) -> None:
            return None

    projected = Projected()
    projected.mountpoint = mountpoint  # type: ignore[attr-defined]
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)
    monkeypatch.setattr(
        "astral_project.sandbox.command._start_projected_home",
        lambda *_args, **_kwargs: projected,
    )
    observed: dict[str, Path | None] = {}

    def capture_plan(plan: LocalSandboxPlan, **_kwargs: object) -> int:
        observed["manifest"] = plan.host_rx_manifest
        assert plan.host_rx_manifest is not None and plan.host_rx_manifest.is_file()
        assert plan.host_rx_manifest.read_text(encoding="utf-8") == "/home/sandbox/tool\n"
        return 0

    monkeypatch.setattr("astral_project.sandbox.command.run_plan", capture_plan)
    assert (
        run_sandbox(
            [
                "sandbox",
                "--network",
                "none",
                "--profile",
                str(profile_path),
                "--home-root",
                str(home),
                "--",
                "/home/sandbox/tool",
            ],
            daemon_request=lambda *_args: {},
            runtime=tmp_path,
        )
        == 0
    )
    assert observed["manifest"] is not None and not observed["manifest"].exists()


def test_run_sandbox_excludes_credential_sensitive_socket_without_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = tmp_path / "credential.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    home = tmp_path / "home"
    home.mkdir()
    profile_path = tmp_path / "profile.toml"
    profile_path.write_text(
        Profile(
            1,
            "credential-socket",
            "credential-socket",
            sockets=(SocketRule(str(socket_path), Sensitivity.CREDENTIAL, WarningLevel.STRONG),),
        ).to_toml(),
        encoding="utf-8",
    )
    mountpoint = tmp_path / "mountpoint"
    mountpoint.mkdir()

    class Projected:
        def close(self) -> None:
            return None

    projected = Projected()
    projected.mountpoint = mountpoint  # type: ignore[attr-defined]
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)
    monkeypatch.setattr(
        "astral_project.sandbox.command._start_projected_home",
        lambda *_args, **_kwargs: projected,
    )
    plans: list[LocalSandboxPlan] = []

    def capture_plan(plan: LocalSandboxPlan, **_kwargs: object) -> int:
        plans.append(plan)
        return 0

    monkeypatch.setattr("astral_project.sandbox.command.run_plan", capture_plan)
    try:
        assert (
            run_sandbox(
                [
                    "sandbox",
                    "--network",
                    "none",
                    "--profile",
                    str(profile_path),
                    "--home-root",
                    str(home),
                ],
                daemon_request=lambda *_args: {},
                runtime=tmp_path,
            )
            == 0
        )
    finally:
        listener.close()
    assert plans and plans[0].socket_paths == ()


def test_run_plan_supplies_visible_path_roots_to_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    visible = tmp_path / "visible"
    hidden = tmp_path / "hidden"
    visible.mkdir()
    hidden.mkdir()
    monkeypatch.setattr("astral_project.sandbox.plan.os.path.ismount", lambda _path: True)
    plan = LocalSandboxPlan(("/bin/true",), NetworkMode.INHERIT, projected_home=visible)
    captured: dict[str, object] = {}

    class Finished:
        returncode = 0

        def __init__(self) -> None:
            self.stdin = self

        def write(self, _value: bytes) -> None:
            return None

        def close(self) -> None:
            return None

        def poll(self) -> int:
            return self.returncode

    def popen(*_args: object, **kwargs: object) -> Finished:
        captured.update(kwargs)
        return Finished()

    monkeypatch.setenv("PATH", f"{visible}{os.pathsep}{hidden}")
    result = run_plan(
        plan,
        environment_policy=EnvironmentPolicy(allowed_names=frozenset({"PATH"})),
        popen=popen,  # type: ignore[arg-type]
    )
    assert result == 0
    environment = cast(dict[str, str], captured["env"])
    assert environment["PATH"] == str(visible)


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
