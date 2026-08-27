#!/usr/bin/env python3
"""Disposable packaged acceptance for Packets 28-29."""

from __future__ import annotations

import os
import pty
import subprocess
import sys
import tempfile
import termios
import threading
import time
from pathlib import Path
from typing import cast

from astral_project.approval.protocol import (
    ApprovalClient,
    ApprovalProtocolError,
    ApprovalRequest,
    ApprovalServer,
)
from astral_project.approval.terminal import ApprovalController
from astral_project.homed.host import BackingNode, HostReadonlyView
from astral_project.homed.lifecycle import ProjectedHomeProcess
from astral_project.homed.mediation import (
    MediationDecision,
    PendingRequest,
    RemoteUnknownPathMediator,
    UnknownPathMediator,
)
from astral_project.profile import Operation, Profile, Sensitivity
from astral_project.sandbox.command import run_sandbox
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode


def wait_pending(mediator: UnknownPathMediator, timeout: float = 3.0) -> PendingRequest:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        pending = mediator.pending()
        if pending:
            return pending[0]
        time.sleep(0.01)
    raise AssertionError("approval request did not reach trusted mediator")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aspr-approval-acceptance-") as temporary:
        base = Path(temporary)
        runtime = base / "runtime"
        fixture = base / "fixture"
        fixture.mkdir()
        (fixture / ".approved").write_text("approved", encoding="utf-8")
        (fixture / ".unknown").write_text("unknown", encoding="utf-8")
        (fixture / ".denied").write_text("denied", encoding="utf-8")
        (fixture / ".opaque").mkdir()
        (fixture / ".opaque/child").write_text("child", encoding="utf-8")
        profile = Profile.from_toml(
            """
            version = 1
            id = "acceptance"
            name = "acceptance"
            unknown_learning = "prompt"
            [[home.rules]]
            path = ".approved"
            mode = "host-ro"
            sensitivity = "configuration"
            [[home.rules]]
            path = ".opaque/child"
            mode = "host-ro"
            sensitivity = "credential"
            """
        )
        session = "acceptance-session"
        profile_path = base / "profile.toml"
        profile_path.write_text(profile.to_toml(), encoding="utf-8")
        mediator = UnknownPathMediator(timeout=5, max_pending=4, max_requests_per_session=8)
        approval_path = runtime / "approval.sock"
        server = ApprovalServer(approval_path, mediator)
        server.start()
        projected = None
        try:
            projected = ProjectedHomeProcess.start(
                runtime,
                root=fixture,
                profile=profile,
                approval_socket=approval_path,
                session_id=session,
            )
            mount = projected.mountpoint
            assert (mount / ".approved").read_text(encoding="utf-8") == "approved"
            client = ApprovalClient(approval_path)
            remote_view = HostReadonlyView(
                fixture,
                profile,
                mediator=RemoteUnknownPathMediator(str(approval_path)),
                session_id=session,
            )
            lookup_result: dict[str, object] = {}

            def lookup_unknown() -> None:
                try:
                    lookup_result["value"] = remote_view.lookup(".unknown")
                except BaseException as error:
                    lookup_result["error"] = error

            lookup_thread = threading.Thread(target=lookup_unknown)
            lookup_thread.start()
            request = wait_pending(mediator)
            assert client.approve(
                ApprovalRequest(session, request.request_number, MediationDecision.ALLOW_ONCE)
            )
            lookup_thread.join(3)
            assert "error" not in lookup_result
            assert cast(BackingNode, lookup_result["value"]).size == len("unknown")
            remote_view.close()
            denied_result: dict[str, object] = {}

            def denied_read() -> None:
                try:
                    (mount / ".denied").read_text(encoding="utf-8")
                except BaseException as error:
                    denied_result["error"] = error

            denied_thread = threading.Thread(target=denied_read)
            denied_thread.start()
            request = wait_pending(mediator)
            assert not client.approve(
                ApprovalRequest(
                    "wrong-session", request.request_number, MediationDecision.ALLOW_ONCE
                )
            )
            assert client.approve(
                ApprovalRequest(session, request.request_number, MediationDecision.DENY)
            )
            denied_thread.join(3)
            assert isinstance(denied_result.get("error"), PermissionError)
            try:
                list((mount / ".opaque").iterdir())
            except (FileNotFoundError, PermissionError):
                pass
            else:
                raise AssertionError("opaque ancestor listing was not denied")
            timeout_result = UnknownPathMediator(timeout=0.02).request(
                session_id="timeout",
                path=".timeout",
                path_component=".timeout",
                operation=Operation.READ,
                sensitivity=Sensitivity.OTHER,
            )
            assert timeout_result.decision is MediationDecision.TIMEOUT
            bounded = UnknownPathMediator(timeout=1, max_pending=1)
            bounded_thread = threading.Thread(
                target=lambda: bounded.request(
                    session_id="bounded",
                    path=".one",
                    path_component=".one",
                    operation=Operation.READ,
                    sensitivity=Sensitivity.OTHER,
                )
            )
            bounded_thread.start()
            wait_pending(bounded)
            queue_result = bounded.request(
                session_id="bounded",
                path=".two",
                path_component=".two",
                operation=Operation.READ,
                sensitivity=Sensitivity.OTHER,
            )
            assert queue_result.decision is MediationDecision.QUEUE_FULL
            bounded.cancel_session("bounded")
            bounded_thread.join(1)
            print("unknown-path-mediation=passed")
            print("timeout-and-queue-bounds=passed")
            print("exact-session-and-deny-hide=passed")
            print("opaque-ancestor-list-deny=passed")
        finally:
            if projected is not None:
                projected.close()
            server.close()

        flow_pending = threading.Event()
        flow_input_master, flow_input_slave = pty.openpty()
        flow_requests: list[PendingRequest] = []
        flow_result: dict[str, object] = {}

        def observe_flow(request: PendingRequest) -> None:
            flow_requests.append(request)
            flow_pending.set()

        def approve_flow() -> None:
            approved: set[tuple[str, int]] = set()
            try:
                while "code" not in flow_result:
                    if not flow_pending.wait(1):
                        if "code" in flow_result:
                            break
                        raise AssertionError("user-facing sandbox mediation request did not arrive")
                    flow_pending.clear()
                    for flow_request in flow_requests:
                        if flow_request.key in approved:
                            continue
                        assert flow_request.opaque_ancestor is False
                        os.write(flow_input_master, b"\x1d")
                        time.sleep(0.1)
                        os.write(flow_input_master, b"y")
                        approved.add(flow_request.key)
            except BaseException as error:
                flow_result["approval_error"] = error

        approver = threading.Thread(target=approve_flow)
        approver.start()
        flow_result["code"] = run_sandbox(
            [
                "sandbox",
                "--network",
                "none",
                "--profile",
                str(profile_path),
                "--home-root",
                str(fixture),
                "--",
                "/bin/sh",
                "-c",
                "cat /home/sandbox/.unknown >/tmp/result && test -s /tmp/result",
            ],
            daemon_request=lambda *_args: {},
            runtime=runtime,
            approval_observer=observe_flow,
            approval_input_fd=flow_input_slave,
        )
        approver.join(10)
        os.close(flow_input_master)
        os.close(flow_input_slave)
        assert "approval_error" not in flow_result
        assert flow_result.get("code") == 0
        print("sandbox-projected-mediation=passed")

        pty_mediator = UnknownPathMediator(timeout=1)
        pty_session = "pty-session"
        pty_socket = runtime / "pty-approval.sock"
        pty_server = ApprovalServer(pty_socket, pty_mediator)
        pty_server.start()
        input_fd = os.open(os.devnull, os.O_RDONLY)
        controller = ApprovalController(
            session_id=pty_session,
            mediator=pty_mediator,
            approval_socket=pty_socket,
            input_fd=input_fd,
        )
        pending_thread = threading.Thread(
            target=lambda: pty_mediator.request(
                session_id=pty_session,
                path=".terminal",
                path_component=".terminal",
                operation=Operation.READ,
                sensitivity=Sensitivity.CREDENTIAL,
            ),
            daemon=True,
        )
        pending_thread.start()
        request = wait_pending(pty_mediator)

        def approve_pty() -> None:
            for _ in range(100):
                if pty_socket.exists():
                    break
                time.sleep(0.01)
            for _ in range(100):
                try:
                    if ApprovalClient(pty_socket).approve(
                        ApprovalRequest(
                            pty_session, request.request_number, MediationDecision.ALLOW_ONCE
                        )
                    ):
                        break
                except ApprovalProtocolError:
                    time.sleep(0.01)
            else:
                raise AssertionError("PTY external approval socket did not become ready")

        approver = threading.Thread(target=approve_pty)
        approver.start()
        result = controller.run(
            [
                sys.executable,
                "-c",
                "import time; print('trusted-child', flush=True); time.sleep(.2)",
            ],
        )
        approver.join(2)
        pending_thread.join(2)
        assert result == 0
        os.close(input_fd)
        pty_server.close()
        print("trusted-pty-terminal=passed")
        print("terminal-cleanup=passed")

        guard_master, guard_slave = pty.openpty()
        before = termios.tcgetattr(guard_slave)
        try:
            crashed = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os, signal, sys; "
                        "from astral_project.approval.terminal import TerminalGuard; "
                        "guard = TerminalGuard(int(sys.argv[1])); guard.__enter__(); "
                        "os.kill(os.getpid(), signal.SIGKILL)"
                    ),
                    str(guard_slave),
                ],
                pass_fds=(guard_slave,),
            )
            assert crashed.wait(timeout=5) < 0
            time.sleep(0.3)
            assert termios.tcgetattr(guard_slave) == before
        finally:
            os.close(guard_master)
            os.close(guard_slave)
        print("terminal-guard-crash=passed")

        plan = LocalSandboxPlan(
            ("/bin/sh", "-c", 'test -z "${ASPR_APPROVAL_SOCKET-}"'), NetworkMode.NONE
        )
        subprocess.run(plan.argv(), check=True, capture_output=True)
        print("sandbox-approval-socket-absent=passed")


if __name__ == "__main__":
    main()
