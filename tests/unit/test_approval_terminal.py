from __future__ import annotations

import io
import os
import pty
import signal
import subprocess
import sys
import termios
import threading
import time
from pathlib import Path

import pytest

from astral_project.approval.protocol import ApprovalClient, ApprovalRequest
from astral_project.approval.terminal import (
    ApprovalController,
    TerminalControllerError,
    TerminalGuard,
)
from astral_project.homed.mediation import (
    MediationDecision,
    UnknownPathMediator,
)
from astral_project.profile import Operation, Sensitivity


def _request(mediator: UnknownPathMediator) -> int:
    def wait() -> None:
        mediator.request(
            session_id="session",
            path=".secret",
            path_component=".secret",
            operation=Operation.READ,
            sensitivity=Sensitivity.CREDENTIAL,
        )

    threading.Thread(target=wait, daemon=True).start()
    for _ in range(100):
        if mediator.pending():
            return mediator.pending()[0].request_number
        time.sleep(0.001)
    raise AssertionError("pending request was not created")


def test_terminal_guard_on_non_tty_and_controller_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    read_fd, write_fd = os.pipe()
    try:
        with TerminalGuard(read_fd):
            pass
    finally:
        os.close(read_fd)
        os.close(write_fd)
    master, slave = pty.openpty()

    def fail_fork() -> int:
        raise OSError("fork")

    monkeypatch.setattr(os, "fork", fail_fork)
    try:
        with TerminalGuard(slave):
            pass
    finally:
        os.close(master)
        os.close(slave)
    with pytest.raises(TerminalControllerError):
        ApprovalController(
            session_id="",
            mediator=UnknownPathMediator(),
        )
    with pytest.raises(TerminalControllerError):
        ApprovalController(session_id="s", mediator=UnknownPathMediator()).run(())


def test_parent_pty_relay_external_approval_and_buffered_output(tmp_path: Path) -> None:
    mediator = UnknownPathMediator(timeout=2)
    number = _request(mediator)
    output = io.BytesIO()
    socket_path = tmp_path / "approval.sock"
    controller = ApprovalController(
        session_id="session",
        mediator=mediator,
        approval_socket=socket_path,
        input_fd=os.open(os.devnull, os.O_RDONLY),
        output=output,
    )

    def approve() -> None:
        for _ in range(100):
            if socket_path.exists():
                break
            time.sleep(0.01)
        assert ApprovalClient(socket_path).approve(
            ApprovalRequest("session", number, MediationDecision.ALLOW_ONCE)
        )

    thread = threading.Thread(target=approve)
    thread.start()
    try:
        assert (
            controller.run(
                [
                    sys.executable,
                    "-c",
                    "import time; print('child-output', flush=True); time.sleep(.3)",
                ]
            )
            == 0
        )
    finally:
        os.close(controller.input_fd)
    thread.join(5)
    assert b"child-output" in output.getvalue()
    assert not socket_path.exists()


def test_terminal_escape_enters_trusted_transition_and_child_cannot_approve() -> None:
    mediator = UnknownPathMediator(timeout=2)
    _request(mediator)
    input_master, input_slave = pty.openpty()
    output = io.BytesIO()
    controller = ApprovalController(
        session_id="session",
        mediator=mediator,
        input_fd=input_slave,
        output=output,
    )

    def interact() -> None:
        time.sleep(0.05)
        os.write(input_master, b"z")
        time.sleep(0.05)
        os.write(input_master, b"\x1d")
        time.sleep(0.5)
        os.write(input_master, b"y")

    thread = threading.Thread(target=interact)
    thread.start()
    try:
        assert (
            controller.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import time; time.sleep(.2); "
                        "print('child-output', flush=True); time.sleep(.4)"
                    ),
                ]
            )
            == 0
        )
    finally:
        os.close(input_master)
        os.close(input_slave)
    thread.join(2)
    assert b"approval required" in output.getvalue()
    assert b"child-output" in output.getvalue()


def test_full_screen_child_output_survives_parent_pty_relay() -> None:
    input_fd = os.open(os.devnull, os.O_RDONLY)
    output = io.BytesIO()
    controller = ApprovalController(
        session_id="screen", mediator=UnknownPathMediator(), input_fd=input_fd, output=output
    )
    try:
        assert (
            controller.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import curses, time; "
                        "curses.wrapper(lambda screen: (screen.addstr(0, 0, "
                        "'full-screen'), screen.refresh(), time.sleep(.05)))"
                    ),
                ],
                env={"PATH": os.environ["PATH"], "TERM": "xterm-256color"},
            )
            == 0
        )
    finally:
        os.close(input_fd)
    assert b"full-screen" in output.getvalue()


def test_terminal_buffer_cap_discards_excess_output(monkeypatch: pytest.MonkeyPatch) -> None:
    mediator = UnknownPathMediator(timeout=2)
    _request(mediator)
    input_master, input_slave = pty.openpty()
    output = io.BytesIO()
    controller = ApprovalController(
        session_id="session", mediator=mediator, input_fd=input_slave, output=output
    )
    monkeypatch.setattr("astral_project.approval.terminal._MAX_BUFFER", 1)

    def interact() -> None:
        time.sleep(0.05)
        os.write(input_master, b"\x1d")
        time.sleep(0.4)
        os.write(input_master, b"y")

    thread = threading.Thread(target=interact)
    thread.start()
    try:
        assert (
            controller.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import time; time.sleep(.2); "
                        "print('long-output', flush=True); time.sleep(.1); "
                        "print('second-output', flush=True); time.sleep(.8)"
                    ),
                ]
            )
            == 0
        )
    finally:
        os.close(input_master)
        os.close(input_slave)
    thread.join(2)
    assert b"approval required" in output.getvalue()


def test_terminal_private_controls_cover_signals_resize_and_decisions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mediator = UnknownPathMediator(timeout=2)
    controller = ApprovalController(session_id="session", mediator=mediator, output=io.BytesIO())
    killed: list[int] = []
    writes: list[bytes] = []

    def fake_kill(pid: int, value: int) -> None:
        killed.append(pid + value)

    def fake_write(_fd: int, data: bytes) -> int:
        writes.append(data)
        return len(data)

    monkeypatch.setattr(os, "killpg", fake_kill)
    monkeypatch.setattr(os, "write", fake_write)
    controller._forward_input(10, 11, b"\x03")
    controller._forward_input(10, 11, b"\x1a")
    controller._forward_input(10, 11, b"abc")
    controller._forward_input(10, 11, b"\x1d\x1d")
    assert killed == [10 + signal.SIGINT, 10 + signal.SIGTSTP]
    assert controller.output.getvalue().count(b"child input stopped") == 1  # type: ignore[union-attr]

    _request(mediator)
    request = mediator.pending()[0]
    controller._handle_decision(request, b"n")
    assert not mediator.pending()
    assert controller._pending_request() is None
    time.sleep(0.02)
    request_number = _request(mediator)
    request = mediator.pending()[0]
    controller._handle_decision(request, b"x")
    assert mediator.pending()
    controller._handle_decision(request, b"h")
    assert request.request_number == request_number
    assert not mediator.pending()
    monkeypatch.setattr(
        "astral_project.approval.terminal.shutil.get_terminal_size",
        lambda _size: os.terminal_size((90, 30)),
    )
    ioctl_values: list[bytes] = []
    monkeypatch.setattr(
        "astral_project.approval.terminal.fcntl.ioctl",
        lambda _fd, _op, value: ioctl_values.append(value),
    )
    controller._resize(1)
    assert ioctl_values
    controller._on_winch(0, None)
    assert controller._resize_pending
    no_output = ApprovalController(session_id="s", mediator=UnknownPathMediator())
    monkeypatch.setattr(os, "write", fake_write)
    no_output._write(b"direct")
    assert writes[-1] == b"direct"


def test_controller_binary_preface_survives_pty_line_discipline() -> None:
    input_fd = os.open(os.devnull, os.O_RDONLY)
    controller = ApprovalController(
        session_id="session", mediator=UnknownPathMediator(), input_fd=input_fd, output=io.BytesIO()
    )
    try:
        assert (
            controller.run(
                [
                    sys.executable,
                    "-c",
                    "import sys; assert sys.stdin.buffer.readline().startswith(b'ASPRB64\\n')",
                ],
                preface=b"ASPRSB01\x16/",
            )
            == 0
        )
    finally:
        os.close(input_fd)


def test_controller_preface_transport_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "astral_project.approval.terminal.termios.tcgetattr",
        lambda _fd: (_ for _ in ()).throw(termios.error("not a tty")),
    )
    monkeypatch.setattr("astral_project.approval.terminal.os.write", lambda *_args: 0)
    with pytest.raises(TerminalControllerError):
        ApprovalController._write_preface(0, b"metadata")


def test_controller_preface_and_resize_paths() -> None:
    input_fd = os.open(os.devnull, os.O_RDONLY)
    output = io.BytesIO()
    controller = ApprovalController(
        session_id="session", mediator=UnknownPathMediator(), input_fd=input_fd, output=output
    )
    controller._resize_pending = True
    try:
        assert (
            controller.run([sys.executable, "-c", "import sys; sys.stdin.read(1)"], preface=b"x\n")
            == 0
        )
    finally:
        os.close(input_fd)


def test_terminal_guard_crash_without_reaping_or_saved_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guard = TerminalGuard(0)
    guard._guard_pid = 123
    monkeypatch.setattr(
        os,
        "waitpid",
        lambda *_args: (_ for _ in ()).throw(ChildProcessError()),
    )
    with pytest.raises(TerminalControllerError, match="guard exited"):
        guard.ensure_alive()


def test_terminal_guard_detects_guard_crash_and_restores() -> None:
    input_master, input_slave = pty.openpty()
    before = termios.tcgetattr(input_slave)
    guard = TerminalGuard(input_slave)
    guard.__enter__()
    assert guard._guard_pid is not None
    os.kill(guard._guard_pid, signal.SIGKILL)
    time.sleep(0.1)
    try:
        with pytest.raises(TerminalControllerError, match="guard exited"):
            guard.ensure_alive()
        assert termios.tcgetattr(input_slave) == before
    finally:
        guard.restore()
        os.close(input_master)
        os.close(input_slave)


def test_terminal_controller_forwards_sigcont_after_child_suspend() -> None:
    input_fd = os.open(os.devnull, os.O_RDONLY)
    output = io.BytesIO()
    controller = ApprovalController(
        session_id="session", mediator=UnknownPathMediator(), input_fd=input_fd, output=output
    )

    def resume_parent() -> None:
        time.sleep(0.2)
        os.kill(os.getpid(), signal.SIGCONT)

    thread = threading.Thread(target=resume_parent)
    thread.start()
    try:
        assert (
            controller.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os, signal; os.kill(os.getpid(), signal.SIGSTOP); "
                        "print('resumed', flush=True)"
                    ),
                ]
            )
            == 0
        )
    finally:
        thread.join(2)
        os.close(input_fd)
    assert b"resumed" in output.getvalue()


def test_terminal_guard_restores_after_parent_sigkill() -> None:
    input_master, input_slave = pty.openpty()
    before = termios.tcgetattr(input_slave)
    try:
        process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import os, signal, sys; "
                    "from astral_project.approval.terminal import TerminalGuard; "
                    "guard = TerminalGuard(int(sys.argv[1])); "
                    "guard.__enter__(); os.kill(os.getpid(), signal.SIGKILL)"
                ),
                str(input_slave),
            ],
            pass_fds=(input_slave,),
        )
        assert process.wait(timeout=3) < 0
        time.sleep(0.3)
        assert termios.tcgetattr(input_slave) == before
    finally:
        os.close(input_master)
        os.close(input_slave)


def test_controller_health_and_exec_failures_restore_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    controller = ApprovalController(
        session_id="session",
        mediator=UnknownPathMediator(),
        output=io.BytesIO(),
        input_fd=os.open(os.devnull, os.O_RDONLY),
    )
    try:
        with pytest.raises(TerminalControllerError):
            controller.run(
                [sys.executable, "-c", "import time; time.sleep(1)"], health_check=lambda: False
            )
        try:
            result = controller.run(["/no/such/child"])
        except TerminalControllerError:
            pass
        else:
            assert result >= 0
    finally:
        os.close(controller.input_fd)
    monkeypatch.setattr(
        "astral_project.approval.terminal.pty.fork",
        lambda: (_ for _ in ()).throw(OSError("fork")),
    )
    with pytest.raises(TerminalControllerError):
        controller.run([sys.executable, "-c", "pass"])


def test_controller_does_not_publish_socket_to_child(tmp_path: Path) -> None:
    mediator = UnknownPathMediator(timeout=1)
    output = io.BytesIO()
    socket_path = tmp_path / "approval.sock"
    controller = ApprovalController(
        session_id="session",
        mediator=mediator,
        approval_socket=socket_path,
        input_fd=os.open(os.devnull, os.O_RDONLY),
        output=output,
    )
    try:
        controller.run(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ.get('ASPR_APPROVAL_SOCKET', 'absent'))",
            ]
        )
    finally:
        os.close(controller.input_fd)
    assert b"absent" in output.getvalue()
