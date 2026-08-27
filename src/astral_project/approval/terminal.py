"""Parent-controlled PTY relay and trusted approval transition."""

from __future__ import annotations

import base64
import errno
import fcntl
import os
import pty
import select
import selectors
import shutil
import signal
import struct
import termios
import tty
from collections import deque
from collections.abc import Callable, Sequence
from contextlib import suppress
from pathlib import Path
from typing import Any, BinaryIO

from astral_project.approval.protocol import ApprovalServer
from astral_project.homed.mediation import MediationDecision, PendingRequest, UnknownPathMediator

_ESCAPE = b"\x1d"
_INTERRUPT = b"\x03"
_SUSPEND = b"\x1a"
_MAX_BUFFER = 256 * 1024


class TerminalControllerError(RuntimeError):
    """PTY controller setup or relay failure."""


class TerminalGuard:
    """Restore parent terminal attributes even when relay exits exceptionally."""

    def __init__(self, fd: int) -> None:
        self.fd = fd
        self._attributes: list[Any] | None = None
        self._guard_pid: int | None = None
        self._guard_write: int | None = None

    def ensure_alive(self) -> None:
        """Fail closed if the independent restoration guard exits unexpectedly."""
        guard_pid = self._guard_pid
        if guard_pid is None:
            return
        try:
            waited, _status = os.waitpid(guard_pid, os.WNOHANG)
        except ChildProcessError:
            waited = guard_pid
        if waited != guard_pid:
            return
        self._guard_pid = None
        write_fd = self._guard_write
        self._guard_write = None
        if write_fd is not None:
            with suppress(OSError):
                os.close(write_fd)
        attributes = self._attributes
        self._attributes = None
        if attributes is not None:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, attributes)
        raise TerminalControllerError("terminal restoration guard exited")

    def __enter__(self) -> TerminalGuard:
        if os.isatty(self.fd):
            self._attributes = termios.tcgetattr(self.fd)
            tty.setraw(self.fd)
            self._start_guard()
        return self

    def _start_guard(self) -> None:
        assert self._attributes is not None
        read_fd, write_fd = os.pipe()
        try:
            pid = os.fork()
        except OSError:
            os.close(read_fd)
            os.close(write_fd)
            return
        if pid == 0:  # pragma: no cover - guard process has a separate coverage runtime
            os.close(write_fd)
            parent = os.getppid()
            while True:
                ready, _, _ = select.select([read_fd], [], [], 0.1)
                if ready:
                    if not os.read(read_fd, 1):
                        termios.tcsetattr(self.fd, termios.TCSADRAIN, self._attributes)
                    os.close(read_fd)
                    os._exit(0)
                if os.getppid() != parent:
                    termios.tcsetattr(self.fd, termios.TCSADRAIN, self._attributes)
                    os.close(read_fd)
                    os._exit(0)
        os.close(read_fd)
        self._guard_pid = pid
        self._guard_write = write_fd

    def restore(self) -> None:
        if self._attributes is not None:
            termios.tcsetattr(self.fd, termios.TCSADRAIN, self._attributes)
            self._attributes = None
        write_fd = self._guard_write
        self._guard_write = None
        if write_fd is not None:
            with suppress(OSError):
                os.close(write_fd)
        guard_pid = self._guard_pid
        self._guard_pid = None
        if guard_pid is not None:
            with suppress(ChildProcessError):
                os.waitpid(guard_pid, 0)

    def __exit__(self, *_: object) -> None:
        self.restore()


class ApprovalController:
    """Relay child PTY traffic while keeping approval authority in parent."""

    def __init__(
        self,
        *,
        session_id: str,
        mediator: UnknownPathMediator,
        approval_socket: Path | None = None,
        input_fd: int = 0,
        output: BinaryIO | None = None,
    ) -> None:
        if not session_id:
            raise TerminalControllerError("approval session identity is required")
        self.session_id = session_id
        self.mediator = mediator
        self.approval_socket = approval_socket
        self.input_fd = input_fd
        self.output = output
        self._resize_pending = False
        self._continue_pending = False

    def run(
        self,
        argv: Sequence[str],
        *,
        env: dict[str, str] | None = None,
        preface: bytes = b"",
        health_check: Callable[[], bool] | None = None,
    ) -> int:
        if not argv:
            raise TerminalControllerError("child argv is empty")
        server = (
            ApprovalServer(self.approval_socket, self.mediator) if self.approval_socket else None
        )
        if server is not None:
            server.start()
        old_winch = signal.getsignal(signal.SIGWINCH)
        old_cont = signal.getsignal(signal.SIGCONT)
        signal.signal(signal.SIGWINCH, self._on_winch)
        signal.signal(signal.SIGCONT, self._on_cont)
        try:
            pid, master = pty.fork()
            if pid == 0:  # pragma: no cover - child process has a separate coverage runtime
                if env is None:
                    os.execvp(argv[0], list(argv))
                os.execvpe(argv[0], list(argv), env)
            return self._relay(pid, master, preface, health_check)
        except OSError as error:
            raise TerminalControllerError(f"PTY relay failed: {error}") from error
        finally:
            signal.signal(signal.SIGWINCH, old_winch)
            signal.signal(signal.SIGCONT, old_cont)
            if server is not None:
                server.close()

    def _relay(
        self,
        pid: int,
        master: int,
        preface: bytes,
        health_check: Callable[[], bool] | None,
    ) -> int:
        selector = selectors.DefaultSelector()
        selector.register(master, selectors.EVENT_READ, "child")
        if os.isatty(self.input_fd):
            selector.register(self.input_fd, selectors.EVENT_READ, "input")
        buffered = deque[bytes]()
        buffered_size = 0
        active: PendingRequest | None = None
        announced: tuple[str, int] | None = None
        try:
            if preface:
                self._write_preface(master, preface)
            with TerminalGuard(self.input_fd) as guard:
                while True:
                    guard.ensure_alive()
                    if health_check is not None and not health_check():
                        os.killpg(pid, signal.SIGTERM)
                        raise TerminalControllerError("sandbox authority health check failed")
                    if self._resize_pending:
                        self._resize(master)
                        self._resize_pending = False
                    if self._continue_pending:
                        os.killpg(pid, signal.SIGCONT)
                        self._continue_pending = False
                    if active is None:
                        pending = self._pending_for_session()
                        if pending is not None and pending.key != announced:
                            self._write(b"\r\n[approval pending; press Ctrl-] to review]\r\n")
                            announced = pending.key
                    else:
                        if not any(item.key == active.key for item in self.mediator.pending()):
                            self._write(b"\r\n[approval resolved]\r\n")
                            while buffered:
                                self._write(buffered.popleft())
                            buffered_size = 0
                            active = None
                    for key, _ in selector.select(timeout=0.05):
                        if key.data == "child":
                            try:
                                data = os.read(master, 65536)
                            except OSError as error:
                                if error.errno in {errno.EIO, errno.EBADF}:
                                    data = b""
                                else:  # pragma: no cover - unexpected PTY read errors propagate
                                    raise
                            if not data:
                                _, status = os.waitpid(pid, 0)
                                return os.waitstatus_to_exitcode(status)
                            if active is None:
                                self._write(data)
                            elif buffered_size < _MAX_BUFFER:
                                chunk = data[: _MAX_BUFFER - buffered_size]
                                buffered.append(chunk)
                                buffered_size += len(chunk)
                        else:
                            data = os.read(self.input_fd, 4096)
                            if active is None:
                                self._forward_input(pid, master, data)
                                if _ESCAPE in data:
                                    active = self._pending_request()
                            else:
                                self._handle_decision(active, data)
        finally:
            self.mediator.cancel_session(self.session_id)
            selector.close()
            with suppress(OSError):
                os.close(master)
            with suppress(ChildProcessError):
                os.waitpid(pid, 0)

    @staticmethod
    def _write_preface(master: int, preface: bytes) -> None:
        """Send binary launcher metadata through a PTY-safe ASCII envelope."""
        if preface.startswith(b"ASPRSB01"):
            preface = b"ASPRB64\n" + base64.b64encode(preface) + b"\n"
        attributes: list[Any] | None
        try:
            attributes = termios.tcgetattr(master)
        except termios.error:
            attributes = None
        try:
            if attributes is not None:
                quiet = list(attributes)
                quiet[3] &= ~termios.ECHO
                termios.tcsetattr(master, termios.TCSANOW, quiet)
            offset = 0
            while offset < len(preface):
                count = os.write(master, preface[offset:])
                if count <= 0:
                    raise TerminalControllerError("PTY preface write failed")
                offset += count
        finally:
            if attributes is not None:
                termios.tcsetattr(master, termios.TCSANOW, attributes)

    def _pending_for_session(self) -> PendingRequest | None:
        return next(
            (
                request
                for request in self.mediator.pending()
                if request.session_id == self.session_id
            ),
            None,
        )

    def _pending_request(self) -> PendingRequest | None:
        request = self._pending_for_session()
        if request is None:
            return None
        self._write(
            (
                "\r\n[approval required] "
                f"session={request.session_id} request={request.request_number} "
                f"operation={request.operation.value} component={request.path_component!r} "
                f"opaque={request.opaque_ancestor} sensitivity={request.sensitivity.value}\r\n"
                "[y] allow once  [n] deny  [h] hide\r\n"
            ).encode()
        )
        return request

    def _handle_decision(self, request: PendingRequest, data: bytes) -> None:
        for byte in data:
            if byte in {ord("y"), ord("Y")}:
                self.mediator.decide(
                    session_id=request.session_id,
                    request_number=request.request_number,
                    decision=MediationDecision.ALLOW_ONCE,
                )
                return
            if byte in {ord("n"), ord("N")}:
                self.mediator.decide(
                    session_id=request.session_id,
                    request_number=request.request_number,
                    decision=MediationDecision.DENY,
                )
                return
            if byte in {ord("h"), ord("H")}:
                self.mediator.decide(
                    session_id=request.session_id,
                    request_number=request.request_number,
                    decision=MediationDecision.HIDE,
                )
                return

    def _forward_input(self, pid: int, master: int, data: bytes) -> None:
        if _ESCAPE in data:
            self._write(b"\r\n[approval pending; child input stopped]\r\n")
            return
        if _INTERRUPT in data:
            os.killpg(pid, signal.SIGINT)
            return
        if _SUSPEND in data:
            os.killpg(pid, signal.SIGTSTP)
            return
        os.write(master, data)

    def _write(self, data: bytes) -> None:
        if self.output is not None:
            self.output.write(data)
            self.output.flush()
            return
        os.write(1, data)

    def _on_winch(self, _signum: int, _frame: object) -> None:
        self._resize_pending = True

    def _on_cont(self, _signum: int, _frame: object) -> None:
        self._continue_pending = True

    @staticmethod
    def _resize(master: int) -> None:
        size = shutil.get_terminal_size((80, 24))
        packed = struct.pack("HHHH", size.lines, size.columns, 0, 0)
        fcntl.ioctl(master, termios.TIOCSWINSZ, packed)
