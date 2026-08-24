"""Thread-safe broker worker registry; expiry and cancellation always terminate child."""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from astral_project.broker.executor import ActiveWorkerSession
from astral_project.core.errors import AstralError, ErrorCode


@dataclass(frozen=True, slots=True)
class ActiveSession:
    session_id: bytes
    expires_at: int
    worker: ActiveWorkerSession


class ActiveSessionRegistry:
    """Sole owner of started workers after broker returns namespace ready."""

    def __init__(self, *, clock: Callable[[], int] | None = None) -> None:
        self._clock: Callable[[], int] = _system_clock if clock is None else clock
        self._sessions: dict[bytes, ActiveSession] = {}
        self._lock = threading.Lock()

    def register(self, session_id: bytes, worker: ActiveWorkerSession, *, expires_at: int) -> None:
        if len(session_id) != 16 or expires_at <= self._clock():
            worker.terminate()
            raise _error("worker session identifier or expiry is invalid")
        with self._lock:
            if session_id in self._sessions:
                worker.terminate()
                raise _error("worker session identifier is already active")
            self._sessions[session_id] = ActiveSession(session_id, expires_at, worker)
        thread = threading.Thread(target=self._supervise, args=(session_id,), daemon=True)
        thread.start()

    def register_from_server(
        self, session_id: bytes, worker: ActiveWorkerSession, expires_at: int
    ) -> None:
        self.register(session_id, worker, expires_at=expires_at)

    def cancel(self, session_id: bytes) -> bool:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is None:
            return False
        session.worker.terminate()
        return True

    def expire(self) -> int:
        now = self._clock()
        with self._lock:
            expired = [key for key, value in self._sessions.items() if value.expires_at <= now]
            sessions = [self._sessions.pop(key) for key in expired]
        for session in sessions:
            session.worker.terminate()
        return len(sessions)

    def active_count(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _supervise(self, session_id: bytes) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            return
        try:
            try:
                result = session.worker.supervise(
                    timeout_seconds=max(0.01, session.expires_at - self._clock())
                )
            except AstralError:
                # WorkerProcess.wait kills and reaps at the expiry deadline before
                # reporting the timeout. Retrying terminate is idempotent and makes
                # any broken supervision path fail loudly rather than orphan authority.
                session.worker.terminate()
                return
            if not hasattr(result, "exit_code"):
                return
            if result.exit_code not in {0, None} or result.signal is not None:
                print(
                    "astral worker termination "
                    f"exit_code={result.exit_code} signal={result.signal} "
                    f"stderr={result.stderr.decode('utf-8', 'replace')!r} "
                    f"stderr_truncated={result.stderr_truncated}",
                    file=sys.stderr,
                    flush=True,
                )
        finally:
            with self._lock:
                self._sessions.pop(session_id, None)


def _system_clock() -> int:
    return int(time.time())


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="worker session was rejected",
        unsafe_reason="broker must retain cancellation and expiry authority over native worker",
        next_action="start a fresh authenticated session",
    )
