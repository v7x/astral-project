"""Active worker registry cancellation tests."""

from __future__ import annotations

import threading

from astral_project.broker.registry import ActiveSessionRegistry


class Worker:
    def __init__(self) -> None:
        self.terminated = threading.Event()
        self.supervised = threading.Event()

    def terminate(self) -> None:
        self.terminated.set()

    def supervise(self, *, timeout_seconds: float) -> None:
        self.supervised.set()
        self.terminated.wait(timeout_seconds)


def test_registry_cancellation_terminates_and_removes_worker() -> None:
    worker = Worker()
    registry = ActiveSessionRegistry(clock=lambda: 100)
    session_id = b"s" * 16

    registry.register(session_id, worker, expires_at=200)  # type: ignore[arg-type]

    assert worker.supervised.wait(1)
    assert registry.cancel(session_id) is True
    assert worker.terminated.wait(1)
    assert registry.cancel(session_id) is False


def test_registry_expiry_terminates_worker_and_removes_session() -> None:
    worker = Worker()
    now = [100]
    registry = ActiveSessionRegistry(clock=lambda: now[0])
    session_id = b"e" * 16

    registry.register(session_id, worker, expires_at=101)  # type: ignore[arg-type]
    assert worker.supervised.wait(1)
    now[0] = 101

    assert registry.expire() == 1
    assert worker.terminated.wait(1)
    assert registry.active_count() == 0
