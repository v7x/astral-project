"""Registry rejection and supervision result tests."""

from __future__ import annotations

import time

import pytest

from astral_project.broker.registry import ActiveSessionRegistry
from astral_project.core.errors import AstralError


class Worker:
    def __init__(self, result: object = None) -> None:
        self.result = result
        self.terminated_count = 0

    def terminate(self) -> None:
        self.terminated_count += 1

    def supervise(self, *, timeout_seconds: float) -> object:
        assert timeout_seconds > 0
        time.sleep(0.1)
        return self.result


def test_registry_rejects_bad_and_duplicate_sessions() -> None:
    worker = Worker()
    registry = ActiveSessionRegistry(clock=lambda: 10)
    with pytest.raises(AstralError):
        registry.register(b"short", worker, expires_at=20)  # type: ignore[arg-type]
    assert worker.terminated_count == 1
    registry.register(b"a" * 16, worker, expires_at=20)  # type: ignore[arg-type]
    duplicate = Worker()
    with pytest.raises(AstralError):
        registry.register(b"a" * 16, duplicate, expires_at=20)  # type: ignore[arg-type]
    assert duplicate.terminated_count == 1
    assert registry.cancel(b"a" * 16)


def test_registry_rejects_expired_registration() -> None:
    worker = Worker()
    with pytest.raises(AstralError):
        ActiveSessionRegistry(clock=lambda: 20).register(b"a" * 16, worker, expires_at=20)  # type: ignore[arg-type]
    assert worker.terminated_count == 1


def test_registry_supervision_cleans_normal_result() -> None:
    worker = Worker(result=object())
    registry = ActiveSessionRegistry(clock=lambda: int(time.time()))
    registry.register(b"b" * 16, worker, expires_at=int(time.time()) + 10)  # type: ignore[arg-type]
    deadline = time.time() + 1
    while registry.active_count() and time.time() < deadline:
        time.sleep(0.01)
    assert registry.active_count() == 0
