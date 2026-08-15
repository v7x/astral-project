"""Worker supervision error and bounded-log behavior."""

from __future__ import annotations

import os

import pytest

from astral_project.broker.mapping import WorkerProcess
from astral_project.broker.supervision import WorkerLogPipe, supervise_worker
from astral_project.core.errors import AstralError


def test_log_pipe_lifecycle_and_overflow(monkeypatch: pytest.MonkeyPatch) -> None:
    logs = WorkerLogPipe(1, 2)
    calls = [0]

    def fake_read(*_args: object) -> bytes:
        calls[0] += 1
        if calls[0] == 1:
            return b"x" * 70000
        if calls[0] == 2:
            return b"x"
        raise BlockingIOError

    monkeypatch.setattr(os, "read", fake_read)
    logs.drain()
    content, truncated = logs.result()
    assert len(content) == 65536
    assert truncated
    logs.close()
    logs.close()
    monkeypatch.setattr(os, "close", lambda _descriptor: None)
    logs.close_parent_write_descriptor()
    logs.close_parent_write_descriptor()
    logs.drain()
    with pytest.raises(AstralError):
        logs.worker_write_descriptor()


def test_supervision_reports_signal_and_unsupported_status(monkeypatch: pytest.MonkeyPatch) -> None:
    logs = WorkerLogPipe.create()
    process = WorkerProcess(1)
    monkeypatch.setattr(WorkerProcess, "wait", lambda _self, **_kwargs: 9)
    monkeypatch.setattr(os, "WIFEXITED", lambda _status: False)
    monkeypatch.setattr(os, "WIFSIGNALED", lambda _status: True)
    monkeypatch.setattr(os, "WTERMSIG", lambda _status: 9)
    result = supervise_worker(process, logs, timeout_seconds=1)
    assert result.signal == 9

    logs = WorkerLogPipe.create()
    monkeypatch.setattr(os, "WIFSIGNALED", lambda _status: False)
    with pytest.raises(AstralError):
        supervise_worker(process, logs, timeout_seconds=1)
