"""Broker worker mapping and cleanup regressions."""

from __future__ import annotations

from pathlib import Path

from astral_project.broker.mapping import WorkerProcess


def test_worker_terminate_reaps_once_and_removes_empty_staging(
    tmp_path: Path, monkeypatch
) -> None:
    staging = tmp_path / "worker"
    staging.mkdir()
    reaped: list[int] = []
    monkeypatch.setattr(
        "astral_project.broker.mapping._terminate_and_reap", reaped.append
    )
    process = WorkerProcess(1234, staging)

    process.terminate()
    process.terminate()

    assert reaped == [1234]
    assert not staging.exists()


def test_worker_terminate_tolerates_already_removed_staging(
    tmp_path: Path, monkeypatch
) -> None:
    staging = tmp_path / "worker"
    reaped: list[int] = []
    monkeypatch.setattr(
        "astral_project.broker.mapping._terminate_and_reap", reaped.append
    )

    WorkerProcess(5678, staging).terminate()

    assert reaped == [5678]
