"""Additional parent-side worker mapping behavior tests."""

from __future__ import annotations

import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from astral_project.broker import mapping
from astral_project.broker.mapping import WorkerLaunchFds, WorkerProcess
from astral_project.core.errors import AstralError


def test_worker_launch_fds_rejects_empty_duplicate_and_negative() -> None:
    with pytest.raises(AstralError):
        WorkerLaunchFds(1, 2, 3, (), 4)
    with pytest.raises(AstralError):
        WorkerLaunchFds(1, 1, 3, (4,), 5)
    with pytest.raises(AstralError):
        WorkerLaunchFds(-1, 2, 3, (4,), 5)


def test_worker_launch_fds_maps_fixed_abi_positions() -> None:
    fds = WorkerLaunchFds(10, 11, 12, (13, 14), 15)
    result = fds.fixed_mapping()
    assert result[5] == 10
    assert result[6] == 11
    assert result[7] == 12
    assert result[10] == 13
    assert result[11] == 14
    assert result[74] == 15


def test_worker_wait_reaps_and_cleans_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setattr("astral_project.broker.mapping.os.waitpid", lambda *_args: (99, 0))
    process = WorkerProcess(99, staging)
    ticks: list[str] = []
    assert process.wait(on_tick=lambda: ticks.append("tick")) == 0
    assert ticks == ["tick"]
    assert not staging.exists()
    with pytest.raises(AstralError):
        process.wait()


def test_worker_wait_timeout_terminates_and_reaps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.broker.mapping.os.waitpid", lambda *_args: (0, 0))
    times = iter((10.0, 12.0))
    monkeypatch.setattr("astral_project.broker.mapping.time.monotonic", lambda: next(times))
    killed: list[int] = []
    monkeypatch.setattr(mapping, "_terminate_and_reap", killed.append)
    with pytest.raises(AstralError):
        WorkerProcess(12).wait(timeout_seconds=1)
    assert killed == [12]


def test_worker_wait_rejects_nonpositive_timeout() -> None:
    with pytest.raises(AstralError):
        WorkerProcess(1).wait(timeout_seconds=0)


def test_worker_staging_cleanup_reports_unexpected_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = tmp_path / "staging"
    staging.mkdir()
    monkeypatch.setattr(Path, "rmdir", lambda _path: (_ for _ in ()).throw(OSError("busy")))
    monkeypatch.setattr(mapping, "_terminate_and_reap", lambda _pid: None)
    with pytest.raises(AstralError):
        WorkerProcess(1, staging).terminate()


def test_mapping_worker_validates_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    worker = mapping.MappingWorker(Path("/worker"))
    monkeypatch.setattr(mapping.MappingWorker, "start", lambda _self, **_kwargs: WorkerProcess(1))
    monkeypatch.setattr(mapping.WorkerProcess, "wait", lambda _self: 0)
    worker.run(uid=1, gid=1)


def test_mapping_worker_rejects_negative_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    worker = mapping.MappingWorker(Path("/worker"))
    with pytest.raises(AstralError):
        worker.start(uid=-1, gid=1)


def test_mapping_worker_run_terminates_failed_process(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    worker = mapping.MappingWorker(Path("/worker"))
    process = WorkerProcess(1)
    monkeypatch.setattr(mapping.MappingWorker, "start", lambda _self, **_kwargs: process)
    monkeypatch.setattr(mapping.WorkerProcess, "wait", lambda _self: 1)
    with pytest.raises(AstralError):
        worker.run(uid=1, gid=1)


def test_read_mapping_ready_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.broker.mapping.select.select", lambda *_args: ([], [], []))
    with pytest.raises(AstralError):
        mapping._read_mapping_ready(3)


def test_write_identity_map_reports_exited_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        Path, "write_text", lambda *_args, **_kwargs: (_ for _ in ()).throw(FileNotFoundError())
    )
    with pytest.raises(AstralError):
        mapping._write_identity_map(1, uid=2, gid=3)


def test_terminate_and_reap_swallows_dead_child(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "astral_project.broker.mapping.os.kill",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
    )
    monkeypatch.setattr(
        "astral_project.broker.mapping.os.waitpid",
        lambda *_args: (_ for _ in ()).throw(ChildProcessError()),
    )
    mapping._terminate_and_reap(1)
