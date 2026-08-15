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


def test_worker_fd_install_handles_relocation_and_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, int, int]] = []
    monkeypatch.setattr(
        "astral_project.broker.mapping.fcntl.fcntl", lambda source, _op, _floor: source + 100
    )
    fake_os = SimpleNamespace(
        close=lambda fd: calls.append(("close", fd, 0)),
        dup2=lambda source, destination, inheritable: calls.append(("dup2", source, destination)),
    )
    monkeypatch.setattr(mapping, "os", fake_os)
    mapping._install_worker_fds(3, 4, {5: 10})
    assert ("dup2", 103, 3) in calls
    with pytest.raises(AstralError):
        mapping._install_worker_fds(3, 4, {5: 3})


def test_worker_sync_fd_install_uses_common_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "astral_project.broker.mapping.fcntl.fcntl", lambda source, _op, _floor: source + 100
    )
    calls: list[tuple[int, int]] = []
    monkeypatch.setattr(
        mapping,
        "os",
        SimpleNamespace(
            close=lambda _fd: None,
            dup2=lambda source, destination, inheritable: calls.append((source, destination)),
        ),
    )
    mapping._install_worker_sync_fds(3, 4)
    assert calls


def test_worker_fd_install_closes_relocated_fds_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    closed: list[int] = []
    monkeypatch.setattr("astral_project.broker.mapping.fcntl.fcntl", lambda *_args: 75)
    fake_os = SimpleNamespace(
        close=closed.append,
        dup2=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("dup")),
    )
    monkeypatch.setattr(mapping, "os", fake_os)
    with pytest.raises(OSError):
        mapping._install_worker_fds(3, 4, {})
    assert closed


def test_create_staging_reports_os_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(mapping, "_STAGING_ROOT", tmp_path / "staging")
    monkeypatch.setattr(
        Path,
        "mkdir",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("mkdir")),
    )
    with pytest.raises(AstralError):
        mapping._create_worker_staging(7, uid=10, gid=11)


def test_create_staging_and_write_identity_map(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "staging"
    monkeypatch.setattr(mapping, "_STAGING_ROOT", root)
    monkeypatch.setattr("astral_project.broker.mapping.os.chown", lambda *_args: None)
    path = mapping._create_worker_staging(7, uid=10, gid=11)
    assert path == root / "7"
    writes: list[tuple[str, str]] = []
    monkeypatch.setattr(
        Path, "write_text", lambda self, text, **_kwargs: writes.append((str(self), text))
    )
    mapping._write_identity_map(7, uid=10, gid=11)
    assert writes[-2:] == [("/proc/7/uid_map", "0 10 1\n"), ("/proc/7/gid_map", "0 11 1\n")]


def test_mapping_worker_validates_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    worker = mapping.MappingWorker(Path("/worker"))
    monkeypatch.setattr(mapping.MappingWorker, "start", lambda _self, **_kwargs: WorkerProcess(1))
    monkeypatch.setattr(mapping.WorkerProcess, "wait", lambda _self: 0)
    worker.run(uid=1, gid=1)


@pytest.mark.parametrize(
    "details",
    [
        SimpleNamespace(st_mode=stat.S_IFDIR | stat.S_IXUSR, st_uid=0),
        SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=1),
        SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR | 0o002, st_uid=0),
    ],
)
def test_mapping_worker_rejects_unsafe_executable(
    monkeypatch: pytest.MonkeyPatch, details: SimpleNamespace
) -> None:
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    with pytest.raises(AstralError):
        mapping.MappingWorker(Path("/worker"))


def test_mapping_worker_child_exec_failure_exits(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    monkeypatch.setattr("astral_project.broker.mapping.os.pipe2", lambda _flags: (10, 11))
    monkeypatch.setattr("astral_project.broker.mapping.os.fork", lambda: 0)
    monkeypatch.setattr("astral_project.broker.mapping.os.close", lambda _fd: None)
    monkeypatch.setattr(mapping, "_install_worker_fds", lambda *_args: None)
    monkeypatch.setattr(
        "astral_project.broker.mapping.os.execve",
        lambda *_args: (_ for _ in ()).throw(OSError("exec")),
    )
    monkeypatch.setattr(
        "astral_project.broker.mapping.os._exit",
        lambda _code: (_ for _ in ()).throw(RuntimeError("exit")),
    )
    with pytest.raises(RuntimeError, match="exit"):
        mapping.MappingWorker(Path("/worker")).start(uid=1, gid=1)


def test_mapping_worker_start_maps_parent_side(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    closed: list[int] = []
    fake_os = SimpleNamespace(
        O_CLOEXEC=1,
        pipe2=lambda _flags: (10, 11),
        fork=lambda: 99,
        close=closed.append,
        write=lambda _fd, _data: 1,
    )
    monkeypatch.setattr(mapping, "os", fake_os)
    monkeypatch.setattr(mapping, "_read_mapping_ready", lambda _fd: b"R")
    monkeypatch.setattr(mapping, "_create_worker_staging", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(mapping, "_write_identity_map", lambda *_args, **_kwargs: None)
    worker = mapping.MappingWorker(Path("/worker"))
    process = worker.start(uid=1, gid=1)
    assert process.pid == 99
    assert closed == [11, 10, 10, 11]


def test_mapping_worker_start_reaps_on_continuation_write_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    fake_os = SimpleNamespace(
        O_CLOEXEC=1,
        pipe2=lambda _flags: (10, 11),
        fork=lambda: 99,
        close=lambda _fd: None,
        write=lambda _fd, _data: 0,
    )
    monkeypatch.setattr(mapping, "os", fake_os)
    monkeypatch.setattr(mapping, "_read_mapping_ready", lambda _fd: b"R")
    monkeypatch.setattr(mapping, "_create_worker_staging", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(mapping, "_write_identity_map", lambda *_args, **_kwargs: None)
    reaped: list[int] = []
    monkeypatch.setattr(mapping, "_terminate_and_reap", reaped.append)
    with pytest.raises(AstralError):
        mapping.MappingWorker(Path("/worker")).start(uid=1, gid=1)
    assert reaped == [99]


def test_mapping_worker_start_reaps_on_bad_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    fake_os = SimpleNamespace(
        O_CLOEXEC=1, pipe2=lambda _flags: (10, 11), fork=lambda: 99, close=lambda _fd: None
    )
    monkeypatch.setattr(mapping, "os", fake_os)
    monkeypatch.setattr(mapping, "_read_mapping_ready", lambda _fd: b"X")
    reaped: list[int] = []
    monkeypatch.setattr(mapping, "_terminate_and_reap", reaped.append)
    with pytest.raises(AstralError):
        mapping.MappingWorker(Path("/worker")).start(uid=1, gid=1)
    assert reaped == [99]


def test_mapping_worker_rejects_negative_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    worker = mapping.MappingWorker(Path("/worker"))
    with pytest.raises(AstralError):
        worker.start(uid=-1, gid=1)


def test_mapping_worker_run_terminates_after_wait_exception(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    worker = mapping.MappingWorker(Path("/worker"))
    process = WorkerProcess(1)
    terminated: list[int] = []
    monkeypatch.setattr(mapping.MappingWorker, "start", lambda _self, **_kwargs: process)
    monkeypatch.setattr(
        mapping.WorkerProcess, "wait", lambda _self: (_ for _ in ()).throw(RuntimeError("wait"))
    )
    monkeypatch.setattr(
        mapping.WorkerProcess, "terminate", lambda self: terminated.append(self.pid)
    )
    with pytest.raises(RuntimeError):
        worker.run(uid=1, gid=1)
    assert terminated == [1]


def test_mapping_worker_run_rejects_signaled_process(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    worker = mapping.MappingWorker(Path("/worker"))
    process = WorkerProcess(1)
    monkeypatch.setattr(mapping.MappingWorker, "start", lambda _self, **_kwargs: process)
    monkeypatch.setattr(mapping.WorkerProcess, "wait", lambda _self: 1)
    monkeypatch.setattr("astral_project.broker.mapping.os.WIFEXITED", lambda _status: False)
    with pytest.raises(AstralError):
        worker.run(uid=1, gid=1)


def test_mapping_worker_run_terminates_failed_process(monkeypatch: pytest.MonkeyPatch) -> None:
    details = SimpleNamespace(st_mode=stat.S_IFREG | stat.S_IXUSR, st_uid=0)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    worker = mapping.MappingWorker(Path("/worker"))
    process = WorkerProcess(1)
    monkeypatch.setattr(mapping.MappingWorker, "start", lambda _self, **_kwargs: process)
    monkeypatch.setattr(mapping.WorkerProcess, "wait", lambda _self: 1)
    with pytest.raises(AstralError):
        worker.run(uid=1, gid=1)


def test_read_mapping_ready_returns_empty_handshake(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.broker.mapping.select.select", lambda *_args: ([3], [], []))
    monkeypatch.setattr("astral_project.broker.mapping.os.read", lambda *_args: b"")
    assert mapping._read_mapping_ready(3) == b""


def test_read_mapping_ready_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.broker.mapping.select.select", lambda *_args: ([], [], []))
    with pytest.raises(AstralError):
        mapping._read_mapping_ready(3)


def test_write_identity_map_reports_setgroups_and_map_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_setgroups(path: Path, *_args: object, **_kwargs: object) -> None:
        if path.name == "setgroups":
            raise OSError("setgroups")

    monkeypatch.setattr(Path, "write_text", fail_setgroups)
    with pytest.raises(AstralError):
        mapping._write_identity_map(1, uid=2, gid=3)

    calls = [0]

    def fail_map(path: Path, *_args: object, **_kwargs: object) -> None:
        calls[0] += 1
        if calls[0] > 1:
            raise OSError("map")

    monkeypatch.setattr(Path, "write_text", fail_map)
    with pytest.raises(AstralError):
        mapping._write_identity_map(1, uid=2, gid=3)


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
