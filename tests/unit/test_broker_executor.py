"""Broker session executor ownership tests."""

from __future__ import annotations

import os
from contextlib import suppress
from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest

from astral_project.broker.executor import ActiveWorkerSession, BrokerSessionExecutor
from astral_project.broker.mapping import MappingWorker, WorkerLaunchFds, WorkerProcess
from astral_project.broker.sources import PinnedSource, PinnedSources
from astral_project.crypto.grants import AccessMode, ExportKind, Grant, SourceIdentity
from astral_project.namespace.planner import NamespacePlan, PlannedExport
from astral_project.runtime.closure import RuntimeManifestV1
from astral_project.session.ceiling import ServerCeilingV1


def _pinned(descriptor: int) -> PinnedSources:
    export = PlannedExport(
        access_mode=AccessMode.READ_ONLY,
        descriptor_slot=0,
        identity=SourceIdentity(1, 2, "ext4", ExportKind.FILE),
        kind=ExportKind.FILE.value,
        virtual_target="/project",
    )
    return PinnedSources(NamespacePlan((export,)), (PinnedSource(descriptor, export, 1),))


def test_active_worker_termination_closes_process_and_logs() -> None:
    process = Mock(spec=WorkerProcess)
    logs = Mock()
    ActiveWorkerSession(process, logs, b"e", b"r").terminate()
    process.terminate.assert_called_once_with()
    logs.close.assert_called_once_with()


def test_executor_rejects_negative_stream_descriptor(tmp_path: Path) -> None:
    executor = BrokerSessionExecutor(
        ceiling=cast(ServerCeilingV1, None),
        runtime_root=tmp_path,
        runtime_manifest=cast(RuntimeManifestV1, None),
        mapping_worker=cast(MappingWorker, None),
    )
    with pytest.raises(Exception, match="stream descriptor is invalid"):
        executor.start(cast(Grant, None), stream_descriptor=-1, peer_uid=1, peer_gid=1)


def test_executor_closes_pinned_and_logs_when_launch_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    stream_read, stream_write = os.pipe()
    pinned = _pinned(os.open("/dev/null", os.O_RDONLY))
    monkeypatch.setattr(
        "astral_project.broker.executor.pin_grant_sources", lambda *_args, **_kwargs: pinned
    )
    monkeypatch.setattr(
        "astral_project.broker.executor.prepare_worker_launch_with_verified_runtime",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("launch")),
    )
    executor = BrokerSessionExecutor(
        ceiling=cast(ServerCeilingV1, None),
        runtime_root=tmp_path,
        runtime_manifest=cast(RuntimeManifestV1, None),
        mapping_worker=cast(MappingWorker, None),
    )
    try:
        with pytest.raises(RuntimeError):
            executor.start(cast(Grant, None), stream_descriptor=stream_read, peer_uid=1, peer_gid=1)
        with pytest.raises(OSError):
            os.fstat(stream_read)
    finally:
        with suppress(OSError):
            os.close(stream_write)


def test_executor_starts_worker_and_closes_parent_descriptor_copies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_read, source_write = os.pipe()
    stream_read, stream_write = os.pipe()
    pinned = _pinned(source_read)
    prepared_closed = False
    launch_fds = cast(WorkerLaunchFds, object())

    class Prepared:
        def __init__(self) -> None:
            self.launch_fds = launch_fds

        def close(self) -> None:
            nonlocal prepared_closed
            prepared_closed = True
            pinned.close()

    class Worker:
        received: WorkerLaunchFds | None = None

        def start(self, *, uid: int, gid: int, launch_fds: WorkerLaunchFds) -> WorkerProcess:
            self.received = launch_fds
            child = os.fork()
            if child == 0:
                os._exit(0)
            return WorkerProcess(child)

    worker = Worker()
    monkeypatch.setattr(
        "astral_project.broker.executor.pin_grant_sources", lambda *_args, **_kwargs: pinned
    )
    monkeypatch.setattr(
        "astral_project.broker.executor.prepare_worker_launch_with_verified_runtime",
        lambda *_args, **_kwargs: Prepared(),
    )

    class RuntimeManifest:
        def digest(self) -> str:
            return "0" * 64

    executor = BrokerSessionExecutor(
        ceiling=cast(ServerCeilingV1, None),
        runtime_root=tmp_path,
        runtime_manifest=cast(RuntimeManifestV1, RuntimeManifest()),
        mapping_worker=cast(MappingWorker, worker),
    )
    try:
        active = executor.start(
            cast(Grant, None), stream_descriptor=stream_read, peer_uid=1001, peer_gid=1001
        )
        assert worker.received is launch_fds
        assert prepared_closed is True
        for descriptor in (source_read, stream_read):
            try:
                os.fstat(descriptor)
            except OSError:
                continue
            raise AssertionError("parent retained worker descriptor")
        assert active.supervise(timeout_seconds=1).exit_code == 0
    finally:
        for descriptor in (source_write, stream_write):
            with suppress(OSError):
                os.close(descriptor)
