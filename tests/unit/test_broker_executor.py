"""Broker session executor ownership tests."""

from __future__ import annotations

import os
from contextlib import suppress
from pathlib import Path
from typing import cast

import pytest

from astral_project.broker.executor import BrokerSessionExecutor
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
