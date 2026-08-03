"""Sealed plan and fixed descriptor launch preparation tests."""

from __future__ import annotations

import fcntl
import os
from contextlib import suppress
from pathlib import Path

import pytest

from astral_project.broker.launch import (
    prepare_worker_launch,
    prepare_worker_launch_with_verified_runtime,
)
from astral_project.broker.sources import PinnedSource, PinnedSources
from astral_project.crypto.grants import AccessMode, ExportKind, SourceIdentity
from astral_project.namespace.planner import NamespacePlan, PlannedExport
from astral_project.session.broker import WORKER_FD_LAYOUT


def _pinned_source(descriptor: int) -> PinnedSources:
    export = PlannedExport(
        access_mode=AccessMode.READ_ONLY,
        descriptor_slot=0,
        identity=SourceIdentity(1, 2, 3, "ext4", ExportKind.FILE),
        kind=ExportKind.FILE.value,
        virtual_target="/project",
    )
    return PinnedSources(NamespacePlan((export,)), (PinnedSource(descriptor, export),))


def test_prepare_worker_launch_seals_plan_and_keeps_only_fixed_mapping() -> None:
    source_read, source_write = os.pipe()
    runtime_read, runtime_write = os.pipe()
    stream_read, stream_write = os.pipe()
    log_read, log_write = os.pipe()
    pinned = _pinned_source(source_read)
    try:
        with prepare_worker_launch(
            pinned, runtime=runtime_read, stream=stream_read, log=log_write
        ) as prepared:
            mapping = prepared.launch_fds.fixed_mapping()
            assert mapping[WORKER_FD_LAYOUT.source_base] == source_read
            assert mapping[WORKER_FD_LAYOUT.runtime] == runtime_read
            assert mapping[WORKER_FD_LAYOUT.stream] == stream_read
            assert mapping[WORKER_FD_LAYOUT.log] == log_write
            seals = fcntl.fcntl(prepared.launch_fds.sealed_plan, fcntl.F_GET_SEALS)
            assert seals & fcntl.F_SEAL_WRITE
        with pytest.raises(OSError):
            os.fstat(source_read)
    finally:
        for descriptor in (
            source_write,
            runtime_read,
            runtime_write,
            stream_read,
            stream_write,
            log_read,
            log_write,
        ):
            with suppress(OSError):
                os.close(descriptor)


def test_verified_runtime_descriptor_transfers_to_prepared_launch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source_read, source_write = os.pipe()
    runtime_read, runtime_write = os.pipe()
    stream_read, stream_write = os.pipe()
    log_read, log_write = os.pipe()
    pinned = _pinned_source(source_read)
    monkeypatch.setattr(
        "astral_project.broker.launch.open_verified_runtime_closure", lambda *_: runtime_read
    )
    try:
        with prepare_worker_launch_with_verified_runtime(
            pinned,
            runtime_root=tmp_path,
            runtime_manifest=object(),  # type: ignore[arg-type]
            stream=stream_read,
            log=log_write,
        ) as prepared:
            assert prepared.launch_fds.runtime == runtime_read
        with pytest.raises(OSError):
            os.fstat(runtime_read)
    finally:
        for descriptor in (
            source_write,
            runtime_write,
            stream_read,
            stream_write,
            log_read,
            log_write,
        ):
            with suppress(OSError):
                os.close(descriptor)


def test_prepare_worker_launch_rejects_aliased_broker_descriptors() -> None:
    source_read, source_write = os.pipe()
    runtime_read, runtime_write = os.pipe()
    log_read, log_write = os.pipe()
    pinned = _pinned_source(source_read)
    try:
        with pytest.raises(Exception, match="aliased"):
            prepare_worker_launch(pinned, runtime=runtime_read, stream=runtime_read, log=log_write)
        os.fstat(source_read)
    finally:
        pinned.close()
        for descriptor in (source_write, runtime_read, runtime_write, log_read, log_write):
            with suppress(OSError):
                os.close(descriptor)
