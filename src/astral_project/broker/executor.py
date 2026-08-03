"""Root broker composition for one descriptor-pinned native worker session."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from astral_project.broker.launch import (
    PreparedWorkerLaunch,
    prepare_worker_launch_with_verified_runtime,
)
from astral_project.broker.mapping import MappingWorker, WorkerProcess
from astral_project.broker.sources import pin_grant_sources
from astral_project.broker.supervision import WorkerLogPipe, WorkerTermination, supervise_worker
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import Grant
from astral_project.runtime.closure import RuntimeManifestV1
from astral_project.session.ceiling import ServerCeilingV1


@dataclass(slots=True)
class ActiveWorkerSession:
    """Post-fork worker state. Parent owns only reaping and diagnostic read end."""

    process: WorkerProcess
    logs: WorkerLogPipe
    effective_exports_digest: bytes
    runtime_manifest_digest: bytes

    def supervise(self, *, timeout_seconds: float) -> WorkerTermination:
        return supervise_worker(self.process, self.logs, timeout_seconds=timeout_seconds)

    def terminate(self) -> None:
        self.process.terminate()
        self.logs.close()


@dataclass(frozen=True, slots=True)
class BrokerSessionExecutor:
    """Only root-broker composition point for native worker authority."""

    ceiling: ServerCeilingV1
    runtime_root: Path
    runtime_manifest: RuntimeManifestV1
    mapping_worker: MappingWorker

    def start(
        self, grant: Grant, *, stream_descriptor: int, peer_uid: int, peer_gid: int
    ) -> ActiveWorkerSession:
        """Pin, seal, map, and start worker. Every parent copy closes after fork."""
        if stream_descriptor < 0:
            raise _error("broker stream descriptor is invalid")
        pinned = pin_grant_sources(grant, self.ceiling)
        logs = WorkerLogPipe.create()
        prepared: PreparedWorkerLaunch | None = None
        try:
            prepared = prepare_worker_launch_with_verified_runtime(
                pinned,
                runtime_root=self.runtime_root,
                runtime_manifest=self.runtime_manifest,
                stream=stream_descriptor,
                log=logs.worker_write_descriptor(),
            )
            process = self.mapping_worker.start(
                uid=peer_uid, gid=peer_gid, launch_fds=prepared.launch_fds
            )
        except Exception:
            if prepared is not None:
                prepared.close()
            else:
                pinned.close()
            logs.close()
            os.close(stream_descriptor)
            raise
        prepared.close()
        logs.close_parent_write_descriptor()
        os.close(stream_descriptor)
        return ActiveWorkerSession(
            process=process,
            logs=logs,
            effective_exports_digest=hashlib.sha256(pinned.plan.canonical_bytes()).digest(),
            runtime_manifest_digest=bytes.fromhex(self.runtime_manifest.digest()),
        )


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="broker worker launch was rejected",
        unsafe_reason="root broker must retain sole ownership of worker descriptors",
        next_action="repair root-owned broker configuration and retry session",
    )
