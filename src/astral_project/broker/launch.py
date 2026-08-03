"""Broker-owned assembly of sealed plan and fixed native-worker descriptors."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from astral_project.broker.execution_plan import ExecutionPlanV1, create_sealed_execution_plan
from astral_project.broker.mapping import WorkerLaunchFds
from astral_project.broker.sources import PinnedSources
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.runtime.closure import RuntimeManifestV1, open_verified_runtime_closure


@dataclass(slots=True)
class PreparedWorkerLaunch:
    """Own sealed plan and pinned sources until native worker fork transfers them."""

    launch_fds: WorkerLaunchFds
    pinned_sources: PinnedSources
    _owned_descriptors: tuple[int, ...]
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        if self._closed:
            return
        for descriptor in self._owned_descriptors:
            os.close(descriptor)
        self.pinned_sources.close()
        self._closed = True

    def __enter__(self) -> PreparedWorkerLaunch:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def prepare_worker_launch(
    pinned_sources: PinnedSources, *, runtime: int, stream: int, log: int
) -> PreparedWorkerLaunch:
    """Seal plan then bind only broker-owned descriptors to fixed worker ABI."""
    if any(descriptor < 0 for descriptor in (runtime, stream, log)):
        raise _error("worker runtime, stream, or log descriptor is invalid")
    descriptor = create_sealed_execution_plan(
        ExecutionPlanV1.from_namespace_plan(pinned_sources.plan)
    )
    try:
        launch_fds = WorkerLaunchFds(
            sealed_plan=descriptor,
            stream=stream,
            log=log,
            sources=tuple(source.descriptor for source in pinned_sources.sources),
            runtime=runtime,
        )
        return PreparedWorkerLaunch(
            launch_fds=launch_fds,
            pinned_sources=pinned_sources,
            _owned_descriptors=(descriptor,),
        )
    except Exception:
        os.close(descriptor)
        raise


def prepare_worker_launch_with_verified_runtime(
    pinned_sources: PinnedSources,
    *,
    runtime_root: Path,
    runtime_manifest: RuntimeManifestV1,
    stream: int,
    log: int,
) -> PreparedWorkerLaunch:
    """Open and transfer verified root-owned runtime descriptor into launch ownership."""
    runtime = open_verified_runtime_closure(runtime_root, runtime_manifest)
    try:
        prepared = prepare_worker_launch(pinned_sources, runtime=runtime, stream=stream, log=log)
    except Exception:
        os.close(runtime)
        raise
    prepared._owned_descriptors = (*prepared._owned_descriptors, runtime)
    return prepared


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="worker launch preparation was rejected",
        unsafe_reason="native worker receives only fixed broker-owned descriptors",
        next_action="rebuild broker launch state from authenticated request",
    )
