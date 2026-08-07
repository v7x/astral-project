"""Packet 15B sealed binary plan for fixed native worker FD ABI."""

from __future__ import annotations

import fcntl
import os
import struct
from dataclasses import dataclass

from astral_project.broker.sources import PinnedSources
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import AccessMode, ExportKind
from astral_project.namespace.planner import PlannedExport
from astral_project.session.broker import WORKER_FD_LAYOUT

_MAGIC = b"ASPRPLN1"
_VERSION = 1
_HEADER = struct.Struct("<8sII")
_ENTRY = struct.Struct("<IBBHQQQH")
_MAX_EXPORTS = WORKER_FD_LAYOUT.source_limit - WORKER_FD_LAYOUT.source_base
_MAX_TARGET_BYTES = 4096


@dataclass(frozen=True, slots=True)
class ExecutionPlanV1:
    """Sealed worker input: descriptor identity and virtual target only."""

    exports: tuple[PlannedExport, ...]
    broker_mount_ids: tuple[int, ...]

    def __post_init__(self) -> None:
        if (
            not 1 <= len(self.exports) <= _MAX_EXPORTS
            or len(self.exports) != len(self.broker_mount_ids)
            or any(value < 1 for value in self.broker_mount_ids)
        ):
            raise _error("execution plan export or broker mount identity is invalid")

    @classmethod
    def from_pinned_sources(cls, pinned: PinnedSources) -> ExecutionPlanV1:
        return cls(
            tuple(item.export for item in pinned.sources),
            tuple(item.mount_id for item in pinned.sources),
        )

    def to_bytes(self) -> bytes:
        body = bytearray()
        for export, mount_id in zip(self.exports, self.broker_mount_ids, strict=True):
            target = export.virtual_target.encode("utf-8")
            if not 1 <= len(target) <= _MAX_TARGET_BYTES:
                raise _error("execution plan target is invalid")
            body.extend(
                _ENTRY.pack(
                    export.descriptor_slot,
                    _access(export.access_mode),
                    _kind(export.kind),
                    0,
                    export.identity.device,
                    export.identity.inode,
                    mount_id,
                    len(target),
                )
            )
            body.extend(target)
        return _HEADER.pack(_MAGIC, _VERSION, len(self.exports)) + body


def create_sealed_execution_plan(plan: ExecutionPlanV1) -> int:
    """Build immutable `memfd`; broker passes duplicate only at fixed FD 5."""
    descriptor = os.memfd_create("aspr-execution-plan", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        _write_all(descriptor, plan.to_bytes())
        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.fcntl(
            descriptor,
            fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL,
        )
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _access(value: AccessMode) -> int:
    return 1 if value is AccessMode.READ_ONLY else 2


def _kind(value: str) -> int:
    if value == ExportKind.FILE.value:
        return 1
    if value == ExportKind.DIRECTORY.value:
        return 2
    raise _error("execution plan kind is invalid")


def _write_all(descriptor: int, data: bytes) -> None:
    remaining = memoryview(data)
    while remaining:
        count = os.write(descriptor, remaining)
        if count <= 0:
            raise _error("execution plan write made no progress")
        remaining = remaining[count:]


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="execution plan was rejected",
        unsafe_reason="worker receives only sealed descriptor identities",
        next_action="rebuild plan through authenticated broker",
    )
