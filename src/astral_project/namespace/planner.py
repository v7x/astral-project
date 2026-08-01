"""Packet 14 deterministic namespace plan derived from already validated GrantV1.

This module performs no process, descriptor, namespace, mount, broker, or IPC operation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Self

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.cbor import CborValue, canonical_dumps, canonical_loads
from astral_project.crypto.grants import AccessMode, ExportKind, Grant, SourceIdentity

NAMESPACE_PLAN_FORMAT_VERSION = 1
INTERNAL_STAGING_ROOT = "/.astral-project/staging"
RUNTIME_ROOT = "/.astral-project-runtime"


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PATH_RESOLUTION,
        message=message,
        security_result="namespace plan was rejected",
        unsafe_reason="ambiguous virtual targets could change namespace authority",
        next_action="issue a grant with non-overlapping virtual targets",
    )


@dataclass(frozen=True, slots=True)
class PlannedExport:
    """Descriptor-slot request; deliberately contains no source pathname."""

    access_mode: AccessMode
    descriptor_slot: int
    identity: SourceIdentity
    kind: str
    virtual_target: str

    def __post_init__(self) -> None:
        if self.descriptor_slot < 0:
            raise _error("descriptor slot is invalid")
        if self.identity.object_type.value != self.kind:
            raise _error("planned export kind does not match descriptor identity")
        _normalized_target(self.virtual_target)

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "access_mode": self.access_mode.value,
            "descriptor_slot": self.descriptor_slot,
            "identity": self.identity.to_payload(),
            "kind": self.kind,
            "virtual_target": self.virtual_target,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> Self:
        _exact_fields(
            payload, {"access_mode", "descriptor_slot", "identity", "kind", "virtual_target"}
        )
        try:
            return cls(
                access_mode=AccessMode(_string(payload, "access_mode")),
                descriptor_slot=_integer(payload, "descriptor_slot"),
                identity=SourceIdentity.from_payload(_mapping(payload, "identity")),
                kind=ExportKind(_string(payload, "kind")).value,
                virtual_target=_string(payload, "virtual_target"),
            )
        except ValueError as error:
            raise _error("planned export has unsupported access mode or kind") from error


@dataclass(frozen=True, slots=True)
class NamespacePlan:
    """Pure structural plan for later broker-issued sealed execution plan."""

    exports: tuple[PlannedExport, ...]
    staging_root: str = INTERNAL_STAGING_ROOT
    workload: str = "sftp_v1"
    format_version: int = NAMESPACE_PLAN_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != NAMESPACE_PLAN_FORMAT_VERSION:
            raise _error("unsupported namespace plan format version")
        if not self.exports:
            raise _error("namespace plan requires exports")
        if self.staging_root != INTERNAL_STAGING_ROOT or self.workload != "sftp_v1":
            raise _error("internal staging root or workload is not fixed")
        if tuple(sorted(export.descriptor_slot for export in self.exports)) != tuple(
            range(len(self.exports))
        ):
            raise _error("descriptor slots must be contiguous")
        targets = tuple(export.virtual_target for export in self.exports)
        if targets != tuple(sorted(targets, key=lambda target: target.encode("utf-8"))):
            raise _error("planned exports are not deterministically ordered")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "exports": [export.to_payload() for export in self.exports],
            "format_version": self.format_version,
            "staging_root": self.staging_root,
            "workload": self.workload,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())

    @classmethod
    def from_cbor(cls, data: bytes) -> Self:
        payload = canonical_loads(data)
        if not isinstance(payload, Mapping):
            raise _error("namespace plan payload must be map")
        _exact_fields(payload, {"exports", "format_version", "staging_root", "workload"})
        exports = _list(payload, "exports")
        return cls(
            exports=tuple(
                PlannedExport.from_payload(_mapping_item(item, "planned export"))
                for item in exports
            ),
            format_version=_integer(payload, "format_version"),
            staging_root=_string(payload, "staging_root"),
            workload=_string(payload, "workload"),
        )


def build_namespace_plan(grant: Grant) -> NamespacePlan:
    """Create stable target order and reject collisions before execution exists."""
    candidates = sorted(grant.exports, key=lambda export: export.virtual_target.encode("utf-8"))
    planned: list[PlannedExport] = []
    for export in candidates:
        target = _normalized_target(export.virtual_target)
        if _reserved(target):
            raise _error("virtual target overlaps reserved runtime path")
        candidate = PlannedExport(
            access_mode=export.access_mode,
            descriptor_slot=len(planned),
            identity=export.source_identity,
            kind=export.kind.value,
            virtual_target=target,
        )
        duplicate = next((item for item in planned if item.virtual_target == target), None)
        if duplicate is not None:
            if _same_export(duplicate, candidate):
                continue
            raise _error("virtual target collision")
        if any(_nested(item.virtual_target, target) for item in planned):
            raise _error("nested virtual targets require later explicit topology policy")
        planned.append(candidate)
    if not planned:
        raise _error("namespace plan requires exports")
    return NamespacePlan(exports=tuple(planned))


def _normalized_target(target: str) -> str:
    path = PurePosixPath(target)
    encoded = target.encode("utf-8")
    if (
        not target.startswith("/")
        or target == "/"
        or "\x00" in target
        or ".." in path.parts
        or str(path) != target
        or len(encoded) > 4096
        or any(len(part.encode("utf-8")) > 255 for part in path.parts)
    ):
        raise _error("virtual target must be bounded absolute normalized non-root path")
    return target


def _reserved(target: str) -> bool:
    return any(_paths_overlap(target, root) for root in (INTERNAL_STAGING_ROOT, RUNTIME_ROOT))


def _paths_overlap(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _nested(left: str, right: str) -> bool:
    return left.startswith(right + "/") or right.startswith(left + "/")


def _same_export(left: PlannedExport, right: PlannedExport) -> bool:
    return (
        left.access_mode == right.access_mode
        and left.identity == right.identity
        and left.kind == right.kind
        and left.virtual_target == right.virtual_target
    )


def _exact_fields(payload: Mapping[str, object], expected: set[str]) -> None:
    if set(payload) != expected:
        raise _error("namespace plan fields are incomplete or unknown")


def _mapping(payload: Mapping[str, object], field: str) -> Mapping[str, object]:
    value = payload.get(field)
    if not isinstance(value, Mapping):
        raise _error(f"{field} must be map")
    return value


def _mapping_item(value: object, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise _error(f"{field} must be map")
    return value


def _list(payload: Mapping[str, object], field: str) -> list[object]:
    value = payload.get(field)
    if not isinstance(value, list):
        raise _error(f"{field} must be list")
    return value


def _string(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise _error(f"{field} must be string")
    return value


def _integer(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(f"{field} must be integer")
    return value
