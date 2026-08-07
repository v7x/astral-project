"""Broker-owned opening and identity verification for worker source descriptors."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import Grant, GrantExport
from astral_project.namespace.planner import NamespacePlan, PlannedExport, build_namespace_plan
from astral_project.server.path_resolver import (
    ResolvedSource,
    TrustedRoot,
    resolve_source,
    revalidate_source_identity,
)
from astral_project.session.ceiling import ServerCeilingV1, validate_grant_against_ceiling


@dataclass(frozen=True, slots=True)
class PinnedSource:
    """Broker-pinned descriptor plus ephemeral broker-mount identity."""

    descriptor: int
    export: PlannedExport
    mount_id: int


@dataclass(slots=True)
class PinnedSources:
    """Own pinned descriptors until fixed-FD worker handoff or rejection."""

    plan: NamespacePlan
    sources: tuple[PinnedSource, ...]
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if tuple(item.export for item in self.sources) != self.plan.exports:
            raise _error("pinned sources do not match deterministic namespace plan")

    def close(self) -> None:
        if self._closed:
            return
        for source in self.sources:
            os.close(source.descriptor)
        self._closed = True

    def __enter__(self) -> PinnedSources:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def pin_grant_sources(grant: Grant, ceiling: ServerCeilingV1) -> PinnedSources:
    """Open signed sources only beneath root-owned roots; never reopen after pinning."""
    validate_grant_against_ceiling(grant, ceiling)
    plan = build_namespace_plan(grant)
    roots: dict[str, TrustedRoot] = {}
    pinned: list[PinnedSource] = []
    try:
        for export in plan.exports:
            grant_export = _grant_export_for_plan_export(grant, export)
            root_path = _root_for_source(grant_export.canonical_source, ceiling)
            root = roots.get(root_path)
            if root is None:
                root = TrustedRoot.open(root_path)
                roots[root_path] = root
            source = resolve_source(root, grant_export.canonical_source)
            try:
                _require_safe_broker_topology(source, root_path, ceiling)
                _require_signed_identity(source, grant_export)
                revalidate_source_identity(source)
                descriptor = source.descriptor
                source.descriptor = -1
                pinned.append(PinnedSource(descriptor, export, source.identity.mount_id))
            finally:
                source.close()
        return PinnedSources(plan=plan, sources=tuple(pinned))
    except Exception:
        for item in pinned:
            os.close(item.descriptor)
        raise
    finally:
        for root in roots.values():
            root.close()


def _grant_export_for_plan_export(grant: Grant, planned: PlannedExport) -> GrantExport:
    matches = tuple(
        export
        for export in grant.exports
        if export.virtual_target == planned.virtual_target
        and export.access_mode == planned.access_mode
        and export.kind.value == planned.kind
        and export.source_identity == planned.identity
    )
    if not matches:
        raise _error("namespace plan export is absent from signed grant")
    return matches[0]


def _root_for_source(source: str, ceiling: ServerCeilingV1) -> str:
    matches = tuple(
        root.canonical_root
        for root in ceiling.source_roots
        if source == root.canonical_root or source.startswith(root.canonical_root.rstrip("/") + "/")
    )
    if len(matches) != 1:
        raise _error("signed source has no unique configured root")
    return matches[0]


def _require_signed_identity(source: ResolvedSource, export: GrantExport) -> None:
    identity = source.identity
    signed = export.source_identity
    if (
        source.canonical_path != export.canonical_source
        or identity.device != signed.device
        or identity.inode != signed.inode
        or identity.filesystem_type != signed.filesystem_type
        or identity.kind is not signed.object_type
    ):
        raise _error("pinned source does not match signed source identity")


def _require_safe_broker_topology(
    source: ResolvedSource, root_path: str, ceiling: ServerCeilingV1
) -> None:
    """V1 permits only tested local ext4 and no nested mount import."""
    root = next(item for item in ceiling.source_roots if item.canonical_root == root_path)
    if source.identity.filesystem_type != "ext4":
        raise _error("source filesystem is unsupported by strict V1")
    if root.nested_mount_policy == "forbid" and source.nested_mounts:
        raise _error("source contains nested mounts forbidden by server ceiling")


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PATH_RESOLUTION,
        message=message,
        security_result="broker source descriptor was rejected",
        unsafe_reason="worker authority requires a root-owned descriptor matching signed identity",
        next_action="issue a current grant for configured source root",
    )
