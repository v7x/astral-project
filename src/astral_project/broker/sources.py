"""Broker-owned opening and identity verification for worker source descriptors."""

from __future__ import annotations

import array
import os
import socket
import stat
from dataclasses import dataclass, field

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import Grant, GrantExport
from astral_project.namespace.planner import NamespacePlan, PlannedExport, build_namespace_plan
from astral_project.server import linux
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


def pin_grant_sources(
    grant: Grant, ceiling: ServerCeilingV1, *, target_uid: int | None = None, target_gid: int | None = None
) -> PinnedSources:
    """Resolve under target DAC, then clone descriptors only in the broker."""
    if target_uid is None or target_gid is None:
        return _pin_grant_sources(grant, ceiling, clone_mounts=True)
    return _pin_grant_sources_as_target(grant, ceiling, target_uid, target_gid)


def _pin_grant_sources(grant: Grant, ceiling: ServerCeilingV1, *, clone_mounts: bool) -> PinnedSources:
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
                _require_target_dac_access(source)
                _require_signed_identity(source, grant_export)
                revalidate_source_identity(source)
                if clone_mounts:
                    descriptor = linux.clone_mount(source.descriptor)
                    clone_identity = linux.statx_descriptor(descriptor)
                    if (
                        clone_identity.device != source.identity.device
                        or clone_identity.inode != source.identity.inode
                        or stat.S_IFMT(clone_identity.mode)
                        != (stat.S_IFREG if source.identity.kind.value == "file" else stat.S_IFDIR)
                    ):
                        os.close(descriptor)
                        raise _error("broker detached mount clone changed source identity")
                    pinned.append(PinnedSource(descriptor, export, clone_identity.mount_id))
                else:
                    pinned.append(PinnedSource(os.dup(source.descriptor), export, source.identity.mount_id))
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


def _pin_grant_sources_as_target(
    grant: Grant, ceiling: ServerCeilingV1, uid: int, gid: int
) -> PinnedSources:
    """A short-lived child enforces target DAC; parent never reopens a path."""
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    pid = os.fork()
    if pid == 0:
        parent.close()
        try:
            # Deliberately retain only authenticated primary group: extra
            # broker groups must not create source authority for the peer.
            os.setgroups([gid])
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)
            pinned = _pin_grant_sources(grant, ceiling, clone_mounts=False)
            try:
                child.sendmsg([b"O"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [item.descriptor for item in pinned.sources]))])
            finally:
                pinned.close()
            os._exit(0)
        except BaseException:
            try:
                child.send(b"E")
            finally:
                os._exit(1)
    child.close()
    message = b""
    ancillary: list[tuple[int, int, bytes]] = []
    flags = 0
    try:
        message, ancillary, flags, _ = parent.recvmsg(
            1, socket.CMSG_SPACE(len(grant.exports) * array.array("i").itemsize)
        )
    finally:
        parent.close()
        _, status = os.waitpid(pid, 0)

    descriptors: list[int] = []
    malformed_rights = False
    for level, kind, payload in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            continue
        item_size = array.array("i").itemsize
        if len(payload) % item_size:
            malformed_rights = True
        received = array.array("i")
        received.frombytes(payload[: len(payload) - (len(payload) % item_size)])
        descriptors.extend(received)
    if (
        message != b"O"
        or status != 0
        or flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC)
        or malformed_rights
        or len(descriptors) != len(grant.exports)
    ):
        for descriptor in descriptors:
            os.close(descriptor)
        raise _error("target-user DAC source resolution failed")

    raw = _pin_from_descriptors(grant, ceiling, descriptors)
    cloned: list[PinnedSource] = []
    try:
        for item in raw.sources:
            cloned.append(PinnedSource(linux.clone_mount(item.descriptor), item.export, 0))
    except Exception:
        for item in cloned:
            os.close(item.descriptor)
        raise
    finally:
        raw.close()

    try:
        checked: list[PinnedSource] = []
        for item in cloned:
            identity = linux.statx_descriptor(item.descriptor)
            expected_mode = stat.S_IFREG if item.export.kind == "file" else stat.S_IFDIR
            if (
                identity.device != item.export.identity.device
                or identity.inode != item.export.identity.inode
                or stat.S_IFMT(identity.mode) != expected_mode
            ):
                raise _error("broker detached mount clone changed source identity")
            checked.append(PinnedSource(item.descriptor, item.export, identity.mount_id))
        return PinnedSources(plan=raw.plan, sources=tuple(checked))
    except Exception:
        for item in cloned:
            os.close(item.descriptor)
        raise


def _pin_from_descriptors(grant: Grant, ceiling: ServerCeilingV1, descriptors: list[int]) -> PinnedSources:
    plan = build_namespace_plan(grant)
    if len(descriptors) != len(plan.exports):
        raise _error("target-user resolver returned wrong descriptor count")
    return PinnedSources(plan=plan, sources=tuple(PinnedSource(fd, export, 0) for fd, export in zip(descriptors, plan.exports, strict=True)))


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


def _require_target_dac_access(source: ResolvedSource) -> None:
    """Force a read open of the already pinned object under target credentials."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    if source.identity.kind.value == "directory":
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(f"/proc/self/fd/{source.descriptor}", flags)
    except OSError as error:
        raise _error("target user lacks source DAC access") from error
    os.close(descriptor)


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
