"""Descriptor-pinning remote export resolver.

Trusted roots are opened once. Untrusted source paths are then resolved only
relative to those descriptors through ``openat2``; no validated path is opened
again by name.
"""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import PurePosixPath

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import ExportKind
from astral_project.server import linux

_FILESYSTEM_TYPES = {
    0x01021994: "tmpfs",
    0x00006969: "nfs",
    0x0000EF53: "ext4",
    0x58465342: "xfs",
    0x794C7630: "overlay",
    0x65735546: "fuse",
}
_OPEN_FLAGS = getattr(os, "O_PATH", 0o10000000) | os.O_CLOEXEC | os.O_NOFOLLOW
_OPEN_RESOLVE = linux.RESOLVE_BENEATH | linux.RESOLVE_NO_MAGICLINKS | linux.RESOLVE_NO_SYMLINKS


@dataclass(slots=True)
class TrustedRoot:
    """A configured root pinned before untrusted grant path handling."""

    canonical_path: str
    descriptor: int

    @classmethod
    def open(cls, canonical_path: str) -> TrustedRoot:
        _validate_absolute_path(canonical_path, field_name="trusted root", allow_root=True)
        try:
            descriptor = os.open(canonical_path, _OPEN_FLAGS | os.O_DIRECTORY)
        except OSError as error:
            raise _resolution_error("could not open trusted root", error) from error
        return cls(canonical_path, descriptor)

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __enter__(self) -> TrustedRoot:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    device: int
    inode: int
    mount_id: int
    filesystem_type: str
    kind: ExportKind


@dataclass(slots=True)
class ResolvedSource:
    """Validated canonical display path plus ownership of pinned O_PATH descriptor."""

    canonical_path: str
    descriptor: int
    identity: SourceIdentity
    nested_mounts: tuple[MountTopology, ...]

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1

    def __enter__(self) -> ResolvedSource:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class MountTopology:
    mount_id: int
    parent_mount_id: int
    mount_point: str
    filesystem_type: str


def resolve_source(root: TrustedRoot, requested_path: str) -> ResolvedSource:
    """Pin one absolute grant source below a trusted root without symlink traversal."""
    relative_path = _relative_to_root(root.canonical_path, requested_path)
    try:
        descriptor = (
            os.dup(root.descriptor)
            if not relative_path
            else linux.openat2(root.descriptor, relative_path.encode(), _OPEN_FLAGS, _OPEN_RESOLVE)
        )
    except OSError as error:
        raise _resolution_error("source path was rejected during safe resolution", error) from error
    try:
        details = linux.statx_descriptor(descriptor)
        kind = _export_kind(details.mode)
        filesystem_magic = linux.filesystem_magic(descriptor)
        if linux.is_autofs(filesystem_magic):
            raise _autofs_error()
        identity = SourceIdentity(
            device=details.device,
            inode=details.inode,
            mount_id=details.mount_id,
            filesystem_type=_filesystem_name(filesystem_magic),
            kind=kind,
        )
        canonical_path = _canonical_display_path(root.canonical_path, relative_path)
        return ResolvedSource(
            canonical_path=canonical_path,
            descriptor=descriptor,
            identity=identity,
            nested_mounts=_nested_mounts(canonical_path, details.mount_id),
        )
    except Exception:
        os.close(descriptor)
        raise


def _relative_to_root(root: str, requested_path: str) -> str:
    _validate_absolute_path(requested_path, field_name="source path")
    root_parts = PurePosixPath(root).parts
    requested_parts = PurePosixPath(requested_path).parts
    if requested_parts[: len(root_parts)] != root_parts:
        raise _path_error("source path is outside trusted root")
    relative_parts = requested_parts[len(root_parts) :]
    return "/".join(relative_parts)


def _canonical_display_path(root: str, relative_path: str) -> str:
    if not relative_path:
        return root
    return root.rstrip("/") + "/" + relative_path


def _validate_absolute_path(path: str, *, field_name: str, allow_root: bool = False) -> None:
    if (
        not path.startswith("/")
        or "\x00" in path
        or (path == "/" and not allow_root)
        or (path != "/" and any(component in {"", ".", ".."} for component in path.split("/")[1:]))
    ):
        raise _path_error(f"{field_name} must be non-root absolute normalized path")


def _export_kind(mode: int) -> ExportKind:
    if stat.S_ISREG(mode):
        return ExportKind.FILE
    if stat.S_ISDIR(mode):
        return ExportKind.DIRECTORY
    raise _path_error("source object must be regular file or directory")


def _filesystem_name(filesystem_magic: int) -> str:
    return _FILESYSTEM_TYPES.get(filesystem_magic, f"magic:0x{filesystem_magic:08x}")


def _nested_mounts(canonical_path: str, source_mount_id: int) -> tuple[MountTopology, ...]:
    """Read mount metadata only; it never reopens source path by name."""
    try:
        with open("/proc/self/mountinfo", encoding="utf-8") as stream:
            lines = stream.read().splitlines()
    except OSError as error:
        raise _resolution_error("could not inspect mount topology", error) from error
    result: list[MountTopology] = []
    prefix = canonical_path.rstrip("/") + "/"
    for line in lines:
        topology = _parse_mountinfo(line)
        if topology is None or topology.mount_id == source_mount_id:
            continue
        if topology.mount_point.startswith(prefix):
            result.append(topology)
    return tuple(sorted(result, key=lambda item: (item.mount_point, item.mount_id)))


def _parse_mountinfo(line: str) -> MountTopology | None:
    fields = line.split()
    try:
        separator = fields.index("-")
        mount_id = int(fields[0])
        parent_mount_id = int(fields[1])
        mount_point = _unescape_mountinfo(fields[4])
        filesystem_type = fields[separator + 1]
    except (IndexError, ValueError):
        return None
    return MountTopology(mount_id, parent_mount_id, mount_point, filesystem_type)


def _unescape_mountinfo(value: str) -> str:
    for escaped, character in ((r"\040", " "), (r"\011", "\t"), (r"\012", "\n"), (r"\134", "\\")):
        value = value.replace(escaped, character)
    return value


def _path_error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PATH_RESOLUTION,
        message=message,
        security_result="remote source path was rejected",
        unsafe_reason="export source must remain below pinned trusted root without indirection",
        next_action="choose a normalized regular file or directory below allowed root",
    )


def _autofs_error() -> AstralError:
    return AstralError(
        code=ErrorCode.PATH_AUTOFS,
        message="autofs source is unsupported in strict mode",
        security_result="remote source path was rejected",
        unsafe_reason="automount behavior is not yet proven safe for descriptor-pinned staging",
        next_action="choose a non-autofs source or complete filesystem compatibility validation",
    )


def _resolution_error(message: str, error: OSError) -> AstralError:
    if error.errno in {errno.ENOSYS, errno.EOPNOTSUPP}:
        code = ErrorCode.PATH_UNSUPPORTED
    else:
        code = ErrorCode.PATH_RESOLUTION
    return AstralError(
        code=code,
        message=message,
        security_result="remote source path was rejected",
        unsafe_reason="safe descriptor-relative resolution could not be proven",
        next_action="repair source path or use host with supported Linux resolution primitives",
        dependency_error=str(error),
    )
