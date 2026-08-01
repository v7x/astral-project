"""Packet 14B root-owned per-source-root ceiling and GrantV1 validation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self, cast

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import IssuerKeyId
from astral_project.crypto.cbor import CborValue, canonical_dumps, canonical_loads
from astral_project.crypto.grants import AccessMode, ExportKind, Grant
from astral_project.session.contracts import SESSION_FORMAT_VERSION


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.GRANT_INVALID,
        message=message,
        security_result="server ceiling rejected grant",
        unsafe_reason="signed grant cannot exceed independently administered server limits",
        next_action="issue grant within root-owned server ceiling",
    )


@dataclass(frozen=True, slots=True)
class SourceRootCeilingV1:
    """One non-overlapping administrator-owned export root."""

    canonical_root: str
    maximum_access: AccessMode
    allowed_kinds: tuple[ExportKind, ...]
    nested_mount_policy: str = "forbid"

    def __post_init__(self) -> None:
        _path(self.canonical_root, "source root")
        if (
            not self.allowed_kinds
            or tuple(sorted(set(self.allowed_kinds), key=lambda item: item.value))
            != self.allowed_kinds
        ):
            raise _error("source root kinds must be unique sorted")
        if self.nested_mount_policy not in {"forbid", "advisory"}:
            raise _error("source root nested mount policy is invalid")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "allowed_kinds": [item.value for item in self.allowed_kinds],
            "canonical_root": self.canonical_root,
            "maximum_access": self.maximum_access.value,
            "nested_mount_policy": self.nested_mount_policy,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> Self:
        if set(payload) != {
            "allowed_kinds",
            "canonical_root",
            "maximum_access",
            "nested_mount_policy",
        }:
            raise _error("source root ceiling fields are incomplete or unknown")
        try:
            return cls(
                canonical_root=_string(payload, "canonical_root"),
                maximum_access=AccessMode(_string(payload, "maximum_access")),
                allowed_kinds=tuple(
                    ExportKind(item) for item in _strings(payload, "allowed_kinds")
                ),
                nested_mount_policy=_string(payload, "nested_mount_policy"),
            )
        except ValueError as error:
            raise _error("source root ceiling kind or access is invalid") from error


@dataclass(frozen=True, slots=True)
class ServerCeilingV1:
    """Root-owned policy input; worker never receives this object or its paths."""

    source_roots: tuple[SourceRootCeilingV1, ...]
    allowed_issuers: tuple[IssuerKeyId, ...]
    forbidden_source_roots: tuple[str, ...]
    max_exports: int
    max_ttl_seconds: int
    policy_hash: bytes
    version: int = SESSION_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.version != SESSION_FORMAT_VERSION:
            raise _error("unsupported server ceiling version")
        if len(self.policy_hash) != 32:
            raise _error("server ceiling policy hash must be 32 bytes")
        if self.max_exports < 1 or self.max_ttl_seconds < 1:
            raise _error("server ceiling limits are invalid")
        if not self.source_roots:
            raise _error("server ceiling requires source roots")
        roots = tuple(item.canonical_root for item in self.source_roots)
        if roots != tuple(sorted(roots, key=str.encode)) or len(set(roots)) != len(roots):
            raise _error("source roots must be unique sorted")
        if any(
            paths_overlap(left, right)
            for index, left in enumerate(roots)
            for right in roots[index + 1 :]
        ):
            raise _error("overlapping source roots require explicit precedence ADR")
        _roots(self.forbidden_source_roots, "forbidden source roots", require_nonempty=False)
        if (
            not self.allowed_issuers
            or tuple(sorted(set(self.allowed_issuers), key=lambda item: item.value))
            != self.allowed_issuers
        ):
            raise _error("server ceiling issuer list must be unique sorted")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "allowed_issuers": [item.value for item in self.allowed_issuers],
            "forbidden_source_roots": list(self.forbidden_source_roots),
            "max_exports": self.max_exports,
            "max_ttl_seconds": self.max_ttl_seconds,
            "policy_hash": self.policy_hash,
            "source_roots": [item.to_payload() for item in self.source_roots],
            "version": self.version,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())

    @classmethod
    def from_cbor(cls, data: bytes) -> Self:
        decoded = canonical_loads(data)
        expected = {
            "allowed_issuers",
            "forbidden_source_roots",
            "max_exports",
            "max_ttl_seconds",
            "policy_hash",
            "source_roots",
            "version",
        }
        if not isinstance(decoded, Mapping) or set(decoded) != expected:
            raise _error("server ceiling fields are incomplete or unknown")
        roots = decoded.get("source_roots")
        if not isinstance(roots, list) or not all(isinstance(item, Mapping) for item in roots):
            raise _error("source_roots must be map list")
        try:
            return cls(
                source_roots=tuple(
                    SourceRootCeilingV1.from_payload(cast(Mapping[str, object], item))
                    for item in roots
                ),
                allowed_issuers=tuple(
                    IssuerKeyId(value) for value in _strings(decoded, "allowed_issuers")
                ),
                forbidden_source_roots=_strings(decoded, "forbidden_source_roots"),
                max_exports=_integer(decoded, "max_exports"),
                max_ttl_seconds=_integer(decoded, "max_ttl_seconds"),
                policy_hash=_bytes(decoded, "policy_hash"),
                version=_integer(decoded, "version"),
            )
        except ValueError as error:
            raise _error("server ceiling identifiers are invalid") from error


def validate_grant_against_ceiling(grant: Grant, ceiling: ServerCeilingV1) -> None:
    if grant.issuer_key_id not in ceiling.allowed_issuers:
        raise _error("grant issuer is outside server ceiling")
    if len(grant.exports) > ceiling.max_exports:
        raise _error("grant export count exceeds server ceiling")
    if grant.expires_at - grant.issued_at > ceiling.max_ttl_seconds:
        raise _error("grant lifetime exceeds server ceiling")
    if grant.server_policy_hash is not None and grant.server_policy_hash != ceiling.policy_hash:
        raise _error("grant server policy hash does not match server ceiling")
    for export in grant.exports:
        root = next(
            (
                item
                for item in ceiling.source_roots
                if export.canonical_source == item.canonical_root
                or _under(export.canonical_source, item.canonical_root)
            ),
            None,
        )
        if root is None:
            raise _error("grant source is outside allowed server roots")
        if export.kind not in root.allowed_kinds:
            raise _error("grant export type is outside source root ceiling")
        if (
            export.access_mode is AccessMode.READ_WRITE
            and root.maximum_access is not AccessMode.READ_WRITE
        ):
            raise _error("read-write export is outside source root ceiling")
        if any(
            paths_overlap(export.canonical_source, forbidden)
            for forbidden in ceiling.forbidden_source_roots
        ):
            raise _error("grant source overlaps forbidden server root")


def paths_overlap(left: str, right: str) -> bool:
    """Component-aware relation for already canonical absolute paths."""
    return left == right or _under(left, right) or _under(right, left)


def _under(path: str, root: str) -> bool:
    return path != root and (root == "/" or path.startswith(root + "/"))


def _roots(values: tuple[str, ...], name: str, *, require_nonempty: bool) -> None:
    if (require_nonempty and not values) or tuple(sorted(set(values), key=str.encode)) != values:
        raise _error(f"{name} must be unique sorted paths")
    for value in values:
        _path(value, name)


def _path(value: str, name: str) -> None:
    if (
        not value.startswith("/")
        or "\x00" in value
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise _error(f"{name} contains invalid path")


def _strings(payload: Mapping[str, object], field: str) -> tuple[str, ...]:
    value = payload.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _error(f"{field} must be string list")
    return tuple(value)


def _string(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise _error(f"{field} must be string")
    return value


def _bytes(payload: Mapping[str, object], field: str) -> bytes:
    value = payload.get(field)
    if not isinstance(value, bytes):
        raise _error(f"{field} must be bytes")
    return value


def _integer(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(f"{field} must be integer")
    return value
