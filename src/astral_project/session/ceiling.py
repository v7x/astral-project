"""Packet 14B root-owned server-ceiling schema and pure GrantV1 validation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Self

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
class ServerCeilingV1:
    """Root-owned policy input; worker never receives this object or its paths."""

    allowed_source_roots: tuple[str, ...]
    allowed_issuers: tuple[IssuerKeyId, ...]
    allowed_kinds: tuple[ExportKind, ...]
    allow_read_write: bool
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
        _roots(self.allowed_source_roots, "allowed source roots", require_nonempty=True)
        _roots(self.forbidden_source_roots, "forbidden source roots", require_nonempty=False)
        if not self.allowed_issuers or not self.allowed_kinds:
            raise _error("server ceiling requires issuer and type allowlists")
        if (
            tuple(sorted(set(self.allowed_issuers), key=lambda item: item.value))
            != self.allowed_issuers
        ):
            raise _error("server ceiling issuer list must be unique sorted")
        if (
            tuple(sorted(set(self.allowed_kinds), key=lambda item: item.value))
            != self.allowed_kinds
        ):
            raise _error("server ceiling type list must be unique sorted")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "allowed_issuers": [item.value for item in self.allowed_issuers],
            "allowed_kinds": [item.value for item in self.allowed_kinds],
            "allowed_source_roots": list(self.allowed_source_roots),
            "allow_read_write": self.allow_read_write,
            "forbidden_source_roots": list(self.forbidden_source_roots),
            "max_exports": self.max_exports,
            "max_ttl_seconds": self.max_ttl_seconds,
            "policy_hash": self.policy_hash,
            "version": self.version,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())

    @classmethod
    def from_cbor(cls, data: bytes) -> Self:
        decoded = canonical_loads(data)
        expected = {
            "allowed_issuers",
            "allowed_kinds",
            "allowed_source_roots",
            "allow_read_write",
            "forbidden_source_roots",
            "max_exports",
            "max_ttl_seconds",
            "policy_hash",
            "version",
        }
        if not isinstance(decoded, Mapping) or set(decoded) != expected:
            raise _error("server ceiling fields are incomplete or unknown")
        try:
            return cls(
                allowed_source_roots=_strings(decoded, "allowed_source_roots"),
                allowed_issuers=tuple(
                    IssuerKeyId(value) for value in _strings(decoded, "allowed_issuers")
                ),
                allowed_kinds=tuple(
                    ExportKind(value) for value in _strings(decoded, "allowed_kinds")
                ),
                allow_read_write=_boolean(decoded, "allow_read_write"),
                forbidden_source_roots=_strings(decoded, "forbidden_source_roots"),
                max_exports=_integer(decoded, "max_exports"),
                max_ttl_seconds=_integer(decoded, "max_ttl_seconds"),
                policy_hash=_bytes(decoded, "policy_hash"),
                version=_integer(decoded, "version"),
            )
        except ValueError as error:
            raise _error("server ceiling identifiers or kinds are invalid") from error


def validate_grant_against_ceiling(grant: Grant, ceiling: ServerCeilingV1) -> None:
    """Pure root-owned ceiling check. Signature/context verification happens before this."""
    if grant.issuer_key_id not in ceiling.allowed_issuers:
        raise _error("grant issuer is outside server ceiling")
    if len(grant.exports) > ceiling.max_exports:
        raise _error("grant export count exceeds server ceiling")
    if grant.expires_at - grant.issued_at > ceiling.max_ttl_seconds:
        raise _error("grant lifetime exceeds server ceiling")
    if grant.server_policy_hash is not None and grant.server_policy_hash != ceiling.policy_hash:
        raise _error("grant server policy hash does not match server ceiling")
    for export in grant.exports:
        if export.kind not in ceiling.allowed_kinds:
            raise _error("grant export type is outside server ceiling")
        if export.access_mode is AccessMode.READ_WRITE and not ceiling.allow_read_write:
            raise _error("read-write export is outside server ceiling")
        if not _under_any(export.canonical_source, ceiling.allowed_source_roots):
            raise _error("grant source is outside allowed server roots")
        if _under_any(export.canonical_source, ceiling.forbidden_source_roots):
            raise _error("grant source is under forbidden server root")


def _roots(values: tuple[str, ...], name: str, *, require_nonempty: bool) -> None:
    if (require_nonempty and not values) or tuple(sorted(set(values), key=str.encode)) != values:
        raise _error(f"{name} must be unique sorted paths")
    for value in values:
        if (
            not value.startswith("/")
            or "\x00" in value
            or any(part in {".", ".."} for part in value.split("/"))
        ):
            raise _error(f"{name} contains invalid path")


def _under_any(path: str, roots: tuple[str, ...]) -> bool:
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


def _strings(payload: Mapping[str, object], field: str) -> tuple[str, ...]:
    value = payload.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise _error(f"{field} must be string list")
    return tuple(value)


def _bytes(payload: Mapping[str, object], field: str) -> bytes:
    value = payload.get(field)
    if not isinstance(value, bytes):
        raise _error(f"{field} must be bytes")
    return value


def _boolean(payload: Mapping[str, object], field: str) -> bool:
    value = payload.get(field)
    if not isinstance(value, bool):
        raise _error(f"{field} must be boolean")
    return value


def _integer(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(f"{field} must be integer")
    return value
