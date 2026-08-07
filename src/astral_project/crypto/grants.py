"""Version-1 canonical signed grant format."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Self

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.cbor import CborValue, canonical_dumps, canonical_loads
from astral_project.crypto.keys import sign, verify

GRANT_FORMAT_VERSION = 1
NONCE_LENGTH = 32
SIGNATURE_LENGTH = 64


class AccessMode(StrEnum):
    READ_ONLY = "ro"
    READ_WRITE = "rw"


class ExportKind(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"


def _grant_error(message: str, *, code: ErrorCode = ErrorCode.GRANT_INVALID) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="grant was rejected",
        unsafe_reason="signed capability fields must be complete and unambiguous",
        next_action="create or validate grant again",
    )


def _absolute_path(value: str, field_name: str) -> str:
    if (
        not value.startswith("/")
        or "\x00" in value
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise _grant_error(f"{field_name} must be an absolute normalized path")
    return value


def _extension_mapping(value: Mapping[str, CborValue], field_name: str) -> dict[str, CborValue]:
    result = dict(value)
    if any(not key or "\x00" in key for key in result):
        raise _grant_error(
            f"{field_name} has invalid extension name", code=ErrorCode.GRANT_EXTENSION
        )
    return result


@dataclass(frozen=True, slots=True)
class SourceIdentity:
    """Portable signed source-object identity; mount identity is broker-local."""

    device: int
    inode: int
    filesystem_type: str
    object_type: ExportKind

    def __post_init__(self) -> None:
        if min(self.device, self.inode) < 0 or not self.filesystem_type:
            raise _grant_error("source identity is invalid")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "device": self.device,
            "filesystem_type": self.filesystem_type,
            "inode": self.inode,
            "object_type": self.object_type.value,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> Self:
        try:
            return cls(
                device=_integer(payload, "device"),
                inode=_integer(payload, "inode"),
                filesystem_type=_string(payload, "filesystem_type"),
                object_type=ExportKind(_string(payload, "object_type")),
            )
        except ValueError as error:
            raise _grant_error("source identity has unsupported object type") from error


@dataclass(frozen=True, slots=True)
class GrantExport:
    requested_source: str
    canonical_source: str
    virtual_target: str
    access_mode: AccessMode
    kind: ExportKind
    source_identity: SourceIdentity

    def __post_init__(self) -> None:
        _absolute_path(self.requested_source, "requested_source")
        _absolute_path(self.canonical_source, "canonical_source")
        _absolute_path(self.virtual_target, "virtual_target")
        if self.source_identity.object_type is not self.kind:
            raise _grant_error("export kind does not match source identity")

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "access_mode": self.access_mode.value,
            "canonical_source": self.canonical_source,
            "kind": self.kind.value,
            "requested_source": self.requested_source,
            "source_identity": self.source_identity.to_payload(),
            "virtual_target": self.virtual_target,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> Self:
        try:
            source_identity = _mapping(payload, "source_identity")
            return cls(
                requested_source=_string(payload, "requested_source"),
                canonical_source=_string(payload, "canonical_source"),
                virtual_target=_string(payload, "virtual_target"),
                access_mode=AccessMode(_string(payload, "access_mode")),
                kind=ExportKind(_string(payload, "kind")),
                source_identity=SourceIdentity.from_payload(source_identity),
            )
        except ValueError as error:
            raise _grant_error("export has unsupported access mode or kind") from error


@dataclass(frozen=True, slots=True)
class Grant:
    grant_id: GrantId
    issuer_key_id: IssuerKeyId
    host_id: HostId
    ssh_host_key_fingerprint: str
    remote_user: str
    issued_at: int
    not_before: int
    expires_at: int
    nonce: bytes
    exports: tuple[GrantExport, ...]
    requested_features: tuple[str, ...] = ()
    server_policy_hash: bytes | None = None
    mandatory_extensions: Mapping[str, CborValue] = field(default_factory=dict)
    optional_extensions: Mapping[str, CborValue] = field(default_factory=dict)
    format_version: int = GRANT_FORMAT_VERSION

    def __post_init__(self) -> None:
        if self.format_version != GRANT_FORMAT_VERSION:
            raise _grant_error("unsupported grant format version")
        if not self.ssh_host_key_fingerprint or "\x00" in self.ssh_host_key_fingerprint:
            raise _grant_error("SSH host key fingerprint is invalid")
        if not self.remote_user or "\x00" in self.remote_user:
            raise _grant_error("remote user is invalid")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (self.issued_at, self.not_before, self.expires_at)
        ):
            raise _grant_error("grant times must be integer UTC seconds")
        if not self.issued_at <= self.not_before < self.expires_at:
            raise _grant_error("grant time window is invalid")
        if len(self.nonce) != NONCE_LENGTH:
            raise _grant_error("grant nonce must be 32 bytes")
        if not self.exports:
            raise _grant_error("grant requires at least one export")
        if tuple(sorted(set(self.requested_features))) != self.requested_features:
            raise _grant_error("requested features must be unique sorted strings")
        if self.server_policy_hash is not None and len(self.server_policy_hash) != 32:
            raise _grant_error("server policy hash must be 32 bytes")
        object.__setattr__(
            self,
            "mandatory_extensions",
            _extension_mapping(self.mandatory_extensions, "mandatory_extensions"),
        )
        object.__setattr__(
            self,
            "optional_extensions",
            _extension_mapping(self.optional_extensions, "optional_extensions"),
        )

    def to_payload(self) -> dict[str, CborValue]:
        return {
            "expires_at": self.expires_at,
            "exports": [export.to_payload() for export in self.exports],
            "format_version": self.format_version,
            "grant_id": self.grant_id.value,
            "issued_at": self.issued_at,
            "issuer_key_id": self.issuer_key_id.value,
            "mandatory_extensions": dict(self.mandatory_extensions),
            "nonce": self.nonce,
            "not_before": self.not_before,
            "optional_extensions": dict(self.optional_extensions),
            "remote_user": self.remote_user,
            "requested_features": list(self.requested_features),
            "server_policy_hash": self.server_policy_hash,
            "ssh_host_key_fingerprint": self.ssh_host_key_fingerprint,
            "host_id": self.host_id.value,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.to_payload())

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> Self:
        _exact_fields(
            payload,
            {
                "expires_at",
                "exports",
                "format_version",
                "grant_id",
                "host_id",
                "issued_at",
                "issuer_key_id",
                "mandatory_extensions",
                "nonce",
                "not_before",
                "optional_extensions",
                "remote_user",
                "requested_features",
                "server_policy_hash",
                "ssh_host_key_fingerprint",
            },
        )
        exports_value = _list(payload, "exports")
        features = _list(payload, "requested_features")
        return cls(
            grant_id=GrantId(_string(payload, "grant_id")),
            issuer_key_id=IssuerKeyId(_string(payload, "issuer_key_id")),
            host_id=HostId(_string(payload, "host_id")),
            ssh_host_key_fingerprint=_string(payload, "ssh_host_key_fingerprint"),
            remote_user=_string(payload, "remote_user"),
            issued_at=_integer(payload, "issued_at"),
            not_before=_integer(payload, "not_before"),
            expires_at=_integer(payload, "expires_at"),
            nonce=_bytes(payload, "nonce"),
            exports=tuple(
                GrantExport.from_payload(_object_mapping(item, "export")) for item in exports_value
            ),
            requested_features=tuple(_string_value(item, "requested feature") for item in features),
            server_policy_hash=_optional_bytes(payload, "server_policy_hash"),
            mandatory_extensions=_cbor_mapping(payload, "mandatory_extensions"),
            optional_extensions=_cbor_mapping(payload, "optional_extensions"),
            format_version=_integer(payload, "format_version"),
        )


@dataclass(frozen=True, slots=True)
class GrantVerificationContext:
    host_id: HostId
    ssh_host_key_fingerprint: str
    remote_user: str
    now: int
    known_mandatory_extensions: frozenset[str] = frozenset()
    known_optional_extensions: frozenset[str] = frozenset()
    allow_unknown_optional_extensions: bool = False


@dataclass(frozen=True, slots=True)
class SignedGrant:
    grant: Grant
    signature: bytes

    def __post_init__(self) -> None:
        if len(self.signature) != SIGNATURE_LENGTH:
            raise _grant_error("Ed25519 signature must be 64 bytes")

    @classmethod
    def create(cls, grant: Grant, key: Ed25519PrivateKey) -> Self:
        return cls(grant=grant, signature=sign(key, grant.canonical_bytes()))

    def to_cbor(self) -> bytes:
        return canonical_dumps({"grant": self.grant.to_payload(), "signature": self.signature})

    @classmethod
    def from_cbor(cls, data: bytes) -> Self:
        envelope = _object_mapping(canonical_loads(data), "grant envelope")
        _exact_fields(envelope, {"grant", "signature"})
        return cls(
            grant=Grant.from_payload(_mapping(envelope, "grant")),
            signature=_bytes(envelope, "signature"),
        )

    def verify(self, key: Ed25519PublicKey, context: GrantVerificationContext) -> Grant:
        if not verify(key, self.signature, self.grant.canonical_bytes()):
            raise _grant_error(
                "grant signature verification failed", code=ErrorCode.CRYPTO_SIGNATURE
            )
        if self.grant.host_id != context.host_id:
            raise _grant_error(
                "grant host does not match connection", code=ErrorCode.CRYPTO_CONTEXT
            )
        if self.grant.ssh_host_key_fingerprint != context.ssh_host_key_fingerprint:
            raise _grant_error(
                "grant SSH host key fingerprint does not match", code=ErrorCode.CRYPTO_CONTEXT
            )
        if self.grant.remote_user != context.remote_user:
            raise _grant_error("grant remote user does not match", code=ErrorCode.CRYPTO_CONTEXT)
        if context.now < self.grant.not_before:
            raise _grant_error("grant is not valid yet", code=ErrorCode.CRYPTO_CONTEXT)
        if context.now >= self.grant.expires_at:
            raise _grant_error("grant has expired", code=ErrorCode.CRYPTO_CONTEXT)
        unknown_mandatory = set(self.grant.mandatory_extensions).difference(
            context.known_mandatory_extensions
        )
        if unknown_mandatory:
            raise _grant_error(
                "grant has unknown mandatory extension", code=ErrorCode.GRANT_EXTENSION
            )
        unknown_optional = set(self.grant.optional_extensions).difference(
            context.known_optional_extensions
        )
        if unknown_optional and not context.allow_unknown_optional_extensions:
            raise _grant_error(
                "grant has optional extension rejected by policy", code=ErrorCode.GRANT_EXTENSION
            )
        return self.grant


def _object_mapping(value: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or not all(isinstance(key, str) for key in value):
        raise _grant_error(f"{field_name} must be a text-keyed map")
    return value


def _mapping(payload: Mapping[str, object], field_name: str) -> Mapping[str, object]:
    try:
        return _object_mapping(payload[field_name], field_name)
    except KeyError as error:
        raise _grant_error(f"grant missing {field_name}") from error


def _cbor_mapping(payload: Mapping[str, object], field_name: str) -> Mapping[str, CborValue]:
    return _mapping(payload, field_name)  # type: ignore[return-value]


def _string_value(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise _grant_error(f"{field_name} must be text")
    return value


def _string(payload: Mapping[str, object], field_name: str) -> str:
    try:
        return _string_value(payload[field_name], field_name)
    except KeyError as error:
        raise _grant_error(f"grant missing {field_name}") from error


def _integer(payload: Mapping[str, object], field_name: str) -> int:
    try:
        value = payload[field_name]
    except KeyError as error:
        raise _grant_error(f"grant missing {field_name}") from error
    if isinstance(value, bool) or not isinstance(value, int):
        raise _grant_error(f"{field_name} must be integer")
    return value


def _bytes(payload: Mapping[str, object], field_name: str) -> bytes:
    try:
        value = payload[field_name]
    except KeyError as error:
        raise _grant_error(f"grant missing {field_name}") from error
    if not isinstance(value, bytes):
        raise _grant_error(f"{field_name} must be bytes")
    return value


def _optional_bytes(payload: Mapping[str, object], field_name: str) -> bytes | None:
    try:
        value = payload[field_name]
    except KeyError as error:
        raise _grant_error(f"grant missing {field_name}") from error
    if value is None:
        return None
    if not isinstance(value, bytes):
        raise _grant_error(f"{field_name} must be bytes or null")
    return value


def _list(payload: Mapping[str, object], field_name: str) -> list[object]:
    try:
        value = payload[field_name]
    except KeyError as error:
        raise _grant_error(f"grant missing {field_name}") from error
    if not isinstance(value, list):
        raise _grant_error(f"{field_name} must be array")
    return value


def _exact_fields(payload: Mapping[str, object], expected: set[str]) -> None:
    if set(payload) != expected:
        raise _grant_error("grant field set is invalid")
