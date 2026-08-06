"""Root-owned VM authority artifacts: strict TOML and canonical ceiling CBOR."""

from __future__ import annotations

import base64
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import HostId, IssuerKeyId
from astral_project.session.ceiling import ServerCeilingV1


@dataclass(frozen=True, slots=True)
class AuthorityTomlV1:
    """Complete root-owned broker authority reference; no ambient defaults."""

    expected_peer_uid: int
    expected_peer_gid: int
    host_id: HostId
    ssh_host_key_fingerprint: str
    remote_user: str
    issuer_keys: tuple[tuple[IssuerKeyId, bytes], ...]
    transport_key_ids: tuple[str, ...]
    ceiling_path: Path

    def __post_init__(self) -> None:
        if self.expected_peer_uid < 1 or self.expected_peer_gid < 1:
            raise _error("authority peer UID or GID is invalid")
        if not self.ssh_host_key_fingerprint or not self.remote_user:
            raise _error("authority host binding is incomplete")
        if not self.ceiling_path.is_absolute():
            raise _error("authority ceiling path is not absolute")
        identifiers = tuple(identifier for identifier, _ in self.issuer_keys)
        if not identifiers or identifiers != tuple(sorted(set(identifiers), key=str)):
            raise _error("authority issuer key IDs must be unique sorted")
        if any(len(key) != 32 for _, key in self.issuer_keys):
            raise _error("authority issuer key is invalid")
        if not self.transport_key_ids or self.transport_key_ids != tuple(
            sorted(set(self.transport_key_ids))
        ):
            raise _error("authority transport key IDs must be unique sorted")

    def toml_bytes(self) -> bytes:
        lines = [
            "version = 1",
            f"expected_peer_gid = {self.expected_peer_gid}",
            f"expected_peer_uid = {self.expected_peer_uid}",
            f"host_id = {_toml(str(self.host_id))}",
            f"remote_user = {_toml(self.remote_user)}",
            f"ssh_host_key_fingerprint = {_toml(self.ssh_host_key_fingerprint)}",
            f"ceiling_path = {_toml(str(self.ceiling_path))}",
            "transport_key_ids = ["
            + ", ".join(_toml(identifier) for identifier in self.transport_key_ids)
            + "]",
            "",
            "[issuer_keys]",
        ]
        lines.extend(
            f"{_toml(str(identifier))} = {_toml(base64.b64encode(key).decode('ascii'))}"
            for identifier, key in self.issuer_keys
        )
        return ("\n".join(lines) + "\n").encode("utf-8")


def generate_vm_authority(
    authority: AuthorityTomlV1, ceiling: ServerCeilingV1, *, authority_path: Path
) -> None:
    """Atomically emit two root-installable artifacts from typed VM-only values."""
    ceiling_path = authority.ceiling_path
    if authority_path == ceiling_path:
        raise _error("authority and ceiling paths must differ")
    _atomic_write(ceiling_path, ceiling.canonical_bytes(), 0o644)
    _atomic_write(authority_path, authority.toml_bytes(), 0o644)


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise _error("could not atomically write authority artifact") from error
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or stat.S_IMODE(details.st_mode) != mode:
        raise _error("authority artifact mode is invalid")


def _toml(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.CONFIG_PARSE,
        message=message,
        security_result="root broker authority was rejected",
        unsafe_reason="broker authority must be explicit root-owned typed policy",
        next_action="regenerate VM authority from trusted operator inputs",
    )
