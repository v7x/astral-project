"""Root-owned fixed-path broker installation configuration."""

from __future__ import annotations

import base64
import stat
from dataclasses import dataclass
from pathlib import Path

from astral_project.broker.server import BrokerAuthority
from astral_project.core.config import load_toml_config
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import HostId, IssuerKeyId
from astral_project.crypto.keys import public_key_from_bytes
from astral_project.server.entry import ServerTrust
from astral_project.session.ceiling import ServerCeilingV1

DEFAULT_CONFIG = Path("/etc/astral-project/broker.toml")


@dataclass(frozen=True, slots=True)
class BrokerInstallConfig:
    socket_path: Path
    runtime_root: Path
    runtime_manifest_digest: str
    mount_worker: Path
    namespace_worker: Path
    authority_path: Path
    version: int


def load_broker_install_config(path: Path = DEFAULT_CONFIG) -> BrokerInstallConfig:
    _require_root_owned_regular_file(path)
    raw = load_toml_config(
        path,
        allowed_fields={
            "authority_path",
            "mount_worker",
            "namespace_worker",
            "runtime_manifest_digest",
            "runtime_root",
            "socket_path",
            "version",
        },
    )
    try:
        config = BrokerInstallConfig(
            socket_path=_absolute(raw, "socket_path"),
            runtime_root=_absolute(raw, "runtime_root"),
            runtime_manifest_digest=_digest(raw, "runtime_manifest_digest"),
            mount_worker=_absolute(raw, "mount_worker"),
            namespace_worker=_absolute(raw, "namespace_worker"),
            authority_path=_absolute(raw, "authority_path"),
            version=_integer(raw, "version"),
        )
    except (TypeError, ValueError) as error:
        raise _error("broker installation configuration is invalid") from error
    if config.version != 1:
        raise _error("broker installation configuration version is unsupported")
    for trusted_path in (
        config.runtime_root,
        config.mount_worker,
        config.namespace_worker,
        config.authority_path,
    ):
        _require_root_owned_path(trusted_path)
    return config


def load_broker_authority(path: Path) -> BrokerAuthority:
    """Load authority inputs only from separate root-owned exact TOML/CBOR files."""
    _require_root_owned_regular_file(path)
    raw = load_toml_config(
        path,
        allowed_fields={
            "ceiling_path",
            "expected_peer_gid",
            "expected_peer_uid",
            "host_id",
            "issuer_keys",
            "remote_user",
            "ssh_host_key_fingerprint",
            "transport_key_ids",
            "version",
        },
    )
    ceiling_path = _absolute(raw, "ceiling_path")
    _require_root_owned_regular_file(ceiling_path)
    try:
        ceiling = ServerCeilingV1.from_cbor(ceiling_path.read_bytes())
        keys_value = raw["issuer_keys"]
        if not isinstance(keys_value, dict):
            raise ValueError("issuer_keys")
        keys = {
            IssuerKeyId(key): public_key_from_bytes(base64.b64decode(value, validate=True))
            for key, value in keys_value.items()
            if isinstance(key, str) and isinstance(value, str)
        }
        transport = raw["transport_key_ids"]
        if not isinstance(transport, list) or not all(
            isinstance(value, str) for value in transport
        ):
            raise ValueError("transport_key_ids")
        if raw["version"] != 1:
            raise ValueError("version")
        return BrokerAuthority(
            expected_peer_uid=_integer(raw, "expected_peer_uid"),
            expected_peer_gid=_integer(raw, "expected_peer_gid"),
            server_ceiling=ceiling,
            trust=ServerTrust(
                host_id=HostId(_string(raw, "host_id")),
                ssh_host_key_fingerprint=_string(raw, "ssh_host_key_fingerprint"),
                remote_user=_string(raw, "remote_user"),
                issuer_keys=keys,
                transport_key_ids=frozenset(transport),
            ),
        )
    except (OSError, ValueError, TypeError, AstralError) as error:
        raise _error("broker authority configuration is invalid") from error


def _require_root_owned_regular_file(path: Path) -> None:
    _require_root_owned_path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise _error("root configuration is not regular file")


def _require_root_owned_path(path: Path) -> None:
    try:
        details = path.lstat()
    except OSError as error:
        raise _error("root-owned broker path is unavailable") from error
    if details.st_uid != 0 or details.st_mode & 0o022 or stat.S_ISLNK(details.st_mode):
        raise _error("root-owned broker path has unsafe ownership, mode, or type")


def _absolute(raw: dict[str, object], field: str) -> Path:
    value = raw[field]
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ValueError(field)
    return Path(value)


def _digest(raw: dict[str, object], field: str) -> str:
    value = raw[field]
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(field)
    return value


def _string(raw: dict[str, object], field: str) -> str:
    value = raw[field]
    if not isinstance(value, str):
        raise ValueError(field)
    return value


def _integer(raw: dict[str, object], field: str) -> int:
    value = raw[field]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(field)
    return value


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.CONFIG_PARSE,
        message=message,
        security_result="root broker configuration was rejected",
        unsafe_reason="broker authority and executable paths must be root-owned exact inputs",
        next_action="repair root-owned package configuration",
    )
