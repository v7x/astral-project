"""Frozen host probe and host-record contracts."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import HostId


class CapabilityStatus(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class Capability:
    name: str
    status: CapabilityStatus
    reason: str
    evidence: str

    def __post_init__(self) -> None:
        if not self.name or not self.reason or not self.evidence:
            raise _invalid("capability name, reason, and evidence must be non-empty")


_REQUIRED_CAPABILITIES = frozenset(
    {
        "bubblewrap",
        "user_namespaces",
        "openat2",
        "open_tree",
        "move_mount",
        "mount_setattr",
        "landlock",
        "sftp_server",
        "loader_libraries",
        "filesystems",
        "mount_topology",
        "authorized_keys",
        "authorized_principals",
    }
)


def _invalid(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.HOST_RECORD,
        message=message,
        security_result="host record was rejected",
        unsafe_reason="enrollment requires complete machine-readable host evidence",
        next_action="repair probe output or rerun compatible host probe",
    )


def _toml_string(value: str) -> str:
    escaped: list[str] = []
    for character in value:
        if character == "\\":
            escaped.append("\\\\")
        elif character == '"':
            escaped.append('\\"')
        elif character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        elif ord(character) < 0x20:
            escaped.append(f"\\u{ord(character):04x}")
        else:
            escaped.append(character)
    return '"' + "".join(escaped) + '"'


def _string(data: dict[str, object], field: str) -> str:
    value = data.get(field)
    if not isinstance(value, str) or not value:
        raise _invalid(f"{field} must be a non-empty string")
    return value


@dataclass(frozen=True, slots=True)
class ProbeReport:
    os: str
    architecture: str
    remote_user: str
    remote_home: str
    capabilities: tuple[Capability, ...]

    def __post_init__(self) -> None:
        if not self.remote_home.startswith("/"):
            raise _invalid("remote_home must be absolute")
        names = [capability.name for capability in self.capabilities]
        if set(names) != _REQUIRED_CAPABILITIES or len(names) != len(set(names)):
            raise _invalid("probe must contain every required capability exactly once")

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> ProbeReport:
        if set(data) != {
            "architecture",
            "capabilities",
            "os",
            "remote_home",
            "remote_user",
            "version",
        }:
            raise _invalid("probe fields are invalid")
        if data["version"] != 1 or not isinstance(data["capabilities"], list):
            raise _invalid("probe version or capabilities are invalid")
        capabilities: list[Capability] = []
        for raw in data["capabilities"]:
            if not isinstance(raw, dict) or set(raw) != {"evidence", "name", "reason", "status"}:
                raise _invalid("capability fields are invalid")
            try:
                status = CapabilityStatus(_string(raw, "status"))
            except ValueError as error:
                raise _invalid("capability status is invalid") from error
            capabilities.append(
                Capability(
                    _string(raw, "name"), status, _string(raw, "reason"), _string(raw, "evidence")
                )
            )
        return cls(
            os=_string(data, "os"),
            architecture=_string(data, "architecture"),
            remote_user=_string(data, "remote_user"),
            remote_home=_string(data, "remote_home"),
            capabilities=tuple(capabilities),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "version": 1,
            "os": self.os,
            "architecture": self.architecture,
            "remote_user": self.remote_user,
            "remote_home": self.remote_home,
            "capabilities": [
                {
                    "name": item.name,
                    "status": item.status.value,
                    "reason": item.reason,
                    "evidence": item.evidence,
                }
                for item in self.capabilities
            ],
        }


@dataclass(frozen=True, slots=True)
class HostRecord:
    host_id: HostId
    ssh_host_fingerprint: str
    probe: ProbeReport

    def __post_init__(self) -> None:
        if not self.ssh_host_fingerprint:
            raise _invalid("ssh_host_fingerprint must be non-empty")

    @classmethod
    def load(cls, path: Path) -> HostRecord:
        try:
            with path.open("rb") as stream:
                data = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError) as error:
            raise _invalid(f"could not parse host record: {path}") from error
        if set(data) != {"host_id", "probe", "ssh_host_fingerprint", "version"}:
            raise _invalid("host record fields are invalid")
        if data["version"] != 1 or not isinstance(data["probe"], dict):
            raise _invalid("host record version or probe is invalid")
        return cls(
            HostId(_string(data, "host_id")),
            _string(data, "ssh_host_fingerprint"),
            ProbeReport.from_dict(data["probe"]),
        )

    def to_toml(self) -> str:
        lines = [
            "version = 1",
            f"host_id = {_toml_string(str(self.host_id))}",
            f"ssh_host_fingerprint = {_toml_string(self.ssh_host_fingerprint)}",
            "",
            "[probe]",
            "version = 1",
            f"os = {_toml_string(self.probe.os)}",
            f"architecture = {_toml_string(self.probe.architecture)}",
            f"remote_user = {_toml_string(self.probe.remote_user)}",
            f"remote_home = {_toml_string(self.probe.remote_home)}",
        ]
        for item in self.probe.capabilities:
            lines.extend(
                [
                    "",
                    "[[probe.capabilities]]",
                    f"name = {_toml_string(item.name)}",
                    f"status = {_toml_string(item.status.value)}",
                    f"reason = {_toml_string(item.reason)}",
                    f"evidence = {_toml_string(item.evidence)}",
                ]
            )
        return "\n".join(lines) + "\n"
