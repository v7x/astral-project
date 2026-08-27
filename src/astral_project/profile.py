"""Pure projected-home profile schema and deterministic policy matcher."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any


class ProfileError(ValueError):
    """Invalid profile or policy rule."""


class RuleMode(StrEnum):
    HOST_RO = "host-ro"
    HOST_RX = "host-rx"
    PRIVATE_RW = "private-rw"
    OVERLAY_RW = "overlay-rw"
    DENY = "deny"


class RuleScope(StrEnum):
    EXACT = "exact"
    SUBTREE = "subtree"


class Operation(StrEnum):
    LOOKUP = "lookup"
    STAT = "stat"
    LIST = "list"
    READ = "read"
    CREATE = "create"
    WRITE = "write"
    TRUNCATE = "truncate"
    RENAME = "rename"
    HARDLINK = "hardlink"
    SYMLINK = "symlink"
    UNLINK = "unlink"
    MKDIR = "mkdir"
    RMDIR = "rmdir"
    CHMOD = "chmod"
    CHOWN = "chown"
    XATTR = "xattr"
    LOCK = "lock"
    FSYNC = "fsync"
    EXECUTE = "execute"


class Sensitivity(StrEnum):
    CONFIGURATION = "configuration"
    CREDENTIAL = "credential"
    APPLICATION_STATE = "application-state"
    EXECUTABLES = "executables"
    CACHE = "cache"
    OTHER = "other"


class WarningLevel(StrEnum):
    INFO = "info"
    WARN = "warn"
    STRONG = "strong"


_DANGEROUS_SOCKETS = frozenset(
    {
        "/run/docker.sock",
        "/var/run/docker.sock",
        "/run/podman/podman.sock",
        "/run/user/1000/podman/podman.sock",
    }
)


@dataclass(frozen=True, slots=True)
class SocketRule:
    """Exact pathname socket exposed only after explicit profile approval."""

    path: str
    sensitivity: Sensitivity = Sensitivity.OTHER
    warning: WarningLevel = WarningLevel.WARN

    def __post_init__(self) -> None:
        if (
            not self.path.startswith("/")
            or "\x00" in self.path
            or self.path.startswith("@")
            or self.path.endswith("/")
            or str(PurePosixPath(self.path)) != self.path
            or any(part in {".", ".."} for part in PurePosixPath(self.path).parts)
        ):
            raise ProfileError("socket path must be exact absolute pathname")

    @property
    def dangerous(self) -> bool:
        return self.path in _DANGEROUS_SOCKETS or self.path.endswith(
            ("/docker.sock", "/podman.sock")
        )


@dataclass(frozen=True, slots=True)
class CredentialRule:
    """Exact credential path requiring strong confirmation and redacted audit data."""

    path: str
    warning: WarningLevel = WarningLevel.STRONG

    def __post_init__(self) -> None:
        normalize_home_path(self.path)
        if self.warning is not WarningLevel.STRONG:
            raise ProfileError("credential access requires strong warning")


_READ_OPS = frozenset({Operation.LOOKUP, Operation.STAT, Operation.LIST, Operation.READ})
_EXEC_OPS = frozenset({Operation.EXECUTE})
_WRITE_OPS = frozenset(Operation) - _READ_OPS - _EXEC_OPS


@dataclass(frozen=True, slots=True)
class Rule:
    path: str
    scope: RuleScope
    mode: RuleMode
    sensitivity: Sensitivity = Sensitivity.OTHER
    list_allowed: bool = False

    def __post_init__(self) -> None:
        normalized = normalize_home_path(self.path)
        object.__setattr__(self, "path", normalized)
        if self.scope is RuleScope.EXACT and self.list_allowed:
            raise ProfileError("exact rule cannot grant directory listing")

    def matches(self, path: str) -> bool:
        candidate = normalize_home_path(path)
        return candidate == self.path or (
            self.scope is RuleScope.SUBTREE and candidate.startswith(self.path + "/")
        )

    def allows(self, operation: Operation) -> bool:
        if self.mode is RuleMode.DENY:
            return False
        if operation in _READ_OPS:
            return operation is not Operation.LIST or self.list_allowed
        if operation in _EXEC_OPS:
            return self.mode is RuleMode.HOST_RX
        return self.mode in {RuleMode.PRIVATE_RW, RuleMode.OVERLAY_RW}


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    rule: Rule | None
    operation: Operation
    path: str
    reason: str


@dataclass(frozen=True, slots=True)
class ApprovalProvenance:
    """Bounded, non-secret provenance for one persisted learning approval."""

    source: str
    session_id: str
    request_digest: str
    decided_at: int

    def __post_init__(self) -> None:
        if (
            not self.source
            or len(self.source) > 128
            or not self.session_id
            or len(self.session_id) > 128
            or not self.request_digest
            or len(self.request_digest) > 128
            or self.decided_at < 0
        ):
            raise ProfileError("approval provenance is invalid")


@dataclass(frozen=True, slots=True)
class Profile:
    version: int
    profile_id: str
    name: str
    unknown_learning: str = "prompt"
    unknown_sealed: str = "hide"
    sealed: bool = False
    rules: tuple[Rule, ...] = ()
    revision: int = 1
    provenance: tuple[ApprovalProvenance, ...] = ()
    sockets: tuple[SocketRule, ...] = ()
    credentials: tuple[CredentialRule, ...] = ()
    environment_allow: tuple[str, ...] = ()
    environment_unset: tuple[str, ...] = ()
    raw_socket: bool = False

    def __post_init__(self) -> None:
        validate_profile_id(self.profile_id)
        if self.revision < 1:
            raise ProfileError("revision must be positive")

    @classmethod
    def from_toml(cls, source: str | bytes) -> Profile:
        try:
            raw = tomllib.loads(source.decode() if isinstance(source, bytes) else source)
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise ProfileError(f"invalid profile TOML: {error}") from error
        if not isinstance(raw, dict):  # pragma: no cover - tomllib always returns a table
            raise ProfileError("profile root must be a table")
        unknown = set(raw) - {
            "version",
            "id",
            "name",
            "unknown_learning",
            "unknown_sealed",
            "sealed",
            "raw_socket",
            "revision",
            "provenance",
            "sockets",
            "credentials",
            "environment",
            "home",
        }
        if unknown:
            raise ProfileError(f"unsupported profile fields: {sorted(unknown)!r}")
        home = raw.get("home", {})
        if not isinstance(home, dict):
            raise ProfileError("home must be a table")
        home_unknown = set(home) - {"rules"}
        if home_unknown:
            raise ProfileError(f"unsupported home fields: {sorted(home_unknown)!r}")
        rules_raw = home.get("rules", [])
        if not isinstance(rules_raw, list):
            raise ProfileError("home.rules must be an array of tables")
        rules = tuple(_parse_rule(value) for value in rules_raw)
        provenance = _parse_provenance(raw.get("provenance", []))
        sockets = _parse_sockets(raw.get("sockets", []))
        credentials = _parse_credentials(raw.get("credentials", []))
        environment_allow, environment_unset = _parse_environment(raw.get("environment", {}))
        profile = cls(
            version=_int_field(raw, "version", 1),
            profile_id=_str_field(raw, "id", "profile-unset"),
            name=_str_field(raw, "name", "unnamed"),
            unknown_learning=_str_field(raw, "unknown_learning", "prompt"),
            unknown_sealed=_str_field(raw, "unknown_sealed", "hide"),
            sealed=_bool_field(raw, "sealed", False),
            raw_socket=_bool_field(raw, "raw_socket", False),
            rules=rules,
            revision=_positive_int_field(raw, "revision", 1),
            provenance=provenance,
            sockets=sockets,
            credentials=credentials,
            environment_allow=environment_allow,
            environment_unset=environment_unset,
        )
        validate_profile(profile)
        return profile

    def decision(self, path: str, operation: Operation | str) -> Decision:
        normalized = normalize_home_path(path)
        op = Operation(operation)
        candidates = [rule for rule in self.rules if rule.matches(normalized)]
        if not candidates and op in {Operation.LOOKUP, Operation.STAT}:
            descendants = [rule for rule in self.rules if rule.path.startswith(normalized + "/")]
            if descendants:
                descendants.sort(key=lambda rule: len(rule.path))
                return Decision(False, descendants[0], op, normalized, "opaque ancestor traversal")
        if not candidates:
            return Decision(False, None, op, normalized, "no matching rule")
        candidates.sort(
            key=lambda rule: (
                rule.scope is RuleScope.SUBTREE,
                -len(rule.path),
                rule.mode is not RuleMode.DENY,
            )
        )
        rule = candidates[0]
        allowed = rule.allows(op)
        if not allowed:
            reason = "explicit deny" if rule.mode is RuleMode.DENY else "operation denied by rule"
        else:
            reason = "matched explicit rule"
        return Decision(allowed, rule, op, normalized, reason)

    def to_toml(self) -> str:
        lines = [
            f"version = {self.version}",
            f"id = {toml_string(self.profile_id)}",
            f"name = {toml_string(self.name)}",
            f"unknown_learning = {toml_string(self.unknown_learning)}",
            f"unknown_sealed = {toml_string(self.unknown_sealed)}",
            f"sealed = {str(self.sealed).lower()}",
            f"raw_socket = {str(self.raw_socket).lower()}",
            f"revision = {self.revision}",
            "",
        ]
        if self.environment_allow or self.environment_unset:
            lines.extend(
                [
                    "[environment]",
                    f"allow = {toml_array(self.environment_allow)}",
                    f"unset = {toml_array(self.environment_unset)}",
                    "",
                ]
            )
        for socket_rule in self.sockets:
            lines.extend(
                [
                    "[[sockets]]",
                    f"path = {toml_string(socket_rule.path)}",
                    f"sensitivity = {toml_string(socket_rule.sensitivity.value)}",
                    f"warning = {toml_string(socket_rule.warning.value)}",
                    "",
                ]
            )
        for credential in self.credentials:
            lines.extend(
                [
                    "[[credentials]]",
                    f"path = {toml_string(credential.path)}",
                    f"warning = {toml_string(credential.warning.value)}",
                    "",
                ]
            )
        for entry in self.provenance:
            lines.extend(
                [
                    "[[provenance]]",
                    f"source = {toml_string(entry.source)}",
                    f"session_id = {toml_string(entry.session_id)}",
                    f"request_digest = {toml_string(entry.request_digest)}",
                    f"decided_at = {entry.decided_at}",
                    "",
                ]
            )
        for rule in self.rules:
            lines.extend(
                [
                    "[[home.rules]]",
                    f"path = {toml_string(rule.path)}",
                    f"scope = {toml_string(rule.scope.value)}",
                    f"mode = {toml_string(rule.mode.value)}",
                    f"sensitivity = {toml_string(rule.sensitivity.value)}",
                ]
            )
            if rule.list_allowed:
                lines.append("list = true")
            lines.append("")
        return "\n".join(lines)


def validate_profile_id(profile_id: str) -> None:
    """Require the identifier to be safe when used as one storage directory."""
    if (
        not isinstance(profile_id, str)
        or not profile_id
        or profile_id in {".", ".."}
        or "\x00" in profile_id
        or "/" in profile_id
        or "\\" in profile_id
    ):
        raise ProfileError("profile id must be one path component")


def normalize_home_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise ProfileError("home path must be non-empty string")
    if "\\" in path or "\x00" in path:
        raise ProfileError("home path contains invalid character")
    if path.startswith("/"):
        raise ProfileError("home path must be relative")
    parts = path.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ProfileError("home path must be normalized and cannot escape")
    return str(PurePosixPath(*parts))


def validate_profile(profile: Profile) -> None:
    if profile.version != 1:
        raise ProfileError("unsupported profile version")
    if profile.unknown_learning not in {"prompt", "deny"}:
        raise ProfileError("unknown_learning must be prompt or deny")
    if profile.unknown_sealed not in {"hide", "deny"}:
        raise ProfileError("unknown_sealed must be hide or deny")
    writable = [r for r in profile.rules if r.mode in {RuleMode.PRIVATE_RW, RuleMode.OVERLAY_RW}]
    for index, left in enumerate(writable):
        for right in writable[index + 1 :]:
            if _overlap(left, right):
                raise ProfileError(f"overlapping writable roots: {left.path!r}, {right.path!r}")
    for index, left in enumerate(profile.rules):
        for right in profile.rules[index + 1 :]:
            if (
                left.path == right.path
                and left.scope is right.scope
                and left.mode is not right.mode
                and left.mode is not RuleMode.DENY
                and right.mode is not RuleMode.DENY
            ):
                raise ProfileError(f"equal-specificity conflict at {left.path!r}")


def _overlap(left: Rule, right: Rule) -> bool:
    return left.matches(right.path) or right.matches(left.path)


def _parse_provenance(value: Any) -> tuple[ApprovalProvenance, ...]:
    if not isinstance(value, list):
        raise ProfileError("provenance must be an array of tables")
    entries: list[ApprovalProvenance] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "source",
            "session_id",
            "request_digest",
            "decided_at",
        }:
            raise ProfileError("each provenance entry must contain exact fields")
        try:
            entries.append(
                ApprovalProvenance(
                    source=_str_field(item, "source", ""),
                    session_id=_str_field(item, "session_id", ""),
                    request_digest=_str_field(item, "request_digest", ""),
                    decided_at=_int_field(item, "decided_at", 0),
                )
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ProfileError("invalid provenance entry") from error
    return tuple(entries)


def _parse_sockets(value: Any) -> tuple[SocketRule, ...]:
    if not isinstance(value, list):
        raise ProfileError("sockets must be an array of tables")
    result: list[SocketRule] = []
    for item in value:
        if not isinstance(item, dict) or set(item) - {"path", "sensitivity", "warning"}:
            raise ProfileError("invalid socket entry")
        try:
            result.append(
                SocketRule(
                    path=_str_field(item, "path", ""),
                    sensitivity=Sensitivity(_str_field(item, "sensitivity", "other")),
                    warning=WarningLevel(_str_field(item, "warning", "warn")),
                )
            )
        except (ProfileError, KeyError, TypeError, ValueError) as error:
            raise ProfileError("invalid socket entry") from error
    return tuple(result)


def _parse_environment(value: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if value == {}:
        return (), ()
    if not isinstance(value, dict) or set(value) - {"allow", "unset"}:
        raise ProfileError("environment must contain only allow and unset")
    values: list[tuple[str, ...]] = []
    for key in ("allow", "unset"):
        entries = value.get(key, [])
        if not isinstance(entries, list) or any(
            not isinstance(entry, str) or not entry or "=" in entry or "\x00" in entry
            for entry in entries
        ):
            raise ProfileError(f"environment {key} must be a list of names")
        if len(set(entries)) != len(entries):
            raise ProfileError(f"environment {key} contains duplicate names")
        values.append(tuple(entries))
    return values[0], values[1]


def _parse_credentials(value: Any) -> tuple[CredentialRule, ...]:
    if not isinstance(value, list):
        raise ProfileError("credentials must be an array of tables")
    result: list[CredentialRule] = []
    for item in value:
        if not isinstance(item, dict) or set(item) - {"path", "warning"}:
            raise ProfileError("invalid credential entry")
        try:
            result.append(
                CredentialRule(
                    path=_str_field(item, "path", ""),
                    warning=WarningLevel(_str_field(item, "warning", "strong")),
                )
            )
        except (ProfileError, KeyError, TypeError, ValueError) as error:
            raise ProfileError("invalid credential entry") from error
    return tuple(result)


def _parse_rule(value: Any) -> Rule:
    if not isinstance(value, dict):
        raise ProfileError("each home rule must be a table")
    unknown = set(value) - {"path", "scope", "mode", "sensitivity", "list"}
    if unknown:
        raise ProfileError(f"unsupported rule fields: {sorted(unknown)!r}")
    try:
        path = _rule_string(value, "path")
        scope = RuleScope(_rule_string(value, "scope", "exact"))
        mode = RuleMode(_rule_string(value, "mode"))
        sensitivity = Sensitivity(_rule_string(value, "sensitivity", "other"))
        list_value = value.get("list", False)
        if not isinstance(list_value, bool):
            raise ProfileError("rule list must be boolean")
        return Rule(
            path=path,
            scope=scope,
            mode=mode,
            sensitivity=sensitivity,
            list_allowed=list_value,
        )
    except ProfileError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ProfileError(f"invalid home rule: {value!r}") from error


def _rule_string(value: dict[str, Any], key: str, default: str | None = None) -> str:
    if key not in value:
        if default is not None:
            return default
        raise ProfileError(f"rule {key} is required")
    result = value[key]
    if not isinstance(result, str):
        raise ProfileError(f"rule {key} must be string")
    return result


def _str_field(raw: dict[str, Any], key: str, default: str) -> str:
    value = raw.get(key, default)
    if not isinstance(value, str) or not value:
        raise ProfileError(f"{key} must be non-empty string")
    return value


def _int_field(raw: dict[str, Any], key: str, default: int) -> int:
    value = raw.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ProfileError(f"{key} must be integer")
    return value


def _positive_int_field(raw: dict[str, Any], key: str, default: int) -> int:
    value = _int_field(raw, key, default)
    if value < 1:
        raise ProfileError(f"{key} must be positive")
    return value


def _bool_field(raw: dict[str, Any], key: str, default: bool) -> bool:
    value = raw.get(key, default)
    if not isinstance(value, bool):
        raise ProfileError(f"{key} must be boolean")
    return value


def toml_string(value: str) -> str:
    """Encode a value as a TOML basic string, including all controls."""
    escaped = ['"']
    for character in value:
        codepoint = ord(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character == '"':
            escaped.append('\\"')
        elif codepoint <= 0x1F or 0x7F <= codepoint <= 0x9F:
            escaped.append(f"\\u{codepoint:04X}")
        else:
            escaped.append(character)
    escaped.append('"')
    return "".join(escaped)


def toml_array(values: tuple[str, ...]) -> str:
    return "[" + ", ".join(toml_string(value) for value in values) + "]"


def host_path(root: int, relative: str) -> str:
    """Return a diagnostic-only absolute path for a root descriptor."""
    normalize_home_path(relative)
    return os.path.join(f"/proc/self/fd/{root}", relative)
