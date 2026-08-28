"""Versioned, secret-safe audit events and private append-only storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
import time
import uuid
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import cast

from astral_project.core.paths import ensure_private_directory, safe_component

SCHEMA_VERSION = 1
_REDACTED = "<redacted>"
_SECRET_KEY = re.compile(
    r"(?:private|secret|credential|password|token|content|environment|env|identity[_-]?file)",
    re.IGNORECASE,
)
_PATH_KEY = re.compile(
    r"(?:^|_)(?:path|paths|source|sources|target|targets|root|roots|directory|directories|dir|dirs|manifest)$",
    re.IGNORECASE,
)
_PATH_FIELD_NAMES = frozenset({"destination", "device", "path_component", "remote_home"})


def _is_path_field(key: str) -> bool:
    """Recognize schema fields whose values identify filesystem paths."""
    return key in _PATH_FIELD_NAMES or _PATH_KEY.search(key) is not None


_SECRET_VALUE = re.compile(
    r"(?:-----BEGIN[ -]+(?:OPENSSH[ -]+)?PRIVATE[ -]+KEY-----|"
    r"(?:password|passphrase|secret|private[_ -]?key|token|credential)\s*[:=])",
    re.IGNORECASE,
)
_SAFE_REASON_VALUES = frozenset(
    {
        "available",
        "done",
        "enforced",
        "flush or unmount failure",
        "Landlock and process hardening enforced",
        "Landlock available but not applied",
        "Landlock unavailable",
        "missing ABI",
        "mount failure",
        "operator supplied",
        "remote",
        "test",
        "test hardening enforced",
        "transport failure",
        "user request",
    }
)
_SAFE_PAYLOAD_KEYS = frozenset(
    {
        "access_mode",
        "accepted",
        "allowed",
        "allowed_issuers",
        "allowed_kinds",
        "architecture",
        "backend_id",
        "bundle_digest",
        "cache_path",
        "capabilities",
        "canonical_root",
        "canonical_source",
        "chain_errors",
        "child",
        "client_nonce",
        "code",
        "config_path",
        "created_at",
        "daemon",
        "decision",
        "dependencies",
        "dependency_error",
        "destination",
        "device",
        "directory",
        "effective_export_hash",
        "effective_exports_digest",
        "ended_at",
        "enforced",
        "entries",
        "errno",
        "error",
        "error_code",
        "error_type",
        "event_time",
        "evidence",
        "expires_at",
        "export",
        "exports",
        "filesystem_type",
        "flags",
        "flush_warning",
        "forbidden_source_roots",
        "format_version",
        "grant_id",
        "group",
        "hardening",
        "host_id",
        "host_key_fingerprint",
        "id",
        "identity_file",
        "inode",
        "is_dir",
        "issued_at",
        "issuer_key_id",
        "key_kind",
        "kind",
        "landlock_abi",
        "landlock_available",
        "max_depth",
        "max_exports",
        "maximum_access",
        "max_ttl_seconds",
        "message",
        "method",
        "mode",
        "mount_id",
        "mount_path",
        "name",
        "network",
        "nested_mount_policy",
        "next_action",
        "nonce",
        "not_before",
        "number",
        "object_type",
        "ok",
        "operation",
        "optional_extensions",
        "os",
        "package_version",
        "path",
        "paths",
        "path_component",
        "peer_uid",
        "phase",
        "pid",
        "policy_hash",
        "port",
        "previous_event_id",
        "probe",
        "profile_id",
        "protocol_version",
        "provenance",
        "python_version",
        "reason",
        "recorded",
        "returncode",
        "recursive",
        "remote_count",
        "remote_home",
        "remote_state",
        "remote_user",
        "removed_names",
        "removed_path_entries",
        "request_id",
        "requested_features",
        "requested_source",
        "requested_workload",
        "required",
        "resolution",
        "result",
        "retryable",
        "revision",
        "revoked",
        "root",
        "roots",
        "runtime_manifest_digest",
        "runtime_target",
        "safe_message",
        "schema_version",
        "security_result",
        "sensitivity",
        "server_policy_hash",
        "session_id",
        "session_nonce",
        "source_identity",
        "source_path",
        "source_roots",
        "ssh_host_fingerprint",
        "ssh_host_key_fingerprint",
        "stable_error_code",
        "started_at",
        "start_new_session",
        "state",
        "state_version",
        "status",
        "subject_id",
        "subject_type",
        "supported",
        "syscall",
        "target",
        "target_platform",
        "timeout_seconds",
        "transport_capability",
        "transport_key_id",
        "type",
        "unsafe_reason",
        "updated_at",
        "version",
        "virtual_target",
        "workload_id",
    }
)
_ARGUMENT_KEY = re.compile(
    r"^(?:arg(?:ument)?s?|argv|command(?:[_-](?:line|args?))?)$", re.IGNORECASE
)


class PathMode(Enum):
    """Export treatment for potentially sensitive path values."""

    REDACT = "redact"
    HASH = "hash"


class AuditEventError(ValueError):
    """Raised when an event violates the versioned audit envelope."""


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Validated event envelope; raw paths remain inside private storage only."""

    event_id: str
    occurred_at: int
    kind: str
    subject_type: str
    subject_id: str
    payload: Mapping[str, object]
    previous_event_id: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.schema_version, int)
            or isinstance(self.schema_version, bool)
            or self.schema_version != SCHEMA_VERSION
        ):
            raise AuditEventError("unsupported audit schema version")
        for name, value in (
            ("event_id", self.event_id),
            ("kind", self.kind),
            ("subject_type", self.subject_type),
            ("subject_id", self.subject_id),
        ):
            if not isinstance(value, str) or not value or "\x00" in value:
                raise AuditEventError(f"invalid audit {name}")
        if (
            not isinstance(self.occurred_at, int)
            or isinstance(self.occurred_at, bool)
            or self.occurred_at < 0
        ):
            raise AuditEventError("invalid audit timestamp")
        if self.previous_event_id is not None and (
            not isinstance(self.previous_event_id, str) or not self.previous_event_id
        ):
            raise AuditEventError("invalid previous audit event")
        _validate_payload(self.payload)

    @classmethod
    def create(
        cls,
        kind: str,
        subject_type: str,
        subject_id: str,
        payload: Mapping[str, object],
        *,
        previous_event_id: str | None = None,
        occurred_at: int | None = None,
    ) -> AuditEvent:
        """Create one validated event with a fresh opaque identifier."""
        return cls(
            event_id=str(uuid.uuid4()),
            occurred_at=int(time.time()) if occurred_at is None else occurred_at,
            kind=kind,
            subject_type=subject_type,
            subject_id=subject_id,
            payload=dict(payload),
            previous_event_id=previous_event_id,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> AuditEvent:
        """Parse one strict envelope; callers may skip malformed legacy rows."""
        required = {
            "event_id",
            "occurred_at",
            "kind",
            "subject_type",
            "subject_id",
            "payload",
            "previous_event_id",
            "schema_version",
        }
        if set(value) != required:
            raise AuditEventError("audit event fields are invalid")
        payload = value["payload"]
        if not isinstance(payload, dict):
            raise AuditEventError("audit payload is not an object")
        previous = value["previous_event_id"]
        if previous is not None and not isinstance(previous, str):
            raise AuditEventError("audit previous event is invalid")
        return cls(
            event_id=value["event_id"],  # type: ignore[arg-type]
            occurred_at=value["occurred_at"],  # type: ignore[arg-type]
            kind=value["kind"],  # type: ignore[arg-type]
            subject_type=value["subject_type"],  # type: ignore[arg-type]
            subject_id=value["subject_id"],  # type: ignore[arg-type]
            payload=cast(Mapping[str, object], payload),
            previous_event_id=previous,
            schema_version=value["schema_version"],  # type: ignore[arg-type]
        )

    def to_dict(self, *, path_mode: PathMode | None = None) -> dict[str, object]:
        payload: Mapping[str, object] = self.payload
        if path_mode is not None:
            payload = cast(Mapping[str, object], _transform_paths(payload, path_mode))
        return {
            "event_id": self.event_id,
            "occurred_at": self.occurred_at,
            "kind": self.kind,
            "subject_type": self.subject_type,
            "subject_id": self.subject_id,
            "payload": dict(payload),
            "previous_event_id": self.previous_event_id,
            "schema_version": self.schema_version,
        }


class AuditLog:
    """Private JSONL audit store used by local and remote state owners."""

    def __init__(self, path: Path, *, max_bytes: int = 10 * 1024 * 1024, retain: int = 5) -> None:
        if max_bytes <= 0 or retain < 1:
            raise ValueError("audit rotation limits must be positive")
        self.path = path
        self.max_bytes = max_bytes
        self.retain = retain
        ensure_private_directory(path.parent)
        if path.exists():
            _check_private_file(path)

    def append(
        self,
        kind: str,
        subject_type: str,
        subject_id: str,
        payload: Mapping[str, object],
        *,
        occurred_at: int | None = None,
    ) -> AuditEvent:
        previous = next(iter(reversed(self.read())), None)
        event = AuditEvent.create(
            kind,
            subject_type,
            subject_id,
            payload,
            previous_event_id=None if previous is None else previous.event_id,
            occurred_at=occurred_at,
        )
        self._rotate_if_needed()
        descriptor = os.open(
            self.path,
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        try:
            os.fchmod(descriptor, 0o600)
            data = (
                json.dumps(event.to_dict(), separators=(",", ":"), sort_keys=True) + "\n"
            ).encode()
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("audit write made no progress")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _check_private_file(self.path)
        return event

    def read(self) -> tuple[AuditEvent, ...]:
        """Read valid rows only; malformed historical rows never crash readers."""
        return tuple(event for event, _ in self._all_rows() if event is not None)

    def diagnostics(self) -> tuple[str, ...]:
        """Return safe row diagnostics without exposing malformed contents."""
        return tuple(message for _, message in self._all_rows() if message is not None)

    def export(self, *, path_mode: PathMode = PathMode.REDACT) -> str:
        """Serialize valid rows with redaction or explicit deterministic hashing."""
        return "".join(
            json.dumps(event.to_dict(path_mode=path_mode), separators=(",", ":"), sort_keys=True)
            + "\n"
            for event in self.read()
        )

    def rotate(self) -> None:
        """Rotate current log and retain only configured private generations."""
        if self.path.exists():
            _check_private_file(self.path)
        for index in range(self.retain, 0, -1):
            source = self._generation(index - 1)
            target = self._generation(index)
            if source.exists():
                if index == self.retain:
                    target.unlink(missing_ok=True)
                os.replace(source, target)
                os.chmod(target, 0o600)
        if self.path.exists():
            os.replace(self.path, self._generation(1))
            os.chmod(self._generation(1), 0o600)
        self._reset_oldest_predecessor()

    def _reset_oldest_predecessor(self) -> None:
        """Atomically make the first retained valid row a new chain root."""
        for oldest in self._read_paths():
            try:
                lines = _read_private_text(oldest).splitlines(keepends=True)
            except OSError:
                continue
            for index, line in enumerate(lines):
                try:
                    raw = json.loads(line)
                    if not isinstance(raw, dict):
                        continue
                    event = AuditEvent.from_dict(cast(Mapping[str, object], raw))
                except (AuditEventError, json.JSONDecodeError, TypeError, ValueError):
                    continue
                if event.previous_event_id is None:
                    return
                replacement_value = event.to_dict()
                replacement_value["previous_event_id"] = None
                replacement = (
                    json.dumps(replacement_value, separators=(",", ":"), sort_keys=True) + "\n"
                )
                lines[index] = replacement
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=f".{safe_component(oldest.name)}.", dir=oldest.parent
                )
                temporary = Path(temporary_name)
                try:
                    os.fchmod(descriptor, 0o600)
                    data = "".join(lines).encode()
                    view = memoryview(data)
                    while view:
                        written = os.write(descriptor, view)
                        if written <= 0:
                            raise OSError("audit rotation write made no progress")
                        view = view[written:]
                    os.fsync(descriptor)
                    os.close(descriptor)
                    descriptor = -1
                    os.replace(temporary, oldest)
                    os.chmod(oldest, 0o600)
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                    temporary.unlink(missing_ok=True)
                return

    def _rotate_if_needed(self) -> None:
        if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
            self.rotate()

    def _generation(self, index: int) -> Path:
        return self.path.with_name(f"{safe_component(self.path.name)}.{index}")

    def _all_rows(self) -> Iterator[tuple[AuditEvent | None, str | None]]:
        for path in self._read_paths():
            yield from self._rows(path)

    def _read_paths(self) -> Iterator[Path]:
        for index in range(self.retain, 0, -1):
            path = self._generation(index)
            if path.exists():
                _check_private_file(path)
                yield path
        if self.path.exists():
            _check_private_file(self.path)
            yield self.path

    def _rows(self, path: Path) -> Iterator[tuple[AuditEvent | None, str | None]]:
        try:
            with path.open(encoding="utf-8") as stream:
                for line in stream:
                    try:
                        raw = json.loads(line)
                        if not isinstance(raw, dict):
                            raise AuditEventError("audit row is not an object")
                        yield AuditEvent.from_dict(cast(Mapping[str, object], raw)), None
                    except (AuditEventError, json.JSONDecodeError, TypeError, ValueError):
                        # Keep diagnostic text generic: malformed row may contain secrets.
                        yield None, "malformed audit row skipped"
        except OSError:
            return


def _read_private_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def validate_chain(events: tuple[AuditEvent, ...]) -> tuple[str, ...]:
    """Return event IDs whose predecessor reference is not valid and prior."""
    known: set[str] = set()
    errors: list[str] = []
    for event in events:
        if event.event_id in known:
            errors.append(event.event_id)
        if event.previous_event_id is not None and event.previous_event_id not in known:
            errors.append(event.event_id)
        known.add(event.event_id)
    return tuple(errors)


def _check_private_file(path: Path) -> None:
    details = path.lstat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_mode & 0o077
    ):
        raise PermissionError(f"audit path is not private: {path}")


def _validate_payload(value: object, *, key: str | None = None) -> None:
    if key is not None:
        if _ARGUMENT_KEY.fullmatch(key):
            raise AuditEventError("command arguments are forbidden in audit fields")
        if _SECRET_KEY.search(key):
            raise AuditEventError("secret-bearing audit field is forbidden")
        if key not in _SAFE_PAYLOAD_KEYS:
            raise AuditEventError("audit payload field is not in the schema")
    if isinstance(value, Mapping):
        for item_key, item_value in value.items():
            if not isinstance(item_key, str) or "\x00" in item_key:
                raise AuditEventError("audit payload key is invalid")
            _validate_payload(item_value, key=item_key)
    elif isinstance(value, list):
        if key is None or not _is_path_field(key):
            raise AuditEventError("audit payload lists are restricted to path fields")
        for item in value:
            if not isinstance(item, str):
                raise AuditEventError("audit path collections must contain strings")
            _validate_payload(item, key=key)
    elif isinstance(value, str):
        if _SECRET_VALUE.search(value) or "\x00" in value:
            raise AuditEventError("secret-bearing audit value is forbidden")
        if key == "reason" and value not in _SAFE_REASON_VALUES:
            raise AuditEventError("audit reason is not in the schema")
    elif value is None or isinstance(value, (int, float, bool)):
        return
    else:
        raise AuditEventError("audit payload is not JSON-safe")


def _transform_paths(value: object, mode: PathMode, *, key: str | None = None) -> object:
    if isinstance(value, Mapping):
        return {
            str(item_key): _transform_paths(item_value, mode, key=str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_transform_paths(item, mode, key=key) for item in value]
    if key is not None and _is_path_field(key) and isinstance(value, str):
        if mode is PathMode.REDACT:
            return _REDACTED
        digest = hashlib.sha256(b"astral-project-audit-path\0" + value.encode()).hexdigest()
        return f"sha256:{digest}"
    return value
