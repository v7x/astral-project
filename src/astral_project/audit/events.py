"""Versioned, secret-safe audit events and private append-only storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
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
_PATH_KEY = re.compile(r"(?:^|_)(?:path|source|target|root|directory|dir|manifest)$", re.IGNORECASE)
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
    if key is not None and _SECRET_KEY.search(key):
        raise AuditEventError("secret-bearing audit field is forbidden")
    if key is not None and _ARGUMENT_KEY.fullmatch(key):
        raise AuditEventError("command arguments are forbidden in audit fields")
    if isinstance(value, Mapping):
        for item_key, item_value in value.items():
            if not isinstance(item_key, str) or "\x00" in item_key:
                raise AuditEventError("audit payload key is invalid")
            _validate_payload(item_value, key=item_key)
    elif isinstance(value, list):
        for item in value:
            _validate_payload(item)
    elif value is None or isinstance(value, (str, int, float, bool)):
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
        return [_transform_paths(item, mode) for item in value]
    if key is not None and _PATH_KEY.search(key) and isinstance(value, str):
        if mode is PathMode.REDACT:
            return _REDACTED
        digest = hashlib.sha256(b"astral-project-audit-path\0" + value.encode()).hexdigest()
        return f"sha256:{digest}"
    return value
