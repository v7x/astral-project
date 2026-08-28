"""Atomic, rollback-safe Packet 8 enrollment orchestration."""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project.audit.events import AuditLog
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import _fsync_directory
from astral_project.crypto.keys import public_key_bytes, store_private_key
from astral_project.host.records import HostRecord

ENROLLED_SERVER_EXECUTABLE = "/usr/libexec/astral-project/aspr-server"
_TRANSPORT_KEY_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


class RemoteEnrollment(Protocol):
    """Narrow remote mutation boundary; no arbitrary command operation exists."""

    def install_bundle(self, bundle: bytes, digest: str) -> bool: ...
    def remove_bundle(self, digest: str) -> None: ...
    def install_issuer_key(self, key: bytes) -> bool: ...
    def remove_issuer_key(self, key: bytes) -> None: ...
    def add_authorized_key(self, path: str, entry: str) -> bool: ...
    def remove_authorized_key(self, path: str, entry: str) -> None: ...
    def smoke_test(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ControlFileIdentity:
    inode: int
    digest: str
    link_count: int

    def __post_init__(self) -> None:
        if self.inode < 1 or self.link_count != 1 or len(self.digest) != 64:
            raise _error("control file identity is unsafe")


def _error(message: str, detail: str | None = None) -> AstralError:
    return AstralError(
        code=ErrorCode.HOST_ENROLLMENT,
        message=message,
        security_result="remote enrollment was rolled back or not started",
        unsafe_reason="restricted key installation must not leave general remote authority",
        next_action="inspect remote enrollment evidence and retry",
        dependency_error=detail,
    )


def verify_host_fingerprint(expected: str, observed: str) -> None:
    """Block enrollment when SSH observed key differs from pinned probe evidence."""
    if not expected or expected != observed:
        raise _error("SSH host key fingerprint changed")


def authorized_key_entry(public_key: bytes, transport_key_id: str) -> str:
    """Build one restricted forced-command Ed25519 authorized_keys entry."""
    if (
        len(public_key) != 32
        or transport_key_id.startswith("-")
        or _TRANSPORT_KEY_ID.fullmatch(transport_key_id) is None
    ):
        raise _error("transport key material or identifier is invalid")
    key_blob = struct.pack(">I", len(b"ssh-ed25519")) + b"ssh-ed25519"
    key_blob += struct.pack(">I", len(public_key)) + public_key
    encoded = base64.b64encode(key_blob).decode("ascii")
    command = f"{ENROLLED_SERVER_EXECUTABLE} server ssh-entry --transport-key {transport_key_id}"
    return (
        "restrict,no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,"
        f'command="{command}" ssh-ed25519 {encoded} aspr-{transport_key_id}'
    )


@dataclass(slots=True)
class RollbackJournal:
    """Execute compensations in reverse when any enrollment step fails."""

    compensations: list[Callable[[], None]] = field(default_factory=list)

    def add(self, compensation: Callable[[], None]) -> None:
        self.compensations.append(compensation)

    def rollback(self) -> None:
        failures: list[str] = []
        for compensation in reversed(self.compensations):
            try:
                compensation()
            except Exception as error:
                failures.append(str(error))
        if failures:
            raise _error("remote rollback was incomplete", "; ".join(failures))


@dataclass(frozen=True, slots=True)
class EnrollmentResult:
    bundle_digest: str
    authorized_key: str
    control_file: ControlFileIdentity


def enroll(
    record: HostRecord,
    remote: RemoteEnrollment,
    *,
    bundle: bytes,
    issuer_key: bytes,
    transport_key_id: str,
    private_key_path: Path,
    control_file: ControlFileIdentity,
    audit_log: AuditLog | None = None,
) -> EnrollmentResult:
    """Install narrow remote authority; every created item has compensation."""
    if not bundle or len(issuer_key) != 32:
        raise _error("bundle or issuer key is invalid")
    if private_key_path.exists():
        raise _error("transport private key destination already exists")
    if audit_log is not None:
        audit_log.append(
            "enrollment.started",
            "host",
            str(record.host_id),
            {"transport_key_id": transport_key_id},
        )
    private_key = Ed25519PrivateKey.generate()
    public_key = public_key_bytes(private_key)
    entry = authorized_key_entry(public_key, transport_key_id)
    digest = hashlib.sha256(bundle).hexdigest()
    journal = RollbackJournal()
    try:
        if remote.install_bundle(bundle, digest):
            journal.add(lambda: remote.remove_bundle(digest))
        if remote.install_issuer_key(issuer_key):
            journal.add(lambda: remote.remove_issuer_key(issuer_key))
        capability = next(
            (item for item in record.probe.capabilities if item.name == "authorized_keys"), None
        )
        if capability is None or capability.status.value != "supported":
            raise _error("effective authorized_keys path is unsupported for automatic enrollment")
        path = capability.evidence
        if ";" in path:
            raise _error(
                "multiple effective authorized_keys paths require explicit enrollment choice"
            )
        if remote.add_authorized_key(path, entry):
            journal.add(lambda: remote.remove_authorized_key(path, entry))
        store_private_key(private_key_path, private_key)
        journal.add(lambda: _remove_new_private_key(private_key_path))
        remote.smoke_test()
    except Exception as error:
        if audit_log is not None:
            audit_log.append(
                "enrollment.failed",
                "host",
                str(record.host_id),
                {"error_type": type(error).__name__},
            )
        try:
            journal.rollback()
        except AstralError as rollback_error:
            raise rollback_error from error
        raise _error("remote enrollment failed", str(error)) from error
    if audit_log is not None:
        audit_log.append(
            "enrollment.completed",
            "host",
            str(record.host_id),
            {"bundle_digest": digest, "transport_key_id": transport_key_id},
        )
    return EnrollmentResult(digest, entry, control_file)


def _remove_new_private_key(path: Path) -> None:
    try:
        path.unlink()
        _fsync_directory(path.parent)
    except FileNotFoundError:
        return
    except OSError as error:
        raise _error("could not remove newly created transport private key", str(error)) from error
