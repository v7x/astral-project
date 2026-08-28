"""Private durable SQLite state and transactional migrations."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import time
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from astral_project.audit.events import AuditEvent, AuditEventError, PathMode, validate_chain
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import HostId, SessionId
from astral_project.core.paths import check_private_path, ensure_private_directory
from astral_project.crypto.grants import (
    Grant,
    GrantVerificationContext,
    SignedGrant,
)
from astral_project.session.listing import SessionListingScope


@dataclass(frozen=True, slots=True)
class ActiveListingSession:
    """Trusted state needed to bind one daemon listing to one active grant."""

    session_id: str
    signed_grant: SignedGrant
    host_id: str
    host_key_fingerprint: str
    remote_user: str
    host_metadata: Mapping[str, object]


MigrationApply = Callable[[sqlite3.Connection], None]


@dataclass(frozen=True, slots=True)
class Migration:
    """One ordered, checksummed migration."""

    version: int
    name: str
    source: str
    apply: MigrationApply
    destructive: bool = False

    @property
    def checksum(self) -> str:
        return hashlib.sha256(f"{self.version}\n{self.name}\n{self.source}".encode()).hexdigest()


def _state_error(code: ErrorCode, message: str, error: Exception | None = None) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="state database was rejected",
        unsafe_reason="durable trusted state must remain private and internally consistent",
        next_action="inspect state path or restore trusted backup",
        dependency_error=None if error is None else str(error),
    )


def _initial_schema(connection: sqlite3.Connection) -> None:
    connection.execute(
        """CREATE TABLE hosts (
            host_id TEXT PRIMARY KEY,
            host_key_fingerprint TEXT NOT NULL,
            remote_user TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE grants (
            grant_id TEXT PRIMARY KEY,
            host_id TEXT NOT NULL REFERENCES hosts(host_id),
            grant_cbor BLOB NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY,
            grant_id TEXT NOT NULL REFERENCES grants(grant_id),
            state TEXT NOT NULL,
            started_at INTEGER NOT NULL,
            ended_at INTEGER
        )"""
    )
    connection.execute(
        """CREATE TABLE mounts (
            mount_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id),
            mount_path TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            ended_at INTEGER
        )"""
    )
    connection.execute(
        """CREATE TABLE profile_metadata (
            profile_id TEXT PRIMARY KEY,
            revision INTEGER NOT NULL,
            digest BLOB NOT NULL,
            metadata_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE approvals (
            approval_id TEXT PRIMARY KEY,
            profile_id TEXT REFERENCES profile_metadata(profile_id),
            request_digest BLOB NOT NULL,
            decision TEXT NOT NULL,
            decided_at INTEGER NOT NULL,
            provenance_json TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE audit_events (
            event_id TEXT PRIMARY KEY,
            occurred_at INTEGER NOT NULL,
            kind TEXT NOT NULL,
            subject_type TEXT NOT NULL,
            subject_id TEXT NOT NULL,
            payload_json TEXT NOT NULL
        )"""
    )
    connection.execute(
        """CREATE TABLE revocations (
            grant_id TEXT PRIMARY KEY REFERENCES grants(grant_id),
            revoked_at INTEGER NOT NULL,
            reason TEXT NOT NULL,
            remote_state TEXT NOT NULL
        )"""
    )
    connection.execute("CREATE INDEX grants_host_id_idx ON grants(host_id)")
    connection.execute("CREATE INDEX sessions_grant_id_idx ON sessions(grant_id)")
    connection.execute("CREATE INDEX mounts_session_id_idx ON mounts(session_id)")
    connection.execute("CREATE INDEX audit_events_occurred_at_idx ON audit_events(occurred_at)")


INITIAL_MIGRATION = Migration(
    version=1,
    name="initial-state-schema",
    source=(
        "initial tables: hosts grants sessions mounts profile_metadata approvals "
        "audit_events revocations"
    ),
    apply=_initial_schema,
)
DEFAULT_MIGRATIONS: tuple[Migration, ...] = (INITIAL_MIGRATION,)


class StateDatabase:
    """Database owner; one SQLite connection exists only inside each operation."""

    def __init__(self, path: Path, migrations: Sequence[Migration] = DEFAULT_MIGRATIONS) -> None:
        self.path = path
        self.migrations = tuple(migrations)
        self._validate_migrations()

    @classmethod
    def open(
        cls, path: Path, migrations: Sequence[Migration] = DEFAULT_MIGRATIONS
    ) -> StateDatabase:
        database = cls(path, migrations)
        database._initialize()
        return database

    def activate_session(
        self,
        *,
        session_id: SessionId,
        signed_grant: SignedGrant,
        host_id: HostId,
        host_key_fingerprint: str,
        remote_user: str,
        host_metadata: Mapping[str, object],
        started_at: int,
        issuer_key: Ed25519PublicKey | None = None,
    ) -> None:
        """Atomically register one verified grant-bound active remote session."""
        grant = signed_grant.grant
        effective_issuer_key = issuer_key or signed_grant.issuer_public_key
        if effective_issuer_key is None:
            raise _state_error(ErrorCode.CRYPTO_SIGNATURE, "session issuer key is unavailable")
        try:
            signed_grant.verify(
                effective_issuer_key,
                GrantVerificationContext(
                    host_id=host_id,
                    ssh_host_key_fingerprint=host_key_fingerprint,
                    remote_user=remote_user,
                    now=started_at,
                ),
            )
        except AstralError:
            raise
        if (
            grant.host_id != host_id
            or grant.ssh_host_key_fingerprint != host_key_fingerprint
            or grant.remote_user != remote_user
            or started_at < 0
            or not isinstance(host_metadata, dict)
        ):
            raise _state_error(ErrorCode.DAEMON_AUTH, "session grant and host binding disagree")
        try:
            metadata_json = json.dumps(host_metadata, separators=(",", ":"), sort_keys=True)
        except (TypeError, ValueError) as error:
            raise _state_error(
                ErrorCode.STATE_CORRUPT, "session host metadata is not JSON", error
            ) from error
        with self.transaction(write=True) as connection:
            connection.execute(
                "INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(host_id),
                    host_key_fingerprint,
                    remote_user,
                    metadata_json,
                    started_at,
                    started_at,
                ),
            )
            connection.execute(
                "INSERT INTO grants VALUES (?, ?, ?, ?, ?)",
                (
                    str(grant.grant_id),
                    str(host_id),
                    signed_grant.to_cbor(),
                    grant.issued_at,
                    grant.expires_at,
                ),
            )
            connection.execute(
                "INSERT INTO grant_issuer_keys(grant_id, public_key) VALUES (?, ?)",
                (str(grant.grant_id), effective_issuer_key.public_bytes_raw()),
            )
            connection.execute(
                "INSERT INTO sessions VALUES (?, ?, ?, ?, ?)",
                (str(session_id), str(grant.grant_id), "active", started_at, None),
            )

    def store_signed_grant(
        self,
        signed_grant: SignedGrant,
        *,
        host_key_fingerprint: str,
        remote_user: str,
        host_metadata: Mapping[str, object],
        stored_at: int | None = None,
        issuer_key: Ed25519PublicKey | None = None,
    ) -> None:
        """Persist one cryptographically verified grant and fixed host binding atomically."""
        grant = signed_grant.grant
        when = int(time.time()) if stored_at is None else stored_at
        effective_issuer_key = issuer_key or signed_grant.issuer_public_key
        if effective_issuer_key is None:
            raise _state_error(ErrorCode.CRYPTO_SIGNATURE, "grant issuer key is unavailable")
        verification_time = min(max(when, grant.not_before), grant.expires_at - 1)
        signed_grant.verify(
            effective_issuer_key,
            GrantVerificationContext(
                host_id=grant.host_id,
                ssh_host_key_fingerprint=grant.ssh_host_key_fingerprint,
                remote_user=grant.remote_user,
                now=verification_time,
            ),
        )
        if (
            grant.ssh_host_key_fingerprint != host_key_fingerprint
            or grant.remote_user != remote_user
            or when < 0
            or not isinstance(host_metadata, dict)
        ):
            raise _state_error(ErrorCode.DAEMON_AUTH, "grant host binding disagrees with state")
        try:
            metadata_json = json.dumps(host_metadata, separators=(",", ":"), sort_keys=True)
        except (TypeError, ValueError) as error:
            raise _state_error(
                ErrorCode.STATE_CORRUPT, "grant host metadata is not JSON", error
            ) from error
        with self.transaction(write=True) as connection:
            revoked = connection.execute(
                "SELECT 1 FROM revocations WHERE grant_id = ?", (str(grant.grant_id),)
            ).fetchone()
            if revoked is not None:
                raise _state_error(
                    ErrorCode.DAEMON_AUTH, "revoked grant cannot be imported as active"
                )
            connection.execute(
                "INSERT INTO hosts VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(host_id) DO UPDATE SET "
                "host_key_fingerprint = excluded.host_key_fingerprint, "
                "remote_user = excluded.remote_user, metadata_json = excluded.metadata_json, "
                "updated_at = excluded.updated_at",
                (
                    str(grant.host_id),
                    host_key_fingerprint,
                    remote_user,
                    metadata_json,
                    when,
                    when,
                ),
            )
            try:
                connection.execute(
                    "INSERT INTO grants VALUES (?, ?, ?, ?, ?)",
                    (
                        str(grant.grant_id),
                        str(grant.host_id),
                        signed_grant.to_cbor(),
                        grant.issued_at,
                        grant.expires_at,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise _state_error(
                    ErrorCode.GRANT_INVALID, "grant is already stored", error
                ) from error
            connection.execute(
                "INSERT INTO grant_issuer_keys(grant_id, public_key) VALUES (?, ?)",
                (str(grant.grant_id), effective_issuer_key.public_bytes_raw()),
            )
            self._audit(
                connection,
                "grant.stored",
                "grant",
                str(grant.grant_id),
                {"host_id": str(grant.host_id)},
                when,
            )

    def import_signed_grant(
        self,
        signed_grant: SignedGrant,
        *,
        issuer_key: Ed25519PublicKey | None = None,
        stored_at: int | None = None,
    ) -> None:
        """Import grant only against an already enrolled host record."""
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT host_key_fingerprint, remote_user, metadata_json "
                "FROM hosts WHERE host_id = ?",
                (str(signed_grant.grant.host_id),),
            ).fetchone()
        if row is None:
            raise _state_error(ErrorCode.HOST_RECORD, "grant host is not enrolled")
        try:
            metadata = json.loads(str(row[2]))
            if not isinstance(metadata, dict):
                raise TypeError("host metadata")
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise _state_error(
                ErrorCode.STATE_CORRUPT, "enrolled host metadata is invalid", error
            ) from error
        self.store_signed_grant(
            signed_grant,
            host_key_fingerprint=str(row[0]),
            remote_user=str(row[1]),
            host_metadata=metadata,
            stored_at=stored_at,
            issuer_key=issuer_key,
        )

    def list_signed_grants(self, *, include_revoked: bool = False) -> tuple[SignedGrant, ...]:
        """Return durable grants in stable issuance order."""
        query = "SELECT grant_cbor FROM grants"
        if not include_revoked:
            query += " WHERE grant_id NOT IN (SELECT grant_id FROM revocations)"
        query += " ORDER BY issued_at, grant_id"
        with self.transaction() as connection:
            rows = connection.execute(query).fetchall()
        try:
            return tuple(SignedGrant.from_cbor(bytes(row[0])) for row in rows)
        except (AstralError, TypeError, ValueError) as error:
            raise _state_error(ErrorCode.STATE_CORRUPT, "stored grant is invalid", error) from error

    def grant_verification_context(self, grant_id: str, *, now: int) -> GrantVerificationContext:
        with self.transaction() as connection:
            row = connection.execute(
                """SELECT grants.host_id, hosts.host_key_fingerprint, hosts.remote_user
                   FROM grants JOIN hosts ON hosts.host_id = grants.host_id
                   WHERE grants.grant_id = ?""",
                (grant_id,),
            ).fetchone()
        if row is None:
            raise _state_error(ErrorCode.HOST_RECORD, "grant host binding is absent")
        return GrantVerificationContext(
            host_id=HostId(str(row[0])),
            ssh_host_key_fingerprint=str(row[1]),
            remote_user=str(row[2]),
            now=now,
        )

    def issuer_public_key(self, grant_id: str) -> Ed25519PublicKey:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT public_key FROM grant_issuer_keys WHERE grant_id = ?", (grant_id,)
            ).fetchone()
        if row is None:
            raise _state_error(ErrorCode.CRYPTO_SIGNATURE, "grant issuer key is absent")
        try:
            return Ed25519PublicKey.from_public_bytes(bytes(row[0]))
        except ValueError as error:
            raise _state_error(
                ErrorCode.STATE_CORRUPT, "stored issuer key is invalid", error
            ) from error

    def signed_grant(self, grant_id: str) -> SignedGrant:
        """Load one durable grant by exact identifier."""
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT grant_cbor FROM grants WHERE grant_id = ?", (grant_id,)
            ).fetchone()
        if row is None:
            raise _state_error(ErrorCode.GRANT_INVALID, "grant was not found")
        try:
            return SignedGrant.from_cbor(bytes(row[0]))
        except (AstralError, TypeError, ValueError) as error:
            raise _state_error(ErrorCode.STATE_CORRUPT, "stored grant is invalid", error) from error

    def validate_signed_grant(
        self, signed_grant: SignedGrant, *, issuer_key: object, context: GrantVerificationContext
    ) -> Grant:
        """Verify signature, binding, and time window before any session can use grant."""
        try:
            return signed_grant.verify(issuer_key, context)  # type: ignore[arg-type]
        except AstralError:
            raise
        except (AttributeError, TypeError, ValueError) as error:
            raise _state_error(
                ErrorCode.CRYPTO_SIGNATURE, "grant verification failed", error
            ) from error

    def revoke_grant(
        self,
        grant_id: str,
        *,
        reason: str,
        remote_revoke: Callable[[SignedGrant], None] | None = None,
        revoked_at: int | None = None,
    ) -> str:
        """Mark grant unusable locally before attempting remote revocation."""
        when = int(time.time()) if revoked_at is None else revoked_at
        if when < 0 or not reason or "\x00" in reason:
            raise _state_error(ErrorCode.GRANT_INVALID, "revocation reason is invalid")
        signed = self.signed_grant(grant_id)
        with self.transaction(write=True) as connection:
            connection.execute(
                "UPDATE sessions SET state = 'revoked', ended_at = ? "
                "WHERE grant_id = ? AND state = 'active'",
                (when, grant_id),
            )
            connection.execute(
                "INSERT OR REPLACE INTO revocations VALUES (?, ?, ?, ?)",
                (grant_id, when, reason, "pending"),
            )
            self._audit(
                connection,
                "grant.revoked.local",
                "grant",
                grant_id,
                {"reason": reason, "remote_state": "pending"},
                when,
            )
        remote_state = "pending"
        if remote_revoke is not None:
            try:
                remote_revoke(signed)
            except Exception as error:
                remote_state = f"offline: {error}"
            else:
                remote_state = "confirmed"
        with self.transaction(write=True) as connection:
            connection.execute(
                "UPDATE revocations SET remote_state = ? WHERE grant_id = ?",
                (remote_state, grant_id),
            )
            self._audit(
                connection,
                "grant.revoked.remote",
                "grant",
                grant_id,
                {"remote_state": remote_state},
                when,
            )
        return remote_state

    def grant_is_revoked(self, grant_id: str) -> bool:
        with self.transaction() as connection:
            return (
                connection.execute(
                    "SELECT 1 FROM revocations WHERE grant_id = ?", (grant_id,)
                ).fetchone()
                is not None
            )

    def _audit(
        self,
        connection: sqlite3.Connection,
        kind: str,
        subject_type: str,
        subject_id: str,
        payload: Mapping[str, object],
        occurred_at: int,
    ) -> None:
        previous_row = connection.execute(
            "SELECT event_id FROM audit_events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        previous = None if previous_row is None else str(previous_row[0])
        event = AuditEvent.create(
            kind,
            subject_type,
            subject_id,
            payload,
            previous_event_id=previous,
            occurred_at=occurred_at,
        )
        envelope = {
            "payload": dict(event.payload),
            "previous_event_id": event.previous_event_id,
            "schema_version": event.schema_version,
        }
        connection.execute(
            "INSERT INTO audit_events VALUES (?, ?, ?, ?, ?, ?)",
            (
                event.event_id,
                event.occurred_at,
                event.kind,
                event.subject_type,
                event.subject_id,
                json.dumps(envelope, separators=(",", ":"), sort_keys=True),
            ),
        )

    def list_audit_events(self) -> tuple[AuditEvent, ...]:
        """Return valid audit events; malformed legacy rows are ignored safely."""
        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT event_id, occurred_at, kind, subject_type, subject_id, payload_json "
                "FROM audit_events ORDER BY rowid"
            ).fetchall()
        events: list[AuditEvent] = []
        for row in rows:
            try:
                raw_payload = json.loads(str(row[5]))
                if not isinstance(raw_payload, dict):
                    raise AuditEventError("audit payload is not an object")
                if set(raw_payload) == {"payload", "previous_event_id", "schema_version"}:
                    payload = raw_payload["payload"]
                    previous = raw_payload["previous_event_id"]
                    version = raw_payload["schema_version"]
                else:
                    payload = raw_payload
                    previous = None
                    version = 1
                if not isinstance(payload, dict):
                    raise AuditEventError("audit payload is not an object")
                events.append(
                    AuditEvent(
                        event_id=row[0],
                        occurred_at=row[1],
                        kind=row[2],
                        subject_type=row[3],
                        subject_id=row[4],
                        payload=payload,
                        previous_event_id=previous,
                        schema_version=version,
                    )
                )
            except (AuditEventError, TypeError, ValueError, json.JSONDecodeError):
                continue
        return tuple(events)

    def record_audit(
        self,
        kind: str,
        subject_type: str,
        subject_id: str,
        payload: Mapping[str, object],
        *,
        occurred_at: int | None = None,
    ) -> None:
        """Persist one validated audit event outside another state transaction."""
        when = int(time.time()) if occurred_at is None else occurred_at
        with self.transaction(write=True) as connection:
            self._audit(connection, kind, subject_type, subject_id, payload, when)

    def audit_event(self, event_id: str) -> AuditEvent:
        """Load one exact event or reject an unknown identifier."""
        match = next(
            (event for event in self.list_audit_events() if event.event_id == event_id), None
        )
        if match is None:
            raise _state_error(ErrorCode.STATE_CORRUPT, "audit event was not found")
        return match

    def export_audit(self, *, path_mode: PathMode = PathMode.REDACT) -> str:
        """Export valid local events with explicit path privacy treatment."""
        return "".join(
            json.dumps(event.to_dict(path_mode=path_mode), separators=(",", ":"), sort_keys=True)
            + "\n"
            for event in self.list_audit_events()
        )

    def audit_chain_errors(self) -> tuple[str, ...]:
        """Return broken event references without exposing payload details."""
        return validate_chain(self.list_audit_events())

    def retire_expired_sessions(self, *, now: int | None = None) -> int:
        when = int(time.time()) if now is None else now
        with self.transaction(write=True) as connection:
            cursor = connection.execute(
                "UPDATE sessions SET state = 'expired', ended_at = ? "
                "WHERE state = 'active' AND grant_id IN "
                "(SELECT grant_id FROM grants WHERE expires_at <= ?)",
                (when, when),
            )
            return int(cursor.rowcount)

    def open_session(self, grant_id: str, *, started_at: int | None = None) -> str:
        """Open one durable session only after local revocation and expiry checks."""
        when = int(time.time()) if started_at is None else started_at
        signed = self.signed_grant(grant_id)
        self.validate_signed_grant(
            signed,
            issuer_key=self.issuer_public_key(grant_id),
            context=self.grant_verification_context(grant_id, now=when),
        )
        if self.grant_is_revoked(grant_id):
            raise _state_error(ErrorCode.DAEMON_AUTH, "revoked grant cannot open a session")
        with self.transaction(write=True) as connection:
            active = connection.execute(
                "SELECT 1 FROM sessions WHERE state = 'active' LIMIT 1"
            ).fetchone()
            if active is not None:
                raise _state_error(
                    ErrorCode.DAEMON_AUTH, "another remote session is already active"
                )
            session_id = str(SessionId(str(uuid.uuid4())))
            connection.execute(
                "INSERT INTO sessions VALUES (?, ?, 'active', ?, NULL)",
                (session_id, grant_id, when),
            )
            self._audit(
                connection,
                "session.opened",
                "session",
                session_id,
                {"grant_id": grant_id},
                when,
            )
            return session_id

    def close_session(self, session_id: str, *, ended_at: int | None = None) -> None:
        when = int(time.time()) if ended_at is None else ended_at
        with self.transaction(write=True) as connection:
            cursor = connection.execute(
                "UPDATE sessions SET state = 'closed', ended_at = ? "
                "WHERE session_id = ? AND state = 'active'",
                (when, session_id),
            )
            if cursor.rowcount != 1:
                raise _state_error(ErrorCode.DAEMON_AUTH, "active session was not found")
            self._audit(
                connection,
                "session.closed",
                "session",
                session_id,
                {},
                when,
            )

    def list_sessions(self) -> tuple[dict[str, object], ...]:
        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT session_id, grant_id, state, started_at, ended_at "
                "FROM sessions ORDER BY started_at, session_id"
            ).fetchall()
        return tuple(
            {
                "session_id": str(row[0]),
                "grant_id": str(row[1]),
                "state": str(row[2]),
                "started_at": int(row[3]),
                "ended_at": None if row[4] is None else int(row[4]),
            }
            for row in rows
        )

    def active_listing_session(self) -> ActiveListingSession | None:
        """Return sole active session and its fixed host binding; ambiguity fails closed."""
        with self.transaction() as connection:
            rows = connection.execute(
                """
                SELECT sessions.session_id, grants.grant_cbor,
                       hosts.host_id, hosts.host_key_fingerprint,
                       hosts.remote_user, hosts.metadata_json
                FROM sessions
                JOIN grants ON grants.grant_id = sessions.grant_id
                JOIN hosts ON hosts.host_id = grants.host_id
                WHERE sessions.state = 'active'
                ORDER BY sessions.started_at DESC
                """
            ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise _state_error(
                ErrorCode.DAEMON_AUTH, "multiple active sessions make listing authority ambiguous"
            )
        try:
            metadata = json.loads(str(rows[0][5]))
            if not isinstance(metadata, dict):
                raise TypeError("host metadata")
            signed_grant = SignedGrant.from_cbor(bytes(rows[0][1]))
            return ActiveListingSession(
                session_id=str(rows[0][0]),
                signed_grant=signed_grant,
                host_id=str(rows[0][2]),
                host_key_fingerprint=str(rows[0][3]),
                remote_user=str(rows[0][4]),
                host_metadata=metadata,
            )
        except (AstralError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise _state_error(
                ErrorCode.STATE_CORRUPT, "active session host or grant is invalid", error
            ) from error

    def active_listing_scope(self) -> SessionListingScope | None:
        """Return virtual scope for sole active session."""
        active = self.active_listing_session()
        if active is None:
            return None
        grant = active.signed_grant.grant
        return SessionListingScope(
            str(grant.grant_id), tuple(export.virtual_target for export in grant.exports)
        )

    @property
    def state_version(self) -> int:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT value FROM state_meta WHERE key = 'state_version'"
            ).fetchone()
        if row is None:
            raise _state_error(ErrorCode.STATE_CORRUPT, "state version metadata is absent")
        return int(row[0])

    @contextmanager
    def transaction(self, *, write: bool = False) -> Iterator[sqlite3.Connection]:
        """Open independent transaction; writers reserve lock before mutation."""
        connection = self._connect()
        connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()

    def _validate_migrations(self) -> None:
        versions = [migration.version for migration in self.migrations]
        if versions != list(range(1, len(versions) + 1)):
            raise _state_error(
                ErrorCode.STATE_VERSION, "migration versions must start at one without gaps"
            )
        if len({migration.name for migration in self.migrations}) != len(self.migrations):
            raise _state_error(ErrorCode.STATE_VERSION, "migration names must be unique")

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA busy_timeout = 5000")
            return connection
        except sqlite3.Error as error:
            raise _state_error(
                ErrorCode.STATE_OPEN, f"could not open state database: {self.path}", error
            ) from error

    def _initialize(self) -> None:
        ensure_private_directory(self.path.parent)
        existed = self.path.exists()
        if existed:
            check_private_path(self.path)
        connection = self._connect()
        try:
            os.chmod(self.path, 0o600)
            check_private_path(self.path)
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            self._check_sidecars()
            self._bootstrap(connection)
            self._verify_history(connection)
            self._apply_pending(connection)
            self._ensure_runtime_tables(connection)
        except (OSError, sqlite3.Error, ValueError) as error:
            raise _state_error(
                ErrorCode.STATE_OPEN, "could not initialize state database", error
            ) from error
        finally:
            connection.close()

    def _check_sidecars(self) -> None:
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{self.path}{suffix}")
            if sidecar.exists():
                os.chmod(sidecar, 0o600)
                check_private_path(sidecar)

    def _ensure_runtime_tables(self, connection: sqlite3.Connection) -> None:
        """Create mount runtime records without mutating signed grant tables."""
        connection.execute(
            """CREATE TABLE IF NOT EXISTS grant_issuer_keys (
                grant_id TEXT PRIMARY KEY REFERENCES grants(grant_id),
                public_key BLOB NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS mount_runtime (
                mount_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(session_id),
                grant_id TEXT NOT NULL REFERENCES grants(grant_id),
                mount_path TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL,
                mode TEXT NOT NULL,
                virtual_target TEXT NOT NULL,
                pid INTEGER,
                config_path TEXT NOT NULL,
                cache_path TEXT NOT NULL,
                transport_capability TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                ended_at INTEGER,
                failure_reason TEXT,
                flush_warning TEXT
            )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS mount_runtime_session_idx ON mount_runtime(session_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS mount_runtime_grant_idx ON mount_runtime(grant_id)"
        )

    def create_mount_runtime(self, record: Mapping[str, object]) -> None:
        required = {
            "mount_id",
            "session_id",
            "grant_id",
            "mount_path",
            "state",
            "mode",
            "virtual_target",
            "config_path",
            "cache_path",
            "transport_capability",
            "created_at",
            "updated_at",
        }
        if set(record) != required and set(record) != required | {"pid"}:
            raise _state_error(ErrorCode.STATE_CORRUPT, "mount runtime record fields are invalid")
        with self.transaction(write=True) as connection:
            connection.execute(
                """INSERT INTO mount_runtime(
                    mount_id, session_id, grant_id, mount_path, state, mode,
                    virtual_target, pid, config_path, cache_path,
                    transport_capability, created_at, updated_at,
                    ended_at, failure_reason, flush_warning
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)""",
                tuple(
                    record.get(key)
                    for key in (
                        "mount_id",
                        "session_id",
                        "grant_id",
                        "mount_path",
                        "state",
                        "mode",
                        "virtual_target",
                        "pid",
                        "config_path",
                        "cache_path",
                        "transport_capability",
                        "created_at",
                        "updated_at",
                    )
                ),
            )

    def update_mount_runtime(self, mount_id: str, **fields: object) -> None:
        allowed = {
            "state",
            "pid",
            "updated_at",
            "ended_at",
            "failure_reason",
            "flush_warning",
        }
        if not fields or not set(fields).issubset(allowed):
            raise _state_error(ErrorCode.STATE_CORRUPT, "mount runtime update fields are invalid")
        assignments = ", ".join(f"{key} = ?" for key in fields)
        with self.transaction(write=True) as connection:
            cursor = connection.execute(
                f"UPDATE mount_runtime SET {assignments} WHERE mount_id = ?",
                (*fields.values(), mount_id),
            )
            if cursor.rowcount != 1:
                raise _state_error(ErrorCode.STATE_CORRUPT, "mount runtime record was not found")

    def mount_runtime(self, mount_id: str) -> dict[str, object]:
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM mount_runtime WHERE mount_id = ?", (mount_id,)
            ).fetchone()
            columns = [item[1] for item in connection.execute("PRAGMA table_info(mount_runtime)")]
        if row is None:
            raise _state_error(ErrorCode.STATE_CORRUPT, "mount runtime record was not found")
        return dict(zip(columns, row, strict=True))

    def list_mount_runtime(self) -> tuple[dict[str, object], ...]:
        with self.transaction() as connection:
            rows = connection.execute(
                "SELECT * FROM mount_runtime ORDER BY created_at, mount_id"
            ).fetchall()
            columns = [item[1] for item in connection.execute("PRAGMA table_info(mount_runtime)")]
        return tuple(dict(zip(columns, row, strict=True)) for row in rows)

    def _bootstrap(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                checksum TEXT NOT NULL,
                applied_at INTEGER NOT NULL
            )"""
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS state_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )"""
        )

    def _verify_history(self, connection: sqlite3.Connection) -> None:
        rows = connection.execute(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version"
        ).fetchall()
        if len(rows) > len(self.migrations):
            raise _state_error(
                ErrorCode.STATE_VERSION, "state database is newer than this software"
            )
        for migration, row in zip(self.migrations[: len(rows)], rows, strict=True):
            if (migration.version, migration.name, migration.checksum) != row:
                raise _state_error(
                    ErrorCode.STATE_CORRUPT, "migration history does not match trusted registry"
                )
        row = connection.execute(
            "SELECT value FROM state_meta WHERE key = 'state_version'"
        ).fetchone()
        expected = len(rows)
        if row is not None and row[0] != str(expected):
            raise _state_error(
                ErrorCode.STATE_CORRUPT, "state version does not match migration history"
            )
        if row is None and expected:
            raise _state_error(ErrorCode.STATE_CORRUPT, "migration history has no state version")

    def _apply_pending(self, connection: sqlite3.Connection) -> None:
        applied = connection.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
        for migration in self.migrations[applied:]:
            if migration.destructive:
                self._backup_before(migration.version, connection)
            try:
                connection.execute("BEGIN IMMEDIATE")
                migration.apply(connection)
                connection.execute(
                    "INSERT INTO schema_migrations(version, name, checksum, applied_at) "
                    "VALUES (?, ?, ?, 0)",
                    (migration.version, migration.name, migration.checksum),
                )
                connection.execute(
                    "INSERT OR REPLACE INTO state_meta(key, value) VALUES ('state_version', ?)",
                    (str(migration.version),),
                )
                connection.commit()
            except Exception as error:
                connection.rollback()
                raise _state_error(
                    ErrorCode.STATE_MIGRATION, f"migration {migration.version} failed", error
                ) from error

    def _backup_before(self, version: int, source: sqlite3.Connection) -> Path:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".state-before-v{version}.", dir=self.path.parent
        )
        temporary = Path(temporary_name)
        destination = self.path.parent / f"state-before-v{version}.sqlite3"
        try:
            os.fchmod(descriptor, 0o600)
            os.close(descriptor)
            target = sqlite3.connect(temporary)
            try:
                source.backup(target)
            finally:
                target.close()
            descriptor = os.open(temporary, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, destination)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            check_private_path(destination)
            return destination
        except (OSError, sqlite3.Error) as error:
            raise _state_error(
                ErrorCode.STATE_MIGRATION, f"could not back up before migration {version}", error
            ) from error
        finally:
            temporary.unlink(missing_ok=True)
