"""Private durable SQLite state and transactional migrations."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import check_private_path, ensure_private_directory

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
