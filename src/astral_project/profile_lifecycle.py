"""Durable, transactional lifecycle for reusable projected-home profiles."""

from __future__ import annotations

import difflib
import fcntl
import os
import shlex
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import replace
from pathlib import Path

from astral_project.audit.events import AuditLog
from astral_project.core.errors import AstralError
from astral_project.core.paths import (
    atomic_write_private,
    check_private_path,
    create_private_file,
    ensure_private_directory,
    safe_component,
)
from astral_project.profile import (
    ApprovalProvenance,
    Profile,
    ProfileError,
    Rule,
    validate_profile,
)

AuditSink = Callable[[str, str, str, Mapping[str, object]], None]


class ProfileLifecycleError(ProfileError):
    """Profile lifecycle operation was rejected without changing trusted state."""


def _has_symlink_component(path: Path) -> bool:
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            return True
    return False


class ProfileStore:
    """Own profile files below one private, path-safe configuration directory."""

    def __init__(
        self,
        root: Path,
        *,
        audit_log: AuditLog | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self.root = root
        self.profiles = root / "profiles"
        self.archive = self.profiles / "archive"
        if audit_log is not None and audit_sink is not None:
            raise ValueError("profile audit requires one sink")
        self.audit_log = audit_log
        self.audit_sink = audit_sink
        ensure_private_directory(self.profiles)

    def path(self, profile_id: str) -> Path:
        return self.profiles / f"{safe_component(profile_id)}.toml"

    def load(self, profile_id: str) -> Profile:
        path = self.path(profile_id)
        try:
            check_private_path(path)
            profile = Profile.from_toml(path.read_bytes())
        except (OSError, ProfileError, AstralError) as error:
            raise ProfileLifecycleError(f"profile could not be loaded: {profile_id}") from error
        if profile.profile_id != profile_id:
            raise ProfileLifecycleError("profile identifier does not match filename")
        return profile

    def list(self) -> tuple[Profile, ...]:
        values: list[Profile] = []
        for path in sorted(self.profiles.glob("*.toml")):
            values.append(self.load(path.stem))
        return tuple(values)

    def create(self, profile_id: str, *, name: str | None = None) -> Profile:
        safe_component(profile_id)
        profile = Profile(1, profile_id, name or profile_id)
        path = self.path(profile_id)
        try:
            create_private_file(path, profile.to_toml().encode())
        except (OSError, AstralError) as error:
            raise ProfileLifecycleError(
                f"profile already exists or could not be created: {profile_id}"
            ) from error
        self._audit("profile.created", profile_id, {"revision": profile.revision})
        return profile

    def save(self, profile: Profile, *, expected_revision: int | None = None) -> Profile:
        validate_profile(profile)
        with self._profile_lock(profile.profile_id):
            return self._save_locked(profile, expected_revision=expected_revision)

    def _save_locked(self, profile: Profile, *, expected_revision: int | None) -> Profile:
        path = self.path(profile.profile_id)
        if expected_revision is not None:
            current = self.load(profile.profile_id)
            if current.revision != expected_revision:
                raise ProfileLifecycleError("profile changed during lifecycle operation")
        try:
            atomic_write_private(path, profile.to_toml().encode())
        except (OSError, AstralError) as error:
            raise ProfileLifecycleError(
                f"profile could not be saved: {profile.profile_id}"
            ) from error
        self._audit("profile.edited", profile.profile_id, {"revision": profile.revision})
        return profile

    def commit_learning(
        self,
        profile_id: str,
        rules: tuple[Rule, ...],
        *,
        provenance: ApprovalProvenance | None = None,
    ) -> Profile:
        provenances = () if provenance is None else (provenance,)
        return self.commit_learning_batch(profile_id, ((rule, None) for rule in rules), provenances)

    def commit_learning_batch(
        self,
        profile_id: str,
        approvals: tuple[tuple[Rule, ApprovalProvenance | None], ...]
        | Iterator[tuple[Rule, ApprovalProvenance | None]],
        provenances: tuple[ApprovalProvenance, ...] = (),
    ) -> Profile:
        staged = tuple(approvals)
        rules = tuple(rule for rule, _provenance in staged)
        staged_provenance = tuple(
            provenance for _rule, provenance in staged if provenance is not None
        )
        with self._profile_lock(profile_id):
            current = self.load(profile_id)
            if current.sealed:
                raise ProfileLifecycleError("sealed profile cannot accept learning")
            merged = tuple(dict.fromkeys((*current.rules, *rules)))
            updated = replace(
                current,
                rules=merged,
                revision=current.revision + 1,
                provenance=current.provenance + provenances + staged_provenance,
            )
            saved = self._save_locked(updated, expected_revision=current.revision)
            self._audit("profile.learned", profile_id, {"revision": saved.revision})
            return saved

    def seal(self, profile_id: str) -> Profile:
        with self._profile_lock(profile_id):
            current = self.load(profile_id)
            if current.sealed:
                return current
            saved = self._save_locked(
                replace(current, sealed=True, revision=current.revision + 1),
                expected_revision=current.revision,
            )
            self._audit("profile.sealed", profile_id, {"revision": saved.revision})
            return saved

    def unseal(self, profile_id: str) -> Profile:
        with self._profile_lock(profile_id):
            current = self.load(profile_id)
            if not current.sealed:
                return current
            saved = self._save_locked(
                replace(current, sealed=False, revision=current.revision + 1),
                expected_revision=current.revision,
            )
            self._audit("profile.unsealed", profile_id, {"revision": saved.revision})
            return saved

    def export(self, profile_id: str, destination: Path) -> Path:
        profile = self.load(profile_id)
        if not destination.is_absolute():
            raise ProfileLifecycleError("profile export destination must be absolute")
        if _has_symlink_component(destination):
            raise ProfileLifecycleError("profile export destination must not be a symlink")
        try:
            atomic_write_private(destination, profile.to_toml().encode())
        except (OSError, AstralError) as error:
            raise ProfileLifecycleError("profile export failed") from error
        return destination

    def import_profile(self, source: Path, *, profile_id: str | None = None) -> Profile:
        if not source.is_absolute():
            raise ProfileLifecycleError("profile import source must be absolute")
        if _has_symlink_component(source):
            raise ProfileLifecycleError("profile import source must not be a symlink")
        try:
            check_private_path(source)
            profile = Profile.from_toml(source.read_bytes())
        except (OSError, ProfileError, AstralError) as error:
            raise ProfileLifecycleError("profile import is invalid") from error
        if profile_id is not None and profile.profile_id != profile_id:
            raise ProfileLifecycleError("import identifier does not match requested profile")
        safe_component(profile.profile_id)
        if self.path(profile.profile_id).exists():
            raise ProfileLifecycleError("profile already exists")
        return self.save_new(profile)

    def save_new(self, profile: Profile) -> Profile:
        validate_profile(profile)
        try:
            create_private_file(self.path(profile.profile_id), profile.to_toml().encode())
        except (OSError, AstralError) as error:
            raise ProfileLifecycleError("profile could not be imported") from error
        self._audit("profile.imported", profile.profile_id, {"revision": profile.revision})
        return profile

    def archive_profile(self, profile_id: str) -> Path:
        """Atomically remove current revision under same profile transaction lock."""
        with self._profile_lock(profile_id):
            profile = self.load(profile_id)
            ensure_private_directory(self.archive)
            destination = (
                self.archive
                / f"{safe_component(profile_id)}-{profile.revision}-{time.time_ns()}.toml"
            )
            try:
                os.replace(self.path(profile_id), destination)
                descriptor = os.open(self.archive, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except OSError as error:
                raise ProfileLifecycleError("profile archive failed") from error
            check_private_path(destination)
            self._audit("profile.archived", profile_id, {"revision": profile.revision})
            return destination

    def _audit(self, kind: str, profile_id: str, payload: dict[str, object]) -> None:
        if self.audit_sink is not None:
            self.audit_sink(kind, "profile", profile_id, payload)
        elif self.audit_log is not None:
            self.audit_log.append(kind, "profile", profile_id, payload)

    @contextmanager
    def _profile_lock(self, profile_id: str) -> Iterator[None]:
        lock_path = self.profiles / f".{safe_component(profile_id)}.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            details = os.fstat(descriptor)
            if details.st_uid != os.geteuid() or details.st_mode & 0o077:
                raise ProfileLifecycleError("profile transaction lock is unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def review(self, profile_id: str) -> str:
        return self.load(profile_id).to_toml()

    def diff(self, profile_id: str, candidate: Path) -> str:
        current = self.review(profile_id).splitlines(keepends=True)
        try:
            proposed = candidate.read_text(encoding="utf-8").splitlines(keepends=True)
        except OSError as error:
            raise ProfileLifecycleError("profile diff candidate could not be read") from error
        return "".join(
            difflib.unified_diff(current, proposed, fromfile=profile_id, tofile=str(candidate))
        )

    def edit(
        self,
        profile_id: str,
        *,
        editor: str | None = None,
        run: Callable[..., subprocess.CompletedProcess[bytes]] = subprocess.run,
    ) -> Profile:
        current = self.load(profile_id)
        if current.sealed:
            raise ProfileLifecycleError("sealed profile cannot be edited")
        command = shlex.split(editor or os.environ.get("EDITOR", "vi"))
        if not command or any("\x00" in value for value in command):
            raise ProfileLifecycleError("profile editor command is invalid")
        descriptor, name = tempfile.mkstemp(
            prefix=f".{profile_id}.", suffix=".toml", dir=self.profiles
        )
        temporary = Path(name)
        try:
            remaining = memoryview(current.to_toml().encode())
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("profile editor temporary write made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            result = run([*command, str(temporary)], check=False)
            if result.returncode != 0:
                raise ProfileLifecycleError("profile editor failed; prior revision remains active")
            candidate = Profile.from_toml(temporary.read_bytes())
            if candidate.profile_id != profile_id:
                raise ProfileLifecycleError("edited profile identifier cannot change")
            return self.save(
                replace(candidate, revision=current.revision + 1),
                expected_revision=current.revision,
            )
        except (OSError, ProfileError) as error:
            if isinstance(error, ProfileLifecycleError):
                raise
            raise ProfileLifecycleError(
                "edited profile is invalid; prior revision remains active"
            ) from error
        finally:
            if descriptor != -1:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
