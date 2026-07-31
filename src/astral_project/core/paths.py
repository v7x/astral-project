"""XDG layout and private filesystem helpers."""

from __future__ import annotations

import os
import stat
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode


@dataclass(frozen=True, slots=True)
class XdgPaths:
    """Astral Project XDG roots."""

    config: Path
    state: Path
    runtime: Path


def _required_environment(environment: Mapping[str, str], variable: str) -> str:
    try:
        return environment[variable]
    except KeyError as error:
        raise AstralError(
            code=ErrorCode.CONFIG_INVALID_PATH,
            message=f"{variable} is required",
            security_result="XDG path was rejected",
            unsafe_reason="trusted state needs an explicit absolute root",
            next_action=f"set {variable} to an absolute path",
        ) from error


def _absolute_environment_path(value: str, variable: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise AstralError(
            code=ErrorCode.CONFIG_INVALID_PATH,
            message=f"{variable} must be an absolute path",
            security_result="XDG path was rejected",
            unsafe_reason="relative state paths can redirect trusted files",
            next_action=f"set {variable} to an absolute path",
        )
    return path


def resolve_xdg_paths(environment: Mapping[str, str]) -> XdgPaths:
    """Resolve application paths without creating them."""
    home = _absolute_environment_path(_required_environment(environment, "HOME"), "HOME")
    config_root = _absolute_environment_path(
        environment.get("XDG_CONFIG_HOME", str(home / ".config")), "XDG_CONFIG_HOME"
    )
    state_root = _absolute_environment_path(
        environment.get("XDG_STATE_HOME", str(home / ".local" / "state")), "XDG_STATE_HOME"
    )
    runtime_root = _absolute_environment_path(
        _required_environment(environment, "XDG_RUNTIME_DIR"), "XDG_RUNTIME_DIR"
    )
    return XdgPaths(
        config=config_root / "astral-project",
        state=state_root / "astral-project",
        runtime=runtime_root / "astral-project",
    )


def safe_component(name: str) -> str:
    """Reject user-controlled value that could become a path component escape."""
    if (
        not name
        or name in {".", ".."}
        or "\x00" in name
        or "/" in name
        or "\\" in name
        or Path(name).name != name
    ):
        raise AstralError(
            code=ErrorCode.PATH_INVALID_NAME,
            message=f"invalid path component {name!r}",
            security_result="path component was rejected",
            unsafe_reason="path traversal can redirect trusted state",
            next_action="use one non-empty filename component",
        )
    return name


def _permission_error(code: ErrorCode, path: Path, message: str) -> AstralError:
    return AstralError(
        code=code,
        message=f"{message}: {path}",
        security_result="private path was rejected",
        unsafe_reason="trusted state must not be controlled by another user or group",
        next_action="correct owner and permissions, then retry",
    )


def check_private_path(path: Path, *, expected_uid: int | None = None) -> None:
    """Require existing private regular file or directory owned by current user."""
    details = path.lstat()
    owner = os.getuid() if expected_uid is None else expected_uid
    if details.st_uid != owner:
        raise _permission_error(ErrorCode.PERMISSION_WRONG_OWNER, path, "wrong owner")
    if not stat.S_ISDIR(details.st_mode) and not stat.S_ISREG(details.st_mode):
        raise _permission_error(ErrorCode.PERMISSION_INVALID_TYPE, path, "unsupported file type")
    if details.st_mode & 0o077:
        raise _permission_error(ErrorCode.PERMISSION_INSECURE_MODE, path, "group or world access")


def ensure_private_directory(path: Path, *, expected_uid: int | None = None) -> Path:
    """Create and validate a 0700 private directory."""
    with suppress(FileExistsError):
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not stat.S_ISDIR(path.lstat().st_mode):
        raise _permission_error(ErrorCode.PERMISSION_INVALID_TYPE, path, "not a directory")
    check_private_path(path, expected_uid=expected_uid)
    return path


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("write returned no progress")
        view = view[written:]


def create_private_file(path: Path, content: bytes, *, expected_uid: int | None = None) -> Path:
    """Create a new 0600 regular file without following a final symlink."""
    ensure_private_directory(path.parent, expected_uid=expected_uid)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError as error:
        raise AstralError(
            code=ErrorCode.FILE_CREATE,
            message=f"could not create private file: {path}",
            security_result="file was not created",
            unsafe_reason="private state requires exclusive safe creation",
            next_action="inspect parent directory and target name",
            dependency_error=str(error),
        ) from error
    try:
        _write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    check_private_path(path, expected_uid=expected_uid)
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_error(path: Path, error: OSError) -> AstralError:
    return AstralError(
        code=ErrorCode.FILE_ATOMIC_WRITE,
        message=f"could not atomically write private file: {path}",
        security_result="previous file remains authoritative",
        unsafe_reason="partial trusted state cannot be accepted",
        next_action="inspect storage failure and retry",
        dependency_error=str(error),
    )


def atomic_write_private(path: Path, content: bytes, *, expected_uid: int | None = None) -> Path:
    """Replace private file only after complete same-directory write and fsync."""
    parent = ensure_private_directory(path.parent, expected_uid=expected_uid)
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{safe_component(path.name)}.", dir=parent
        )
    except OSError as error:
        raise _atomic_write_error(path, error) from error

    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, content)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(parent)
    except OSError as error:
        raise _atomic_write_error(path, error) from error
    finally:
        if descriptor != -1:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    check_private_path(path, expected_uid=expected_uid)
    return path
