"""Second-wall process hardening for sandbox children."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import resource
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import ensure_private_directory

_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_TYPE_PATH_BENEATH = 1
LANDLOCK_MINIMUM_ABI = 3
_PR_SET_NO_NEW_PRIVS = 38
_PR_CAPBSET_DROP = 24
_MAX_CAPABILITY = 63
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14
LANDLOCK_HANDLED_ACCESS_FS = (1 << 15) - 1
_READ_ACCESS = (
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
)
_REGULAR_WRITE_ACCESS = (
    _READ_ACCESS
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)
_SOCKET_ACCESS = _READ_ACCESS | LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_REMOVE_FILE
_DEVICE_ACCESS = _READ_ACCESS | LANDLOCK_ACCESS_FS_WRITE_FILE


class RootRole(StrEnum):
    """Fixed authority classes; callers cannot select individual Landlock bits."""

    READ_ONLY = "read-only"
    REGULAR_WRITABLE = "regular-writable"
    SOCKET_RUNTIME = "socket-runtime"
    DEVICE_RUNTIME = "device-runtime"


class HardeningError(AstralError):
    """Fail-closed hardening error."""


@dataclass(frozen=True, slots=True)
class HardeningStatus:
    """Safe status suitable for doctor and audit output."""

    landlock_available: bool
    abi: int | None
    required: bool
    enforced: bool
    reason: str
    required_abi: int = LANDLOCK_MINIMUM_ABI

    def to_dict(self) -> dict[str, object]:
        return {
            "landlock_abi": self.abi,
            "landlock_available": self.landlock_available,
            "landlock_required_abi": self.required_abi,
            "required": self.required,
            "enforced": self.enforced,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class HardeningPolicy:
    """Execution policy for one sandbox child."""

    required: bool = True
    allowed_roots: tuple[tuple[Path, RootRole | bool], ...] = ()
    max_open_files: int = 1024
    max_processes: int = 128

    def __post_init__(self) -> None:
        if not isinstance(self.required, bool):
            raise ValueError("hardening required flag is invalid")
        if self.max_open_files < 64 or self.max_processes < 1:
            raise ValueError("hardening rlimits are invalid")
        for path, role in self.allowed_roots:
            if not isinstance(path, Path) or not path.is_absolute() or not path.exists():
                raise ValueError("hardening root is unavailable")
            if not isinstance(role, (RootRole, bool)):
                raise ValueError("hardening root role is invalid")

    @classmethod
    def for_plan(
        cls, roots: Sequence[tuple[Path, RootRole | bool]], *, writable_tmp: bool = True
    ) -> HardeningPolicy:
        """Build policy with fixed system roots plus exact plan-owned roots."""
        if not isinstance(writable_tmp, bool):
            raise ValueError("hardening temporary-root mutability is invalid")
        fixed_roles = {
            Path("/usr"): RootRole.READ_ONLY,
            Path("/etc"): RootRole.READ_ONLY,
            Path("/dev"): RootRole.DEVICE_RUNTIME,
            Path("/proc"): RootRole.READ_ONLY,
            Path("/run"): RootRole.SOCKET_RUNTIME,
            Path("/tmp"): (RootRole.REGULAR_WRITABLE if writable_tmp else RootRole.READ_ONLY),
        }
        unique: dict[Path, RootRole] = {
            path: role for path, role in fixed_roles.items() if path.exists()
        }
        for path, requested_role in roots:
            role = _root_role(requested_role)
            if path in fixed_roles:
                continue
            current = unique.get(path)
            unique[path] = role if current is None else _stronger_role(current, role)
        return cls(allowed_roots=tuple(unique.items()))


def _root_role(value: RootRole | bool) -> RootRole:
    if isinstance(value, bool):
        return RootRole.REGULAR_WRITABLE if value else RootRole.READ_ONLY
    if not isinstance(value, RootRole):
        raise ValueError("hardening root role is invalid")
    return value


def _access_for_role(role: RootRole) -> int:
    return {
        RootRole.READ_ONLY: _READ_ACCESS,
        RootRole.REGULAR_WRITABLE: _REGULAR_WRITE_ACCESS,
        RootRole.SOCKET_RUNTIME: _SOCKET_ACCESS,
        RootRole.DEVICE_RUNTIME: _DEVICE_ACCESS,
    }[role]


def _stronger_role(first: RootRole, second: RootRole) -> RootRole:
    """Merge duplicate roots without dropping either fixed authority need."""
    first_access = _access_for_role(first)
    second_access = _access_for_role(second)
    if first_access | second_access == first_access:
        return first
    if first_access | second_access == second_access:
        return second
    raise ValueError("conflicting hardening root roles")


def detect_landlock(syscall: Callable[..., int] | None = None) -> int | None:
    """Return Landlock ABI or None when kernel does not provide it."""
    call = syscall or _libc_syscall()
    result = call(
        _LANDLOCK_CREATE_RULESET,
        None,
        0,
        _LANDLOCK_CREATE_RULESET_VERSION,
    )
    if result < 0:
        error = ctypes.get_errno()
        if error in {errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL}:
            return None
        raise OSError(error, os.strerror(error))
    return int(result)


def require_available(policy: HardeningPolicy) -> int:
    """Fail before launch when required Landlock ABI support is unavailable."""
    try:
        abi = detect_landlock()
    except OSError as error:
        if policy.required:
            raise _hardening_error(
                f"Landlock ABI probe failed: {error}", ErrorCode.HARDENING_UNAVAILABLE
            ) from error
        return 0
    if abi is None and policy.required:
        raise _hardening_error("Landlock ABI is unavailable")
    if abi is not None and abi < LANDLOCK_MINIMUM_ABI and policy.required:
        raise _hardening_error(
            f"Landlock ABI {abi} is below required ABI {LANDLOCK_MINIMUM_ABI}",
            ErrorCode.HARDENING_UNAVAILABLE,
        )
    return 0 if abi is None else abi


def enforce(policy: HardeningPolicy) -> HardeningStatus:
    """Apply all second-wall controls to current process or raise."""
    try:
        abi = detect_landlock()
    except OSError as error:
        if policy.required:
            raise _hardening_error(
                f"Landlock ABI probe failed: {error}", ErrorCode.HARDENING_UNAVAILABLE
            ) from error
        return HardeningStatus(False, None, False, False, f"Landlock probe failed: {error}")
    if abi is None:
        if policy.required:
            raise _hardening_error("Landlock ABI is unavailable")
        return HardeningStatus(False, None, False, False, "Landlock unavailable")
    if abi < LANDLOCK_MINIMUM_ABI:
        if policy.required:
            raise _hardening_error(
                f"Landlock ABI {abi} is below required ABI {LANDLOCK_MINIMUM_ABI}",
                ErrorCode.HARDENING_UNAVAILABLE,
            )
        return HardeningStatus(
            True,
            abi,
            False,
            False,
            f"Landlock ABI {abi} is below required ABI {LANDLOCK_MINIMUM_ABI}",
        )
    try:
        _set_no_new_privs()
        _set_limits(policy.max_open_files, policy.max_processes)
        _disable_core_dumps()
        _drop_capability_bounding_set()
        _restrict_paths(policy.allowed_roots)
    except (OSError, ValueError) as error:
        raise _hardening_error(
            f"Landlock or process hardening failed: {error}", ErrorCode.HARDENING_APPLY
        ) from error
    return HardeningStatus(
        True, abi, policy.required, True, "Landlock and process hardening enforced"
    )


def status(*, required: bool = True) -> HardeningStatus:
    """Probe availability without changing process restrictions."""
    try:
        abi = detect_landlock()
    except OSError as error:
        return HardeningStatus(False, None, required, False, f"Landlock probe failed: {error}")
    if abi is None:
        return HardeningStatus(False, None, required, False, "Landlock unavailable")
    if abi < LANDLOCK_MINIMUM_ABI:
        return HardeningStatus(
            True,
            abi,
            required,
            False,
            f"Landlock ABI {abi} is below required ABI {LANDLOCK_MINIMUM_ABI}",
        )
    return HardeningStatus(True, abi, required, False, "Landlock available but not applied")


def secure_temp_directory(parent: Path, *, prefix: str = "aspr-") -> Path:
    """Create private temporary directory with no symlink-following fallback."""
    ensure_private_directory(parent)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    os.chmod(path, 0o700)
    return path


def dependency_versions(names: Sequence[str]) -> dict[str, str]:
    """Return installed versions without importing optional dependencies."""
    from importlib.metadata import PackageNotFoundError, version

    result: dict[str, str] = {}
    for name in names:
        try:
            result[name] = version(name)
        except PackageNotFoundError:
            result[name] = "unavailable"
    return result


def _libc_syscall() -> Callable[..., int]:
    if platform.system() != "Linux":
        raise OSError(errno.ENOSYS, "Landlock requires Linux")
    libc = ctypes.CDLL(None, use_errno=True)
    call = libc.syscall
    call.restype = ctypes.c_long
    return call


def _set_no_new_privs() -> None:
    result = _libc_syscall()(157, _PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _set_limits(max_open_files: int, max_processes: int) -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (max_open_files, max_open_files))
    if hasattr(resource, "RLIMIT_NPROC"):  # pragma: no branch - Linux exposes this limit
        resource.setrlimit(resource.RLIMIT_NPROC, (max_processes, max_processes))


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _drop_capability_bounding_set() -> None:
    call = _libc_syscall()
    for capability in range(_MAX_CAPABILITY + 1):
        result = call(157, _PR_CAPBSET_DROP, capability, 0, 0, 0)
        if result != 0 and ctypes.get_errno() not in {errno.EPERM, errno.EINVAL}:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))


def _restrict_paths(roots: Sequence[tuple[Path, RootRole | bool]]) -> None:
    if not roots:
        raise ValueError("Landlock requires at least one allowed root")
    handled = LANDLOCK_HANDLED_ACCESS_FS
    attr = ctypes.c_uint64(handled)
    ruleset = _libc_syscall()(_LANDLOCK_CREATE_RULESET, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if ruleset < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    opened: list[int] = []
    try:
        for path, writable in roots:
            descriptor = os.open(path, os.O_PATH | os.O_CLOEXEC)
            opened.append(descriptor)
            role = _root_role(writable)
            rule = _PathBeneath(
                parent_fd=descriptor,
                allowed_access=_access_for_role(role),
            )
            result = _libc_syscall()(
                _LANDLOCK_ADD_RULE,
                ruleset,
                _LANDLOCK_RULE_TYPE_PATH_BENEATH,
                ctypes.byref(rule),
                0,
            )
            if result != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
        _set_no_new_privs()
        result = _libc_syscall()(_LANDLOCK_RESTRICT_SELF, ruleset, 0)
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    finally:
        for descriptor in opened:
            os.close(descriptor)
        os.close(ruleset)


class _PathBeneath(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int64)]


def _hardening_error(
    message: str, code: ErrorCode = ErrorCode.HARDENING_UNAVAILABLE
) -> HardeningError:
    return HardeningError(
        code=code,
        message=message,
        security_result="hardened process was not started",
        unsafe_reason="second-wall hardening is mandatory for affected startup",
        next_action="repair kernel hardening support and retry",
    )
