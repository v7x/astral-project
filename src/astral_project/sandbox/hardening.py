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
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import ensure_private_directory

_LANDLOCK_CREATE_RULESET = 444
_LANDLOCK_ADD_RULE = 445
_LANDLOCK_RESTRICT_SELF = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_TYPE_PATH_BENEATH = 1
_PR_SET_NO_NEW_PRIVS = 38
_PR_CAPBSET_DROP = 24
_MAX_CAPABILITY = 63
_READ_ACCESS = (1 << 2) | (1 << 3) | (1 << 0)
_WRITE_ACCESS = _READ_ACCESS | (1 << 1) | (1 << 7) | (1 << 8) | (1 << 5) | (1 << 4)


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

    def to_dict(self) -> dict[str, object]:
        return {
            "landlock_abi": self.abi,
            "landlock_available": self.landlock_available,
            "required": self.required,
            "enforced": self.enforced,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class HardeningPolicy:
    """Execution policy for one sandbox child."""

    required: bool = True
    allowed_roots: tuple[tuple[Path, bool], ...] = ()
    max_open_files: int = 1024
    max_processes: int = 128

    def __post_init__(self) -> None:
        if not isinstance(self.required, bool):
            raise ValueError("hardening required flag is invalid")
        if self.max_open_files < 64 or self.max_processes < 1:
            raise ValueError("hardening rlimits are invalid")
        for path, writable in self.allowed_roots:
            if not isinstance(path, Path) or not path.is_absolute() or not path.exists():
                raise ValueError("hardening root is unavailable")
            if not isinstance(writable, bool):
                raise ValueError("hardening root mutability is invalid")

    @classmethod
    def for_plan(
        cls, roots: Sequence[tuple[Path, bool]], *, writable_tmp: bool = True
    ) -> HardeningPolicy:
        """Build policy with fixed system roots plus exact plan-owned roots."""
        if not isinstance(writable_tmp, bool):
            raise ValueError("hardening temporary-root mutability is invalid")
        fixed = tuple(
            (Path(path), path == "/tmp" and writable_tmp)
            for path in ("/usr", "/dev", "/proc", "/run", "/tmp")
            if Path(path).exists()
        )
        unique: dict[Path, bool] = {path: writable for path, writable in fixed}
        for path, writable in roots:
            unique[path] = unique.get(path, False) or writable
        return cls(allowed_roots=tuple(unique.items()))


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
    """Fail before launch when the required Landlock ABI is unavailable."""
    abi = detect_landlock()
    if abi is None and policy.required:
        raise _hardening_error("Landlock ABI is unavailable")
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


def _restrict_paths(roots: Sequence[tuple[Path, bool]]) -> None:
    if not roots:
        raise ValueError("Landlock requires at least one allowed root")
    handled = _WRITE_ACCESS
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
            rule = _PathBeneath(
                parent_fd=descriptor,
                allowed_access=_WRITE_ACCESS if writable else _READ_ACCESS,
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
