"""Packet 38 process-hardening tests."""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import resource
from pathlib import Path

import pytest

from astral_project.core.errors import ErrorCode
from astral_project.sandbox import hardening
from astral_project.sandbox.hardening import (
    LANDLOCK_HANDLED_ACCESS_FS,
    LANDLOCK_MINIMUM_ABI,
    HardeningPolicy,
    HardeningStatus,
    RootRole,
    enforce,
    require_available,
)


def test_detect_landlock_reports_abi_and_supported_errors() -> None:
    assert hardening.detect_landlock(lambda *_args: 7) == 7
    original_errno = ctypes.get_errno()
    try:
        for value in (errno.ENOSYS, errno.EOPNOTSUPP, errno.EINVAL):
            ctypes.set_errno(value)
            assert hardening.detect_landlock(lambda *_args: -1) is None
        ctypes.set_errno(errno.EPERM)
        with pytest.raises(OSError):
            hardening.detect_landlock(lambda *_args: -1)
    finally:
        ctypes.set_errno(original_errno)


def test_policy_validation_and_plan_roots(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    policy = HardeningPolicy.for_plan(((root, True), (root, False)))
    assert dict(policy.allowed_roots)[root] is RootRole.REGULAR_WRITABLE
    readonly_tmp = HardeningPolicy.for_plan(((Path("/tmp"), False),), writable_tmp=False)
    assert dict(readonly_tmp.allowed_roots)[Path("/tmp")] is RootRole.READ_ONLY
    nested_tmp = tmp_path / "nested-tmp"
    nested_tmp.mkdir()
    nested_policy = HardeningPolicy.for_plan(((nested_tmp, False),), writable_tmp=False)
    assert dict(nested_policy.allowed_roots)[Path("/tmp")] is RootRole.READ_ONLY
    with pytest.raises(ValueError):
        HardeningPolicy.for_plan((), writable_tmp="yes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        HardeningPolicy(required="yes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        HardeningPolicy(max_open_files=1)
    with pytest.raises(ValueError):
        HardeningPolicy(max_processes=0)
    with pytest.raises(ValueError):
        HardeningPolicy(allowed_roots=((tmp_path / "missing", RootRole.READ_ONLY),))
    with pytest.raises(ValueError):
        HardeningPolicy(allowed_roots=((root, "yes"),))  # type: ignore[arg-type]


def test_root_role_rejects_invalid_direct_value() -> None:
    assert hardening._root_role(RootRole.READ_ONLY) is RootRole.READ_ONLY
    with pytest.raises(ValueError, match="root role"):
        hardening._root_role("invalid")  # type: ignore[arg-type]


def test_root_role_merge_preserves_strongest_fixed_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert (
        hardening._stronger_role(RootRole.READ_ONLY, RootRole.REGULAR_WRITABLE)
        is RootRole.REGULAR_WRITABLE
    )
    with pytest.raises(ValueError, match="conflicting"):
        hardening._stronger_role(RootRole.DEVICE_RUNTIME, RootRole.SOCKET_RUNTIME)
    monkeypatch.setattr(
        hardening,
        "_access_for_role",
        lambda role: 1 if role is RootRole.READ_ONLY else 2,
    )
    with pytest.raises(ValueError, match="conflicting"):
        hardening._stronger_role(RootRole.READ_ONLY, RootRole.REGULAR_WRITABLE)


def test_require_available_fails_closed_and_reports_abi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hardening, "detect_landlock", lambda: 4)
    assert require_available(HardeningPolicy(required=True)) == 4
    monkeypatch.setattr(hardening, "detect_landlock", lambda: 2)
    with pytest.raises(hardening.HardeningError, match="below required"):
        require_available(HardeningPolicy(required=True))
    assert require_available(HardeningPolicy(required=False)) == 2
    monkeypatch.setattr(
        hardening,
        "detect_landlock",
        lambda: (_ for _ in ()).throw(OSError("probe")),
    )
    assert require_available(HardeningPolicy(required=False)) == 0
    monkeypatch.setattr(
        hardening,
        "detect_landlock",
        lambda: (_ for _ in ()).throw(OSError("probe")),
    )
    with pytest.raises(hardening.HardeningError, match="probe"):
        require_available(HardeningPolicy(required=True))
    monkeypatch.setattr(hardening, "detect_landlock", lambda: None)
    assert require_available(HardeningPolicy(required=False)) == 0
    with pytest.raises(hardening.HardeningError):
        require_available(HardeningPolicy(required=True))


def test_enforce_converts_probe_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        hardening, "detect_landlock", lambda: (_ for _ in ()).throw(OSError("probe"))
    )
    with pytest.raises(hardening.HardeningError, match="probe") as error:
        enforce(HardeningPolicy(required=True))
    assert error.value.code is ErrorCode.HARDENING_UNAVAILABLE
    optional = enforce(HardeningPolicy(required=False))
    assert optional.reason.startswith("Landlock probe failed")


def test_enforce_fails_closed_or_reports_optional_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hardening, "detect_landlock", lambda: 2)
    with pytest.raises(hardening.HardeningError) as error:
        enforce(HardeningPolicy(required=True))
    assert error.value.code is ErrorCode.HARDENING_UNAVAILABLE
    status = enforce(HardeningPolicy(required=False))
    assert "below required" in status.reason
    monkeypatch.setattr(hardening, "detect_landlock", lambda: None)
    with pytest.raises(hardening.HardeningError) as error:
        enforce(HardeningPolicy(required=True))
    assert error.value.code is ErrorCode.HARDENING_UNAVAILABLE
    status = enforce(HardeningPolicy(required=False))
    assert status == HardeningStatus(False, None, False, False, "Landlock unavailable")


def test_python_native_landlock_rights_parity() -> None:
    native = Path("packaging/native/aspr-hardening.h").read_text(encoding="utf-8")
    names = (
        "EXECUTE",
        "WRITE_FILE",
        "READ_FILE",
        "READ_DIR",
        "REMOVE_DIR",
        "REMOVE_FILE",
        "MAKE_CHAR",
        "MAKE_DIR",
        "MAKE_REG",
        "MAKE_SOCK",
        "MAKE_FIFO",
        "MAKE_BLOCK",
        "MAKE_SYM",
        "REFER",
        "TRUNCATE",
    )
    for bit, name in enumerate(names):
        assert getattr(hardening, f"LANDLOCK_ACCESS_FS_{name}") == 1 << bit
        assert f"ASPR_LANDLOCK_ACCESS_FS_{name} (1ULL << {bit})" in native
    assert f"ASPR_LANDLOCK_MINIMUM_ABI {LANDLOCK_MINIMUM_ABI}" in native
    assert "ASPR_PR_CAPBSET_READ 23" in native
    assert "aspr_capability_bounding_state" in native


def test_landlock_contract_and_root_roles() -> None:
    fixed = dict(HardeningPolicy.for_plan((), writable_tmp=True).allowed_roots)
    assert fixed[Path("/dev")] is RootRole.DEVICE_RUNTIME
    assert fixed[Path("/run")] is RootRole.SOCKET_RUNTIME
    assert LANDLOCK_MINIMUM_ABI == 3
    assert LANDLOCK_HANDLED_ACCESS_FS == (1 << 15) - 1
    assert hardening._access_for_role(RootRole.READ_ONLY) & ~hardening._READ_ACCESS == 0
    assert (
        hardening._access_for_role(RootRole.REGULAR_WRITABLE)
        & hardening.LANDLOCK_ACCESS_FS_MAKE_SOCK
        == 0
    )
    socket_access = hardening._access_for_role(RootRole.SOCKET_RUNTIME)
    assert socket_access == (hardening._READ_ACCESS | hardening.LANDLOCK_ACCESS_FS_MAKE_SOCK)
    assert (
        socket_access
        & (
            hardening.LANDLOCK_ACCESS_FS_WRITE_FILE
            | hardening.LANDLOCK_ACCESS_FS_REMOVE_DIR
            | hardening.LANDLOCK_ACCESS_FS_REMOVE_FILE
            | hardening.LANDLOCK_ACCESS_FS_MAKE_DIR
            | hardening.LANDLOCK_ACCESS_FS_MAKE_REG
            | hardening.LANDLOCK_ACCESS_FS_MAKE_SYM
            | hardening.LANDLOCK_ACCESS_FS_REFER
            | hardening.LANDLOCK_ACCESS_FS_TRUNCATE
        )
        == 0
    )
    assert (
        hardening._access_for_role(RootRole.DEVICE_RUNTIME)
        & hardening.LANDLOCK_ACCESS_FS_WRITE_FILE
    )


def test_enforce_applies_all_controls(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[str] = []
    monkeypatch.setattr(hardening, "detect_landlock", lambda: 4)
    monkeypatch.setattr(hardening, "_set_no_new_privs", lambda: calls.append("nnp"))
    monkeypatch.setattr(hardening, "_set_limits", lambda *_args: calls.append("limits"))
    monkeypatch.setattr(hardening, "_disable_core_dumps", lambda: calls.append("core"))
    monkeypatch.setattr(hardening, "_drop_capability_bounding_set", lambda: calls.append("caps"))
    monkeypatch.setattr(hardening, "_restrict_paths", lambda *_args: calls.append("landlock"))
    root = tmp_path / "root"
    root.mkdir()
    status = enforce(HardeningPolicy(allowed_roots=((root, False),)))
    assert status.enforced is True
    assert calls == ["nnp", "limits", "core", "caps", "landlock"]


def test_enforce_converts_application_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hardening, "detect_landlock", lambda: 3)

    def fail_no_new_privs() -> None:
        raise OSError("no")

    monkeypatch.setattr(hardening, "_set_no_new_privs", fail_no_new_privs)
    with pytest.raises(hardening.HardeningError) as error:
        enforce(HardeningPolicy(allowed_roots=((Path("/usr"), False),)))
    assert error.value.code is ErrorCode.HARDENING_APPLY


def test_capability_bounding_state_handles_unsupported_rights() -> None:
    def unsupported(*_args: object) -> int:
        ctypes.set_errno(errno.EINVAL)
        return -1

    assert hardening._capability_bounding_state(unsupported, 63) == 0


def test_process_controls_and_landlock_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, ...]] = []

    def successful_call(*args: object) -> int:
        calls.append(args)
        return 0

    def record_limits(*args: object) -> None:
        calls.append(args)

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: successful_call)
    monkeypatch.setattr(resource, "setrlimit", record_limits)
    hardening._set_no_new_privs()
    hardening._set_limits(100, 10)
    hardening._disable_core_dumps()
    hardening._drop_capability_bounding_set()
    assert len(calls) >= 67

    def drop_success(*args: object) -> int:
        return 1 if args[1] == hardening._PR_CAPBSET_READ and args[2] == 0 else 0

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: drop_success)
    hardening._drop_capability_bounding_set()

    def failing_call(*_args: object) -> int:
        ctypes.set_errno(errno.EIO)
        return -1

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: failing_call)
    with pytest.raises(OSError):
        hardening._set_no_new_privs()
    with pytest.raises(OSError):
        hardening._drop_capability_bounding_set()


def test_capability_drop_accepts_only_proven_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    states = {0: [1, 0]}

    def denied_call(_syscall: int, operation: int, capability: int, *_args: object) -> int:
        if operation == hardening._PR_CAPBSET_READ:
            if capability == 0:
                return states[0].pop(0)
            return 0
        if operation == hardening._PR_CAPBSET_DROP:
            ctypes.set_errno(errno.EPERM)
            return -1
        raise AssertionError(operation)

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: denied_call)
    hardening._drop_capability_bounding_set()

    def still_present(_syscall: int, operation: int, capability: int, *_args: object) -> int:
        if operation == hardening._PR_CAPBSET_READ:
            return 1 if capability == 0 else 0
        ctypes.set_errno(errno.EPERM)
        return -1

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: still_present)
    with pytest.raises(OSError, match="Operation not permitted"):
        hardening._drop_capability_bounding_set()


def test_clear_process_capabilities_handles_success_and_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    def successful_call(*args: object) -> int:
        calls.append(args)
        return 0

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: successful_call)
    hardening.clear_process_capabilities()
    assert calls[0][1:] == (hardening._PR_CAP_AMBIENT, hardening._PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)
    assert calls[1][0] == hardening._SYS_CAPSET

    def ambient_failure(*_args: object) -> int:
        ctypes.set_errno(errno.EIO)
        return -1

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: ambient_failure)
    with pytest.raises(OSError, match="Input/output error"):
        hardening.clear_process_capabilities()

    def capset_failure(*args: object) -> int:
        if args[0] == hardening._SYS_CAPSET:
            ctypes.set_errno(errno.EIO)
            return -1
        return 0

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: capset_failure)
    with pytest.raises(OSError, match="Input/output error"):
        hardening.clear_process_capabilities()


def test_restrict_paths_success_and_failures(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "root"
    root.mkdir()
    calls: list[int] = []

    def successful_call(number: int, *_args: object) -> int:
        calls.append(number)
        return 10 if number == 444 else 0

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: successful_call)
    monkeypatch.setattr(hardening, "_set_no_new_privs", lambda: None)
    monkeypatch.setattr(os, "open", lambda *_args: 11)
    monkeypatch.setattr(os, "close", lambda *_args: None)
    hardening._restrict_paths(((root, False), (root, True)))
    assert calls == [444, 445, 445, 446]
    with pytest.raises(ValueError):
        hardening._restrict_paths(())

    def create_failure(number: int, *_args: object) -> int:
        if number == 444:
            ctypes.set_errno(errno.EIO)
            return -1
        return 0

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: create_failure)
    with pytest.raises(OSError):
        hardening._restrict_paths(((root, False),))

    def add_failure(number: int, *_args: object) -> int:
        if number == 444:
            return 10
        ctypes.set_errno(errno.EIO)
        return -1

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: add_failure)
    with pytest.raises(OSError):
        hardening._restrict_paths(((root, False),))

    def restrict_failure(number: int, *_args: object) -> int:
        if number == 444:
            return 10
        if number == 446:
            ctypes.set_errno(errno.EIO)
            return -1
        return 0

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: restrict_failure)
    with pytest.raises(OSError):
        hardening._restrict_paths(((root, False),))


def test_non_linux_landlock_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    with pytest.raises(OSError, match="Linux"):
        hardening._libc_syscall()


def test_status_and_dependency_report(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hardening, "detect_landlock", lambda: 3)
    assert hardening.status(required=False).to_dict()["landlock_abi"] == 3
    assert hardening.status(required=False).to_dict()["landlock_required_abi"] == 3
    monkeypatch.setattr(hardening, "detect_landlock", lambda: None)
    assert hardening.status().reason == "Landlock unavailable"
    monkeypatch.setattr(hardening, "detect_landlock", lambda: 2)
    assert "below required" in hardening.status().reason
    monkeypatch.setattr(
        hardening,
        "detect_landlock",
        lambda: (_ for _ in ()).throw(OSError("probe")),
    )
    assert "probe" in hardening.status().reason
    versions = hardening.dependency_versions(("cbor2", "package-does-not-exist"))
    assert versions["cbor2"]
    assert versions["package-does-not-exist"] == "unavailable"


def test_secure_temp_directory_is_private(tmp_path: Path) -> None:
    directory = hardening.secure_temp_directory(tmp_path, prefix="test-")
    assert directory.is_dir()
    assert directory.stat().st_mode & 0o777 == 0o700
    nested = hardening.secure_temp_directory(tmp_path / "missing")
    assert nested.is_dir()
    assert (tmp_path / "missing").stat().st_mode & 0o777 == 0o700


def test_status_to_dict() -> None:
    status = HardeningStatus(True, 3, True, False, "available")
    assert status.to_dict() == {
        "landlock_abi": 3,
        "landlock_available": True,
        "landlock_required_abi": 3,
        "required": True,
        "enforced": False,
        "reason": "available",
    }
