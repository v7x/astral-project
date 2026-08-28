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
    HardeningPolicy,
    HardeningStatus,
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
    assert dict(policy.allowed_roots)[root] is True
    with pytest.raises(ValueError):
        HardeningPolicy(required="yes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        HardeningPolicy(max_open_files=1)
    with pytest.raises(ValueError):
        HardeningPolicy(max_processes=0)
    with pytest.raises(ValueError):
        HardeningPolicy(allowed_roots=((tmp_path / "missing", False),))
    with pytest.raises(ValueError):
        HardeningPolicy(allowed_roots=((root, "yes"),))  # type: ignore[arg-type]


def test_require_available_fails_closed_and_reports_abi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hardening, "detect_landlock", lambda: 4)
    assert require_available(HardeningPolicy(required=True)) == 4
    monkeypatch.setattr(hardening, "detect_landlock", lambda: None)
    assert require_available(HardeningPolicy(required=False)) == 0
    with pytest.raises(hardening.HardeningError):
        require_available(HardeningPolicy(required=True))


def test_enforce_fails_closed_or_reports_optional_absence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(hardening, "detect_landlock", lambda: None)
    with pytest.raises(hardening.HardeningError) as error:
        enforce(HardeningPolicy(required=True))
    assert error.value.code is ErrorCode.HARDENING_UNAVAILABLE
    status = enforce(HardeningPolicy(required=False))
    assert status == HardeningStatus(False, None, False, False, "Landlock unavailable")


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
    monkeypatch.setattr(hardening, "detect_landlock", lambda: 1)

    def fail_no_new_privs() -> None:
        raise OSError("no")

    monkeypatch.setattr(hardening, "_set_no_new_privs", fail_no_new_privs)
    with pytest.raises(hardening.HardeningError) as error:
        enforce(HardeningPolicy(allowed_roots=((Path("/usr"), False),)))
    assert error.value.code is ErrorCode.HARDENING_APPLY


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

    def failing_call(*_args: object) -> int:
        ctypes.set_errno(errno.EIO)
        return -1

    monkeypatch.setattr(hardening, "_libc_syscall", lambda: failing_call)
    with pytest.raises(OSError):
        hardening._set_no_new_privs()
    with pytest.raises(OSError):
        hardening._drop_capability_bounding_set()


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
    monkeypatch.setattr(hardening, "detect_landlock", lambda: None)
    assert hardening.status().reason == "Landlock unavailable"
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
    status = HardeningStatus(True, 1, True, False, "available")
    assert status.to_dict() == {
        "landlock_abi": 1,
        "landlock_available": True,
        "required": True,
        "enforced": False,
        "reason": "available",
    }
