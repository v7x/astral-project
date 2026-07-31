"""XDG and private filesystem primitive tests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from astral_project.core import paths
from astral_project.core.errors import AstralError, ErrorCode


def test_xdg_paths_use_explicit_and_default_roots(tmp_path: Path) -> None:
    environment = {
        "HOME": str(tmp_path / "home"),
        "XDG_RUNTIME_DIR": str(tmp_path / "runtime"),
    }

    resolved = paths.resolve_xdg_paths(environment)

    assert resolved.config == tmp_path / "home" / ".config" / "astral-project"
    assert resolved.state == tmp_path / "home" / ".local" / "state" / "astral-project"
    assert resolved.runtime == tmp_path / "runtime" / "astral-project"


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        ({"XDG_RUNTIME_DIR": "/run/user/1"}, "HOME is required"),
        ({"HOME": "relative", "XDG_RUNTIME_DIR": "/run/user/1"}, "HOME must be an absolute path"),
        ({"HOME": "/home/user"}, "XDG_RUNTIME_DIR is required"),
        (
            {"HOME": "/home/user", "XDG_RUNTIME_DIR": "/run/user/1", "XDG_CONFIG_HOME": "relative"},
            "XDG_CONFIG_HOME must be an absolute path",
        ),
    ],
)
def test_xdg_paths_reject_unsafe_roots(environment: dict[str, str], message: str) -> None:
    with pytest.raises(AstralError) as error:
        paths.resolve_xdg_paths(environment)

    assert error.value.code is ErrorCode.CONFIG_INVALID_PATH
    assert error.value.message == message


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "a\\b", "nul\x00name"])
def test_safe_component_rejects_traversal(name: str) -> None:
    with pytest.raises(AstralError) as error:
        paths.safe_component(name)

    assert error.value.code is ErrorCode.PATH_INVALID_NAME


def test_safe_component_accepts_single_filename() -> None:
    assert paths.safe_component("profile_01") == "profile_01"


def test_private_directory_and_file_lifecycle(tmp_path: Path) -> None:
    private = paths.ensure_private_directory(tmp_path / "private")
    created = paths.create_private_file(private / "key", b"secret")

    assert created.read_bytes() == b"secret"
    assert created.stat().st_mode & 0o077 == 0
    paths.check_private_path(created)

    with pytest.raises(AstralError) as error:
        paths.create_private_file(created, b"replacement")
    assert error.value.code is ErrorCode.FILE_CREATE


@pytest.mark.parametrize("kind", ["wrong-owner", "loose-mode", "symlink", "regular-file"])
def test_private_path_rejects_unsafe_state(tmp_path: Path, kind: str) -> None:
    target = tmp_path / "state"
    if kind == "symlink":
        target.symlink_to(tmp_path)
        with pytest.raises(AstralError) as direct_error:
            paths.check_private_path(target)
        assert direct_error.value.code is ErrorCode.PERMISSION_INVALID_TYPE
    else:
        target.mkdir()
    if kind == "loose-mode":
        target.chmod(0o770)
    if kind == "regular-file":
        target.rmdir()
        target.write_text("not a directory", encoding="utf-8")

    with pytest.raises(AstralError) as error:
        if kind == "wrong-owner":
            paths.check_private_path(target, expected_uid=os.getuid() + 1)
        else:
            paths.ensure_private_directory(target)

    expected = {
        "wrong-owner": ErrorCode.PERMISSION_WRONG_OWNER,
        "loose-mode": ErrorCode.PERMISSION_INSECURE_MODE,
        "symlink": ErrorCode.PERMISSION_INVALID_TYPE,
        "regular-file": ErrorCode.PERMISSION_INVALID_TYPE,
    }
    assert error.value.code is expected[kind]


def test_write_all_handles_partial_writes_and_stops_on_no_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "content"
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    original_write = os.write
    calls = 0

    def partial_write(fd: int, content: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original_write(fd, content[:1])
        return original_write(fd, content)

    try:
        monkeypatch.setattr(os, "write", partial_write)
        paths._write_all(descriptor, b"abc")
    finally:
        os.close(descriptor)
    assert target.read_bytes() == b"abc"

    monkeypatch.setattr(os, "write", lambda fd, content: 0)
    with pytest.raises(OSError, match="no progress"):
        paths._write_all(-1, b"x")


def test_atomic_write_is_complete_or_leaves_original(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = paths.ensure_private_directory(tmp_path / "private")
    target = paths.create_private_file(private / "state", b"old")

    paths.atomic_write_private(target, b"new")
    assert target.read_bytes() == b"new"

    def failed_replace(source: Path, destination: Path) -> None:
        raise OSError("storage failure")

    monkeypatch.setattr(os, "replace", failed_replace)
    with pytest.raises(AstralError) as error:
        paths.atomic_write_private(target, b"partial")

    assert error.value.code is ErrorCode.FILE_ATOMIC_WRITE
    assert target.read_bytes() == b"new"
    assert list(private.glob(".state.*")) == []


def test_atomic_write_reports_temporary_file_creation_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = paths.ensure_private_directory(tmp_path / "private")

    def failed_mkstemp(*args: object, **kwargs: object) -> tuple[int, str]:
        raise OSError("no space")

    monkeypatch.setattr(tempfile, "mkstemp", failed_mkstemp)
    with pytest.raises(AstralError) as error:
        paths.atomic_write_private(private / "state", b"new")

    assert error.value.code is ErrorCode.FILE_ATOMIC_WRITE


def test_atomic_write_closes_descriptor_after_fsync_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = paths.ensure_private_directory(tmp_path / "private")
    target = paths.create_private_file(private / "state", b"old")

    monkeypatch.setattr(os, "fsync", lambda descriptor: (_ for _ in ()).throw(OSError("full")))
    with pytest.raises(AstralError) as error:
        paths.atomic_write_private(target, b"new")

    assert error.value.code is ErrorCode.FILE_ATOMIC_WRITE
    assert target.read_bytes() == b"old"
