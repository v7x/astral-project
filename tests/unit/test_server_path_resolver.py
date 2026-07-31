"""Packet 12 descriptor-pinned remote path resolver tests."""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import ExportKind
from astral_project.server import linux
from astral_project.server.path_resolver import (
    MountTopology,
    TrustedRoot,
    _filesystem_name,
    _parse_mountinfo,
    _relative_to_root,
    resolve_source,
)


def test_resolve_regular_file_returns_pinned_descriptor(tmp_path: Path) -> None:
    source = tmp_path / "root" / "project" / "file.txt"
    source.parent.mkdir(parents=True)
    source.write_text("before", encoding="utf-8")

    with (
        TrustedRoot.open(str(tmp_path / "root")) as root,
        resolve_source(root, str(source)) as resolved,
    ):
        source.unlink()
        assert resolved.canonical_path == str(source)
        assert resolved.identity.kind is ExportKind.FILE
        assert resolved.identity.inode == os.fstat(resolved.descriptor).st_ino
        assert os.fstat(resolved.descriptor).st_nlink == 0


def test_resolve_directory_reports_identity_and_mount_topology(tmp_path: Path) -> None:
    source = tmp_path / "root" / "project"
    source.mkdir(parents=True)

    with (
        TrustedRoot.open(str(tmp_path / "root")) as root,
        resolve_source(root, str(source)) as resolved,
    ):
        assert resolved.identity.kind is ExportKind.DIRECTORY
        assert resolved.identity.mount_id > 0
        assert resolved.identity.filesystem_type
        assert isinstance(resolved.nested_mounts, tuple)


@pytest.mark.parametrize(
    "path",
    ["relative", "/root/../escape", "/root/./file", "/root//file", "/root/\x00file", "/"],
)
def test_invalid_source_paths_fail_before_resolution(tmp_path: Path, path: str) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    with TrustedRoot.open(str(root_path)) as root, pytest.raises(AstralError) as error:
        resolve_source(root, path)
    assert error.value.code is ErrorCode.PATH_RESOLUTION


def test_source_outside_trusted_root_fails(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("no", encoding="utf-8")
    with TrustedRoot.open(str(root_path)) as root, pytest.raises(AstralError) as error:
        resolve_source(root, str(outside))
    assert error.value.code is ErrorCode.PATH_RESOLUTION


@pytest.mark.parametrize("target", ["/etc/passwd", "../outside"])
def test_symlink_escape_fails(tmp_path: Path, target: str) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    (root_path / "outside").write_text("outside", encoding="utf-8")
    link = root_path / "link"
    link.symlink_to(target)
    with TrustedRoot.open(str(root_path)) as root, pytest.raises(AstralError) as error:
        resolve_source(root, str(link))
    assert error.value.code is ErrorCode.PATH_RESOLUTION


def test_symlink_loop_fails(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    (root_path / "first").symlink_to("second")
    (root_path / "second").symlink_to("first")
    with TrustedRoot.open(str(root_path)) as root, pytest.raises(AstralError):
        resolve_source(root, str(root_path / "first"))


def test_proc_magic_link_fails() -> None:
    with TrustedRoot.open("/proc") as root, pytest.raises(AstralError) as error:
        resolve_source(root, "/proc/self/fd/0")
    assert error.value.code is ErrorCode.PATH_RESOLUTION


def test_autofs_is_explicit_strict_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "root" / "project"
    source.mkdir(parents=True)
    monkeypatch.setattr(linux, "filesystem_magic", lambda _: 0x0187)
    with TrustedRoot.open(str(tmp_path / "root")) as root, pytest.raises(AstralError) as error:
        resolve_source(root, str(source))
    assert error.value.code is ErrorCode.PATH_AUTOFS


def test_rename_race_never_returns_reopened_attacker_object(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    safe = root_path / "safe"
    replacement = root_path / "replacement"
    safe.write_text("safe", encoding="utf-8")
    replacement.write_text("replacement", encoding="utf-8")
    stop = threading.Event()

    def swap() -> None:
        while not stop.is_set():
            try:
                os.replace(replacement, safe)
                safe.write_text("replacement", encoding="utf-8")
                os.replace(safe, replacement)
                replacement.write_text("replacement", encoding="utf-8")
                safe.write_text("safe", encoding="utf-8")
            except FileNotFoundError:
                continue

    thread = threading.Thread(target=swap)
    thread.start()
    try:
        with TrustedRoot.open(str(root_path)) as root:
            for _ in range(50):
                try:
                    with resolve_source(root, str(safe)) as resolved:
                        assert resolved.identity.kind is ExportKind.FILE
                        assert os.fstat(resolved.descriptor).st_ino == resolved.identity.inode
                except AstralError:
                    pass
    finally:
        stop.set()
        thread.join()


def test_mountinfo_parse_and_filesystem_labels() -> None:
    parsed = _parse_mountinfo("35 25 0:31 / /srv/project\\040name rw,nosuid - nfs4 host:/export rw")
    assert parsed == MountTopology(35, 25, "/srv/project name", "nfs4")
    assert _parse_mountinfo("malformed") is None
    assert _filesystem_name(0x00006969) == "nfs"
    assert _filesystem_name(0xDEADBEEF) == "magic:0xdeadbeef"


def test_exact_trusted_root_and_relative_path_rules(tmp_path: Path) -> None:
    root_path = tmp_path / "root"
    root_path.mkdir()
    with TrustedRoot.open(str(root_path)) as root, resolve_source(root, str(root_path)) as resolved:
        assert resolved.canonical_path == str(root_path)
        assert resolved.identity.kind is ExportKind.DIRECTORY
    assert _relative_to_root("/", "/project") == "project"
