from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from astral_project.homed.composite import CompositeProjectedHome
from astral_project.homed.host import HostReadonlyView
from astral_project.homed.overlay import OverlayBackend
from astral_project.homed.private import PrivateWritableBackend
from astral_project.profile import Operation, Profile, Rule, RuleMode, RuleScope


def _profile() -> Profile:
    return Profile(
        1,
        "p",
        "p",
        rules=(
            Rule("host.txt", RuleScope.EXACT, RuleMode.HOST_RO),
            Rule("host-dir", RuleScope.SUBTREE, RuleMode.HOST_RO, list_allowed=True),
            Rule("private", RuleScope.SUBTREE, RuleMode.PRIVATE_RW, list_allowed=True),
            Rule("overlay", RuleScope.SUBTREE, RuleMode.OVERLAY_RW, list_allowed=True),
        ),
    )


def _home(tmp_path: Path) -> CompositeProjectedHome:
    root = tmp_path / "home"
    root.mkdir()
    (root / "host.txt").write_bytes(b"host")
    (root / "host-dir").mkdir()
    profile = _profile()
    return CompositeProjectedHome(
        profile,
        host=HostReadonlyView(root, profile),
        private=PrivateWritableBackend(tmp_path / "private", profile),
        overlay=OverlayBackend(root, tmp_path / "overlay", profile),
    )


def test_composite_routes_disjoint_roots_through_one_public_namespace(tmp_path: Path) -> None:
    home = _home(tmp_path)
    try:
        host_node = home.lookup("host.txt")
        host_handle = home.open("host.txt")
        assert home.read(host_handle) == b"host"
        assert host_node.inode != host_handle

        private_root = home.lookup("private")
        assert private_root.is_directory
        private_node = home.create("private/state.txt")
        private_handle = home.open("private/state.txt", os.O_RDWR)
        assert home.write(private_handle, b"private") == len(b"private")
        assert home.read(private_handle, 0) == b"private"
        assert private_node.inode not in {host_node.inode, private_root.inode}

        overlay_root = home.lookup("overlay")
        assert overlay_root.is_directory
        overlay_node = home.create("overlay/state.txt")
        overlay_handle = home.open("overlay/state.txt", os.O_RDWR)
        assert home.write(overlay_handle, b"overlay") == len(b"overlay")
        assert home.read(overlay_handle, 0) == b"overlay"
        assert overlay_node.inode not in {host_node.inode, private_root.inode, private_node.inode}

        with pytest.raises(OSError) as error:
            home.listdir(".")
        assert error.value.errno == errno.EACCES
        assert home.listdir("private") == ("state.txt",)
        assert home.listdir("overlay") == ("state.txt",)
        with pytest.raises(OSError) as error:
            home.rename("private/state.txt", "overlay/state.txt")
        assert error.value.errno == errno.EXDEV

        for handle in (host_handle, private_handle, overlay_handle):
            home.release(handle)
        home.forget(private_node.inode, 1)
        assert home.inode_count >= 1
    finally:
        home.close()


def test_composite_enforces_handles_mutation_and_close_boundaries(tmp_path: Path) -> None:
    home = _home(tmp_path)
    try:
        assert home.lookup(".").inode == 1
        assert home.stat(".").inode == 1
        assert home.stat("private").is_directory
        assert home.listdir("private") == ()
        assert home.max_bytes == 64 * 1024 * 1024
        assert home.max_files == 16_384
        assert home.used_bytes == home.file_count == 0
        assert home.node_path(1) == "."
        with pytest.raises(OSError) as error:
            home.node_path(99)
        assert error.value.errno == errno.ENOENT
        with pytest.raises(OSError) as error:
            home.stat("private/missing")
        assert error.value.errno == errno.ENOENT
        with pytest.raises(OSError) as error:
            home.listdir("private/missing")
        assert error.value.errno == errno.ENOENT

        host_handle = home.open("host.txt")
        with pytest.raises(OSError) as error:
            home.open("host-dir")
        assert error.value.errno == errno.EISDIR
        home.fsync(host_handle)
        for operation in (
            lambda: home.write(host_handle, b"denied"),
            lambda: home.truncate(host_handle, 0),
            lambda: home.chmod(host_handle, 0o700),
        ):
            with pytest.raises(OSError) as error:
                operation()
            assert error.value.errno == errno.EROFS
        with pytest.raises(OSError) as error:
            home.open("host.txt", os.O_WRONLY)
        assert error.value.errno == errno.EACCES
        home.release(host_handle)
        home.release(host_handle)
        with pytest.raises(OSError) as error:
            home.read(host_handle)
        assert error.value.errno == errno.EBADF

        made = home.mkdir("private/nested")
        created = home.create("private/nested/file")
        opened = home.open("private/opened", os.O_CREAT | os.O_RDWR)
        assert home.write(opened, b"open") == 4
        home.release(opened)
        truncated = home.open("private/opened", os.O_RDWR | os.O_TRUNC)
        assert home.read(truncated) == b""
        home.release(truncated)
        handle = home.open("private/nested/file", os.O_RDWR)
        assert home.write(handle, b"one") == 3
        home.truncate(handle, 2)
        home.chmod(handle, 0o777)
        home.fsync(handle)
        home.release(handle)
        created_again = home.lookup("private/nested/file")
        home.forget(created_again.inode, 1)
        home.rename("private/nested/file", "private/nested/renamed")
        home.unlink("private/nested/renamed")
        home.unlink("private/nested", directory=True)
        home.forget(made.inode, 1)
        home.forget(created.inode, 1)
        virtual = home.lookup("overlay")
        assert home.lookup("overlay").inode == virtual.inode
        home.forget(virtual.inode, 2)
        home.forget(1, 1)
        home.forget(999, 1)
        home.forget(999, -1)

        with pytest.raises(OSError) as error:
            home.create("host.txt")
        assert error.value.errno == errno.EACCES
        with pytest.raises(OSError) as error:
            home.lookup("unknown")
        assert error.value.errno == errno.EACCES
    finally:
        home.close()
    home.close()
    with pytest.raises(OSError) as error:
        home.lookup("host.txt")
    assert error.value.errno == errno.ESTALE


def test_composite_missing_backings_and_virtual_ancestors_fail_closed(tmp_path: Path) -> None:
    profile = Profile(
        1,
        "p",
        "p",
        rules=(Rule("private/deep", RuleScope.SUBTREE, RuleMode.PRIVATE_RW),),
    )
    home = CompositeProjectedHome(profile)
    assert home.max_bytes == (1 << 63) - 1
    assert home.max_files == (1 << 31) - 1
    assert home.used_bytes == home.file_count == 0
    with pytest.raises(OSError) as error:
        home.listdir(".")
    assert error.value.errno == errno.EACCES
    with pytest.raises(OSError) as error:
        home.listdir("private")
    assert error.value.errno == errno.EACCES
    assert home.lookup("private").is_directory
    assert home.stat("private").is_directory
    with pytest.raises(OSError) as error:
        _missing_host = home.host_required
    assert error.value.errno == errno.EACCES
    assert not home._is_synthetic_ancestor(".")
    with pytest.raises(OSError) as error:
        home._route("private", Operation.LOOKUP)
    assert error.value.errno == errno.EACCES
    with pytest.raises(OSError) as error:
        home._route("private/deep", Operation.CREATE)
    assert error.value.errno == errno.EACCES
    with pytest.raises(OSError) as error:
        home._backend("private")
    assert error.value.errno == errno.ESTALE
    home.close()


def test_composite_internal_backend_guards_and_parent_failure(tmp_path: Path) -> None:
    home = _home(tmp_path)
    try:
        assert home._backend("host") is home.host
        assert home._backend("private") is home.private
        assert home._backend("overlay") is home.overlay
        with HostReadonlyView(tmp_path / "home", _profile()) as unrelated:
            with pytest.raises(OSError) as error:
                home._backend_name(unrelated)
            assert error.value.errno == errno.EIO
            with pytest.raises(OSError) as error:
                home._writable(unrelated)
            assert error.value.errno == errno.EROFS
    finally:
        home.close()

    nested_profile = Profile(
        1,
        "nested",
        "nested",
        rules=(Rule("private/deep", RuleScope.SUBTREE, RuleMode.PRIVATE_RW),),
    )
    private = PrivateWritableBackend(tmp_path / "nested-private", nested_profile)
    nested = CompositeProjectedHome(nested_profile, private=private)
    try:
        created = nested.create("private/deep/file")
        assert created.is_directory is False
        handle = nested.open("private/deep/file", os.O_RDWR)
        assert nested.write(handle, b"nested") == len(b"nested")
        assert nested.read(handle, 0) == b"nested"
        nested.release(handle)
        with pytest.raises(OSError) as error:
            nested.listdir("private")
        assert error.value.errno == errno.EACCES
    finally:
        nested.close()

    closing_root = tmp_path / "closing"
    closing_root.mkdir()
    closing = _home(closing_root)
    handle = closing.open("host.txt")
    closing.close()
    with pytest.raises(OSError) as error:
        closing.read(handle)
    assert error.value.errno == errno.EBADF


def test_composite_synthetic_ancestors_are_not_backing_or_listing_authority(
    tmp_path: Path,
) -> None:
    root = tmp_path / "home"
    (root / ".config" / "tool").mkdir(parents=True)
    (root / ".config" / "tool" / "config.toml").write_bytes(b"config")
    (root / ".config" / "tool" / "sibling.txt").write_bytes(b"sibling")
    (root / ".config" / "other.txt").write_bytes(b"other")
    profile = Profile(
        1,
        "nested",
        "nested",
        rules=(
            Rule(".config/tool/config.toml", RuleScope.EXACT, RuleMode.HOST_RO),
            Rule("private/deep", RuleScope.SUBTREE, RuleMode.PRIVATE_RW),
            Rule("overlay/deep", RuleScope.SUBTREE, RuleMode.OVERLAY_RW),
        ),
    )
    private = PrivateWritableBackend(tmp_path / "private", profile)
    overlay = OverlayBackend(root, tmp_path / "overlay", profile)
    home = CompositeProjectedHome(
        profile, host=HostReadonlyView(root, profile), private=private, overlay=overlay
    )
    try:
        config_parent = home.lookup(".config")
        config_tool = home.stat(".config/tool")
        assert config_parent.is_directory and config_tool.is_directory
        assert home._nodes[config_parent.inode].backend is None
        assert home._nodes[config_tool.inode].backend is None
        config_handle = home.open(".config/tool/config.toml")
        assert home.read(config_handle) == b"config"
        home.release(config_handle)

        for path in (".", ".config", ".config/tool", "private", "overlay"):
            with pytest.raises(OSError) as error:
                home.listdir(path)
            assert error.value.errno == errno.EACCES
        with pytest.raises(OSError) as error:
            home.lookup(".config/tool/sibling.txt")
        assert error.value.errno == errno.EACCES

        private_parent = home.lookup("private")
        assert private_parent.is_directory
        private_file = home.create("private/deep/file")
        private_handle = home.open("private/deep/file", os.O_RDWR)
        assert not private_file.is_directory
        assert home.write(private_handle, b"private") == len(b"private")
        assert home.read(private_handle, 0) == b"private"
        home.release(private_handle)

        overlay_parent = home.lookup("overlay")
        assert overlay_parent.is_directory
        overlay_handle = home.open("overlay/deep/file", os.O_CREAT | os.O_RDWR)
        assert home.write(overlay_handle, b"overlay") == len(b"overlay")
        assert home.read(overlay_handle, 0) == b"overlay"
        home.release(overlay_handle)
        assert not (root / "overlay" / "deep" / "file").exists()
        assert (tmp_path / "overlay" / "nested" / "overlay" / "deep" / "file").exists()
    finally:
        home.close()


def test_composite_explicit_listing_uses_only_authorized_backend(
    tmp_path: Path,
) -> None:
    root = tmp_path / "home"
    (root / "visible").mkdir(parents=True)
    (root / "visible" / "shown.txt").write_bytes(b"shown")
    profile = Profile(
        1,
        "listing",
        "listing",
        rules=(
            Rule("visible", RuleScope.SUBTREE, RuleMode.HOST_RO, list_allowed=True),
            Rule("unrelated", RuleScope.EXACT, RuleMode.HOST_RO),
        ),
    )
    home = CompositeProjectedHome(profile, host=HostReadonlyView(root, profile))
    try:
        assert home.listdir("visible") == ("shown.txt",)
        with pytest.raises(OSError) as error:
            home.listdir(".")
        assert error.value.errno == errno.EACCES
    finally:
        home.close()
