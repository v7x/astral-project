from __future__ import annotations

import errno
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from astral_project.homed.private import PrivateStateError, PrivateWritableBackend
from astral_project.profile import Profile


def _profile() -> Profile:
    return Profile.from_toml(
        """
        version = 1
        id = "private-profile"
        name = "private"
        [[home.rules]]
        path = ".cache"
        scope = "subtree"
        mode = "private-rw"
        list = true
        [[home.rules]]
        path = ".state"
        scope = "subtree"
        mode = "private-rw"
        list = true
        """
    )


def test_private_inode_cache_forget_is_bounded(tmp_path: Path) -> None:
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        backend.mkdir(".cache")
        backend.create(".cache/a")
        node = backend.lookup(".cache/a")
        assert backend.inode_count == 3
        backend.lookup(".cache/a")
        backend.forget(node.inode, 1)
        assert backend.node_path(node.inode) == ".cache/a"
        backend.forget(node.inode, 2)
        assert backend.inode_count == 2
        with pytest.raises(PrivateStateError):
            backend.node_path(node.inode)
        backend.forget(1, 1)
        backend.forget(999, 1)
        backend.forget(node.inode, -1)


def test_private_state_persists_per_profile_and_uses_safe_metadata(tmp_path: Path) -> None:
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        backend.mkdir(".cache")
        backend.mkdir(".state")
        assert backend.listdir() == (".cache", ".state")
        handle = backend.open(".cache/log", os.O_RDWR | os.O_CREAT, 0o4777)
        backend.write(handle, b"cache")
        backend.fsync(handle)
        node = backend.lookup(".cache/log")
        assert node.size == 5
        assert node.mode == stat.S_IFREG | 0o700
        backend.release(handle)
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        handle = backend.open(".cache/log")
        assert backend.read(handle) == b"cache"
        backend.release(handle)
        assert (tmp_path / "state" / "private-profile" / ".cache" / "log").exists()


def test_private_rename_unlink_and_host_path_is_not_touched(tmp_path: Path) -> None:
    host = tmp_path / "host"
    host.mkdir()
    (host / "log").write_bytes(b"host")
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        backend.mkdir(".state")
        handle = backend.open(".state/a", os.O_CREAT | os.O_RDWR)
        backend.write(handle, b"private")
        backend.release(handle)
        backend.rename(".state/a", ".state/b")
        handle = backend.open(".state/b")
        assert backend.read(handle) == b"private"
        backend.release(handle)
        backend.unlink(".state/b")
        with pytest.raises(PrivateStateError) as error:
            backend.lookup(".state/b")
        assert error.value.errno == errno.ENOENT
    assert (host / "log").read_bytes() == b"host"


def test_private_path_io_truncate_chmod_and_rmdir(tmp_path: Path) -> None:
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        backend.mkdir(".cache", 0o777)
        backend.create(".cache/log", 0o4777)
        assert backend.write(".cache/log", b"abcdef") == 6
        backend.truncate(".cache/log", 3)
        assert backend.read(".cache/log") == b"abc"
        backend.chmod(".cache/log", 0o4777)
        assert backend.lookup(".cache/log").mode == stat.S_IFREG | 0o700
        backend.unlink(".cache/log")
        backend.rmdir(".cache")


def test_private_quota_and_unsupported_nodes_have_stable_errors(tmp_path: Path) -> None:
    profile = _profile()
    with PrivateWritableBackend(tmp_path / "state", profile, max_bytes=3) as backend:
        backend.mkdir(".cache")
        handle = backend.open(".cache/x", os.O_CREAT | os.O_RDWR)
        with pytest.raises(PrivateStateError) as error:
            backend.write(handle, b"1234")
        assert error.value.errno == errno.EDQUOT
        backend.release(handle)
        with pytest.raises(PrivateStateError) as error:
            backend.setxattr(".cache/x", b"name", b"value")
        assert error.value.errno == errno.ENOTSUP
        with pytest.raises(PrivateStateError) as error:
            backend.mknod(".cache/device", stat.S_IFCHR)
        assert error.value.errno == errno.EPERM
    with PrivateWritableBackend(tmp_path / "append-limit", _profile(), max_bytes=4) as backend:
        backend.mkdir(".cache")
        handle = backend.open(".cache/append", os.O_CREAT | os.O_RDWR)
        assert backend.write(handle, b"123") == 3
        backend.release(handle)
        handle = backend.open(".cache/append", os.O_WRONLY | os.O_APPEND)
        with pytest.raises(PrivateStateError) as error:
            backend.write(handle, b"45")
        assert error.value.errno == errno.EDQUOT
        backend.release(handle)
        assert backend.read(".cache/append") == b"123"
    with PrivateWritableBackend(tmp_path / "file-limit", _profile(), max_files=1) as backend:
        backend.mkdir(".cache")
        backend.create(".cache/one")
        with pytest.raises(PrivateStateError) as error:
            backend.create(".cache/two")
        assert error.value.errno == errno.EDQUOT


def test_private_concurrent_writes_are_serialized(tmp_path: Path) -> None:
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        backend.mkdir(".cache")
        handle = backend.open(".cache/log", os.O_CREAT | os.O_RDWR)

        def write(value: bytes) -> None:
            backend.write(handle, value)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(write, [bytes([index]) for index in range(32)]))
        backend.fsync(handle)
        assert backend.lookup(".cache/log").size == 32
        backend.release(handle)


def test_private_symlink_escape_is_rejected(tmp_path: Path) -> None:
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        backend.mkdir(".cache")
        outside = tmp_path / "outside"
        outside.write_bytes(b"outside")
        os.symlink(outside, tmp_path / "state" / "private-profile" / ".cache" / "link")
        with pytest.raises(PrivateStateError) as error:
            backend.lookup(".cache/link")
        assert error.value.errno in {errno.EACCES, errno.ELOOP}


def test_private_metadata_properties_stat_and_context_manager(tmp_path: Path) -> None:
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        backend.mkdir(".cache")
        backend.create(".cache/file")
        assert backend.root_fd >= 0
        assert backend.profile_root.startswith("/proc/self/fd/")
        assert backend.used_bytes == 0
        assert backend.file_count == 1
        assert backend.stat(".cache/file").size == 0
        (tmp_path / "state" / "private-profile" / "unlisted").write_bytes(b"x")
        assert "unlisted" not in backend.listdir()
        with pytest.raises(PrivateStateError) as error:
            backend.node_path(999)
        assert error.value.errno == errno.ENOENT
        with pytest.raises(PrivateStateError) as error:
            backend._path("../escape")
        assert error.value.errno == errno.EINVAL


def test_private_sanitizes_setid_and_rejects_hardlink_aliases(tmp_path: Path) -> None:
    root = tmp_path / "state"
    profile_root = root / "private-profile"
    profile_root.mkdir(mode=0o700, parents=True)
    os.chmod(root, 0o700)
    (profile_root / "setid").write_bytes(b"x")
    os.chmod(profile_root / "setid", 0o4700)
    (profile_root / "setid-dir").mkdir()
    os.chmod(profile_root / "setid-dir", 0o2700)
    with PrivateWritableBackend(root, "private-profile") as backend:
        assert backend.lookup("setid").mode == stat.S_IFREG | 0o700
        assert backend.lookup("setid-dir").mode == stat.S_IFDIR | 0o700
        assert stat.S_IMODE(os.stat(profile_root / "setid-dir").st_mode) == 0o700
        outside = tmp_path / "outside"
        outside.write_bytes(b"outside")
        os.link(outside, profile_root / "alias")
        backend._scan_usage = lambda: (0, 0)  # type: ignore[method-assign]
        with pytest.raises(PrivateStateError) as error:
            backend.lookup("alias")
        assert error.value.errno == errno.EACCES
        backend._scan_usage = lambda: (0, 0)  # type: ignore[method-assign]
        with pytest.raises(PrivateStateError) as error:
            backend.open("alias")
        assert error.value.errno == errno.EACCES
    with pytest.raises(OSError) as error2:
        PrivateWritableBackend(root, "private-profile")
    assert error2.value.errno == errno.EACCES


def test_private_rejects_invalid_configuration_and_unsafe_state(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        PrivateWritableBackend(tmp_path / "state", _profile(), max_bytes=-1)
    with pytest.raises(ValueError):
        PrivateWritableBackend(tmp_path / "state", "bad/id")
    with pytest.raises(ValueError):
        PrivateWritableBackend(tmp_path / "state", "")
    unsafe_root = tmp_path / "unsafe-root"
    unsafe_root.mkdir(mode=0o700)
    os.chmod(unsafe_root, 0o755)
    with pytest.raises(OSError) as error:
        PrivateWritableBackend(unsafe_root, _profile())
    assert error.value.errno == errno.EACCES
    root_file = tmp_path / "root-file"
    root_file.write_bytes(b"x")
    with pytest.raises(OSError) as error:
        PrivateWritableBackend(root_file, _profile())
    assert error.value.errno == errno.EACCES
    profile_root = tmp_path / "existing"
    profile_root.mkdir(mode=0o700)
    (profile_root / "private-profile").mkdir(mode=0o700)
    os.chmod(profile_root / "private-profile", 0o755)
    with pytest.raises(OSError) as error:
        PrivateWritableBackend(profile_root, _profile())
    assert error.value.errno == errno.EACCES
    oversized = tmp_path / "oversized"
    oversized.mkdir(mode=0o700)
    (oversized / "private-profile").mkdir(mode=0o700)
    (oversized / "private-profile" / "file").write_bytes(b"1234")
    with pytest.raises(OSError) as error:
        PrivateWritableBackend(oversized, _profile(), max_bytes=3)
    assert error.value.errno == errno.EDQUOT
    scan_root = tmp_path / "scan-root"
    (scan_root / "private-profile").mkdir(mode=0o700, parents=True)
    os.mkfifo(scan_root / "private-profile" / "fifo")
    with pytest.raises(OSError) as error:
        PrivateWritableBackend(scan_root, _profile())
    assert error.value.errno == errno.EACCES


def test_private_rejects_invalid_operations_and_node_types(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        with pytest.raises(PrivateStateError) as error:
            backend.lookup("missing")
        assert error.value.errno == errno.EACCES
        backend.mkdir(".cache")
        with pytest.raises(PrivateStateError) as error:
            backend.mkdir(".cache/missing/child")
        assert error.value.errno == errno.ENOENT
        backend.create(".cache/file")
        with pytest.raises(PrivateStateError):
            backend.create(".cache/file")
        backend.create(".cache/source")
        backend.mkdir(".cache/source-dir")
        backend.mkdir(".cache/dest-dir")
        backend.rename(".cache/source-dir", ".cache/dest-dir")
        backend.mkdir(".cache/directory")
        with pytest.raises(PrivateStateError) as error:
            backend.rename(".cache/source", ".cache/directory")
        assert error.value.errno == errno.EISDIR
        os.mkfifo(tmp_path / "state" / "private-profile" / ".cache" / "fifo")
        monkeypatch.setattr(backend, "_scan_usage", lambda: (0, 0))
        with pytest.raises(PrivateStateError) as error:
            backend.lookup(".cache/fifo")
        assert error.value.errno == errno.EACCES
        with pytest.raises(PrivateStateError) as error:
            backend.open(".cache/fifo")
        assert error.value.errno == errno.EACCES
        with pytest.raises(PrivateStateError) as error:
            backend.rename(".cache/fifo", ".cache/fifo-destination")
        assert error.value.errno == errno.EACCES
        backend.create(".cache/destination-source")
        os.mkfifo(tmp_path / "state" / "private-profile" / ".cache" / "destination-node")
        with pytest.raises(PrivateStateError) as error:
            backend.rename(".cache/destination-source", ".cache/destination-node")
        assert error.value.errno == errno.EACCES
        with pytest.raises(PrivateStateError) as error:
            backend.unlink(".cache")
        assert error.value.errno == errno.EISDIR
        with pytest.raises(PrivateStateError) as error:
            backend.rmdir(".cache/file")
        assert error.value.errno == errno.ENOTDIR
        with pytest.raises(PrivateStateError) as error:
            backend.rename(".cache/missing", ".cache/new")
        assert error.value.errno == errno.ENOENT
        backend.create(".cache/destination")
        backend.rename(".cache/file", ".cache/destination")
        backend.rename(".cache/source", ".cache/final")
        with pytest.raises(PrivateStateError) as error:
            backend.setxattr(".cache/file", b"n", b"v")
        assert error.value.errno == errno.ENOTSUP
        with pytest.raises(PrivateStateError) as error:
            backend.symlink("target", ".cache/link")
        assert error.value.errno == errno.EOPNOTSUPP


def test_private_rejects_unowned_file_descriptors(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        descriptor = os.open(outside, os.O_RDONLY)
        try:
            with pytest.raises(PrivateStateError) as error:
                backend.read(descriptor)
            assert error.value.errno == errno.EBADF
        finally:
            os.close(descriptor)


def test_private_operation_edges_and_error_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with PrivateWritableBackend(tmp_path / "state", _profile(), max_files=2) as backend:
        backend.mkdir(".cache")
        backend.create(".cache/file")
        assert backend.listdir(".cache") == ("file",)
        assert backend.stat(".cache/file").size == 0
        handle = backend.open(".cache/file", os.O_RDWR | os.O_TRUNC)
        assert backend.read(handle, 0, 0) == b""
        with pytest.raises(ValueError):
            backend.read(handle, -1)
        with pytest.raises(TypeError):
            backend.write(handle, "bad")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            backend.write(handle, b"x", -1)
        with pytest.raises(ValueError):
            backend.truncate(handle, -1)
        backend.release(handle)
        backend.release(99999)
        with PrivateWritableBackend(tmp_path / "state-no-profile", "plain") as unscoped:
            assert unscoped._filter_listing(".", ("name",)) == ("name",)
        with pytest.raises(PrivateStateError) as error:
            backend.open(".cache/file", os.O_CREAT | os.O_EXCL)
        assert error.value.errno == errno.EEXIST
        with pytest.raises(PrivateStateError):
            backend.open(".cache/file", os.O_RDONLY | os.O_DIRECTORY)
        with pytest.raises(PrivateStateError) as error:
            backend.open(".cache", os.O_RDONLY)
        assert error.value.errno == errno.EACCES
        with pytest.raises(PrivateStateError) as error:
            backend.open(".cache/missing")
        assert error.value.errno == errno.ENOENT
        with pytest.raises(PrivateStateError):
            backend.mkdir(".cache")
        with pytest.raises(PrivateStateError):
            backend.rmdir(".cache")
        monkeypatch.setattr(backend, "_scan_usage", lambda: (0, 0))
        monkeypatch.setattr(os, "listdir", lambda _fd: [str(i) for i in range(4097)])
        with pytest.raises(PrivateStateError) as error:
            backend.listdir(".cache")
        assert error.value.errno == errno.EOVERFLOW


def test_private_close_releases_open_handles_and_reserves_lock(tmp_path: Path) -> None:
    backend = PrivateWritableBackend(tmp_path / "state", _profile())
    backend.mkdir(".cache")
    handle = backend.open(".cache/file", os.O_CREAT | os.O_RDWR)
    with pytest.raises(PrivateStateError):
        backend._path(".aspr-private-lock")
    backend.close()
    backend.close()
    with pytest.raises(OSError):
        os.fstat(handle)


def test_private_internal_error_paths_are_stable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with PrivateWritableBackend(tmp_path / "state", _profile()) as backend:
        backend.mkdir(".cache")
        backend.mkdir(".state")
        backend.create(".cache/file")
        handle = backend.open(".cache/file", os.O_RDWR)
        backend.fsync(".cache/file")
        monkeypatch.setattr(
            os, "pread", lambda *_args: (_ for _ in ()).throw(OSError(errno.EIO, "read"))
        )
        with pytest.raises(PrivateStateError) as error:
            backend.read(handle)
        assert error.value.errno == errno.EIO
        monkeypatch.setattr(os, "pread", os.pread)
        monkeypatch.setattr(
            os, "ftruncate", lambda *_args: (_ for _ in ()).throw(OSError(errno.EIO, "truncate"))
        )
        with pytest.raises(PrivateStateError):
            backend.truncate(handle, 1)
        monkeypatch.setattr(os, "ftruncate", os.ftruncate)
        monkeypatch.setattr(
            os, "fsync", lambda *_args: (_ for _ in ()).throw(OSError(errno.EIO, "sync"))
        )
        with pytest.raises(PrivateStateError):
            backend.fsync(handle)
        monkeypatch.setattr(os, "fsync", os.fsync)
        monkeypatch.setattr(
            os, "fchmod", lambda *_args: (_ for _ in ()).throw(OSError(errno.EIO, "chmod"))
        )
        with pytest.raises(PrivateStateError):
            backend.chmod(handle, 0o600)
        backend.release(handle)
        directory_handle = os.open(backend.profile_root, os.O_RDONLY | os.O_DIRECTORY)
        backend._handles.add(directory_handle)
        with pytest.raises(PrivateStateError) as error:
            backend.write(directory_handle, b"x")
        assert error.value.errno == errno.EISDIR
        backend.release(directory_handle)
        with pytest.raises(PrivateStateError):
            backend._parent(".")
        with pytest.raises(PrivateStateError):
            backend._node("bad", os.stat_result((stat.S_IFCHR, 0, 0, 0, 0, 0, 0, 0, 0, 0)))
        backend._used_bytes = 0
        backend._check_size(10, -1)
        original_listdir = os.listdir
        calls = 0

        def fail_after_child(_descriptor: int) -> list[str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                return [".cache", ".state"]
            raise OSError(errno.EIO, "scan")

        monkeypatch.setattr(os, "listdir", fail_after_child)
        with pytest.raises(PrivateStateError):
            backend._scan_usage()
        monkeypatch.setattr(os, "listdir", original_listdir)


def test_private_policy_and_closed_backend_fail_closed(tmp_path: Path) -> None:
    backend = PrivateWritableBackend(tmp_path / "state", _profile())
    with pytest.raises(PrivateStateError) as error:
        backend.open(".unknown", os.O_CREAT | os.O_RDWR)
    assert error.value.errno == errno.EACCES
    backend.close()
    with pytest.raises(PrivateStateError) as error:
        backend.listdir()
    assert error.value.errno == errno.ESTALE
