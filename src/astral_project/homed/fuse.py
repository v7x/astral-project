"""pyfuse3 adapter for the empty projected-home core."""

from __future__ import annotations

import errno
import os
import stat
import subprocess
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from astral_project.homed.composite import CompositeProjectedHome
from astral_project.homed.core import (
    ROOT_INODE,
    EmptyProjectedHome,
    HomedError,
    InodeRecord,
    RequestLease,
)
from astral_project.homed.host import BackingNode, HostReadonlyView
from astral_project.homed.mediation import RemoteUnknownPathMediator, UnknownPathMediator
from astral_project.homed.overlay import OverlayBackend
from astral_project.homed.private import PrivateWritableBackend
from astral_project.profile import Profile
from astral_project.sandbox.hardening import HardeningPolicy, enforce

try:
    import pyfuse3 as _pyfuse3  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised only on hosts without FUSE build deps
    _pyfuse3 = None


class FuseUnavailable(RuntimeError):
    """FUSE runtime is unavailable in this installation."""


def _fuse_error(  # pragma: no cover - concrete error type exercised by FUSE acceptance
    error: HomedError | OSError,
) -> Any:
    if _pyfuse3 is None:
        raise FuseUnavailable("pyfuse3 is not installed") from error
    return _pyfuse3.FUSEError(error.errno or errno.EIO)


def _host_attributes(  # pragma: no cover - concrete type exercised by FUSE acceptance
    record: BackingNode,
) -> Any:
    if _pyfuse3 is None:
        raise FuseUnavailable("pyfuse3 is not installed")
    result = _pyfuse3.EntryAttributes()
    result.st_ino = record.inode
    result.st_mode = record.mode
    result.st_nlink = 2 if record.is_directory else 1
    result.st_uid = os.getuid()
    result.st_gid = os.getgid()
    result.st_size = record.size
    result.st_atime_ns = result.st_mtime_ns = record.mtime_ns
    result.st_ctime_ns = record.mtime_ns
    result.entry_timeout = 0
    result.attr_timeout = 0
    result.generation = 0
    return result


def _attributes(  # pragma: no cover - concrete type exercised by FUSE acceptance
    record: InodeRecord,
) -> Any:
    if _pyfuse3 is None:
        raise FuseUnavailable("pyfuse3 is not installed")
    result = _pyfuse3.EntryAttributes()
    result.st_ino = record.inode
    result.st_mode = record.mode
    result.st_nlink = 2 if stat.S_ISDIR(record.mode) else 1
    result.st_uid = os.getuid()
    result.st_gid = os.getgid()
    result.st_size = record.size
    result.st_atime_ns = result.st_mtime_ns = result.st_ctime_ns = 0
    result.entry_timeout = 0
    result.attr_timeout = 0
    result.generation = 0
    return result


if _pyfuse3 is not None:  # pragma: no cover - exercised by installed FUSE acceptance

    class ProjectedHomeOperations(_pyfuse3.Operations):  # type: ignore[misc]
        """Stable projected-home FUSE filesystem."""

        def __init__(
            self,
            state: EmptyProjectedHome | None = None,
            host_view: HostReadonlyView | None = None,
            private_view: PrivateWritableBackend | None = None,
            overlay_view: OverlayBackend | None = None,
            profile: Profile | None = None,
        ) -> None:
            super().__init__()
            self.state = state or EmptyProjectedHome()
            self.host_view: HostReadonlyView | None
            self.private_view: (
                PrivateWritableBackend | OverlayBackend | CompositeProjectedHome | None
            )
            self.overlay_view: OverlayBackend | None
            backings = sum(view is not None for view in (host_view, private_view, overlay_view))
            if backings > 1:
                if profile is None:
                    raise ValueError("composite projected home requires a profile")
                self.host_view = None
                self.overlay_view = None
                self.private_view = CompositeProjectedHome(
                    profile, host=host_view, private=private_view, overlay=overlay_view
                )
            else:
                self.host_view = host_view
                self.overlay_view = overlay_view
                self.private_view = private_view or overlay_view
            self._host_handles: dict[int, str] = {}
            self._next_host_handle = 1 << 32

        async def lookup(self, parent_inode: int, name: bytes, ctx: Any) -> Any:
            del ctx
            with RequestLease(self.state.budget, len(name)):
                if self.private_view is not None:
                    try:
                        parent = self.private_view.node_path(parent_inode)
                        if name == b".":
                            path = parent
                        elif name == b"..":
                            path = "." if parent == "." else parent.rsplit("/", 1)[0] or "."
                        else:
                            component = name.decode("utf-8")
                            path = component if parent == "." else f"{parent}/{component}"
                        return _host_attributes(self.private_view.lookup(path))
                    except UnicodeDecodeError as error:
                        raise _fuse_error(OSError(errno.EINVAL, "invalid UTF-8 name")) from error
                    except OSError as error:
                        raise _fuse_error(error) from error
                if self.host_view is None:
                    try:
                        return _attributes(self.state.lookup(parent_inode, name))
                    except HomedError as error:
                        raise _fuse_error(error) from error
                try:
                    parent = (
                        "."
                        if parent_inode == ROOT_INODE
                        else self.host_view.node_path(parent_inode)
                    )
                    if name == b".":
                        path = parent
                    elif name == b"..":
                        path = "." if parent == "." else parent.rsplit("/", 1)[0] or "."
                    else:
                        component = name.decode("utf-8")
                        path = component if parent == "." else f"{parent}/{component}"
                    return _host_attributes(await self._host_call(self.host_view.lookup, path))
                except UnicodeDecodeError as error:
                    raise _fuse_error(OSError(errno.EINVAL, "invalid UTF-8 name")) from error
                except OSError as error:
                    raise _fuse_error(error) from error

        async def getattr(self, inode: int, ctx: Any = None) -> Any:
            del ctx
            with RequestLease(self.state.budget, 1):
                if self.private_view is not None:
                    try:
                        return _host_attributes(
                            self.private_view.lookup(self.private_view.node_path(inode))
                        )
                    except OSError as error:
                        raise _fuse_error(error) from error
                if self.host_view is None or inode == ROOT_INODE:
                    try:
                        return _attributes(self.state.getattr(inode))
                    except HomedError as error:
                        raise _fuse_error(error) from error
                try:
                    path = self.host_view.node_path(inode)
                    return _host_attributes(await self._host_call(self.host_view.stat, path))
                except OSError as error:
                    raise _fuse_error(error) from error

        async def open(self, inode: int, flags: int, ctx: Any) -> Any:
            del ctx
            with RequestLease(self.state.budget, 1):
                if self.private_view is not None:
                    try:
                        path = self.private_view.node_path(inode)
                        return _pyfuse3.FileInfo(fh=self.private_view.open(path, flags))
                    except OSError as error:
                        raise _fuse_error(error) from error
                if self.host_view is None:
                    try:
                        return _pyfuse3.FileInfo(fh=self.state.open(inode, flags))
                    except HomedError as error:
                        raise _fuse_error(error) from error
                if flags & (os.O_WRONLY | os.O_RDWR | os.O_TRUNC):
                    raise _pyfuse3.FUSEError(errno.EROFS)
                try:
                    path = self.host_view.node_path(inode)
                    node = await self._host_call(self.host_view.stat, path)
                    if node.is_directory:
                        raise OSError(errno.EISDIR, "directory is not a file")
                    handle = self._next_host_handle
                    self._next_host_handle += 1
                    self._host_handles[handle] = path
                    return _pyfuse3.FileInfo(fh=handle)
                except OSError as error:
                    raise _fuse_error(error) from error

        async def release(self, fh: int) -> None:
            with RequestLease(self.state.budget, 1):
                if self.private_view is not None:
                    self.private_view.release(fh)
                elif self.host_view is None:
                    self.state.release(fh)
                else:
                    self._host_handles.pop(fh, None)

        async def forget(self, inode_list: list[tuple[int, int]]) -> None:
            with RequestLease(self.state.budget, 1):
                for inode, count in inode_list:
                    self.state.forget(inode, count)
                    if self.host_view is not None:
                        self.host_view.forget(inode, count)
                    if self.private_view is not None:
                        self.private_view.forget(inode, count)

        async def opendir(self, inode: int, ctx: Any) -> int:
            del ctx
            with RequestLease(self.state.budget, 1):
                if self.private_view is not None:
                    try:
                        node = self.private_view.lookup(self.private_view.node_path(inode))
                        if not node.is_directory:
                            raise OSError(errno.ENOTDIR, "not a directory")
                        return inode
                    except OSError as error:
                        raise _fuse_error(error) from error
                if self.host_view is None:
                    if inode != ROOT_INODE:
                        raise _pyfuse3.FUSEError(errno.ENOENT)
                    return ROOT_INODE
                try:
                    if inode == ROOT_INODE:
                        return ROOT_INODE
                    path = self.host_view.node_path(inode)
                    node = await self._host_call(self.host_view.stat, path)
                    if not node.is_directory:
                        raise OSError(errno.ENOTDIR, "not a directory")
                    return inode
                except OSError as error:
                    raise _fuse_error(error) from error

        async def readdir(self, fh: int, start_id: int, token: Any) -> None:
            with RequestLease(self.state.budget, 64 * 1024):
                if self.private_view is not None:
                    path = self.private_view.node_path(fh)
                    try:
                        names = await self._host_call(self.private_view.listdir, path)
                        for index, name in enumerate(names, start=1):
                            if index <= start_id:
                                continue
                            child_path = name if path == "." else f"{path}/{name}"
                            try:
                                child = await self._host_call(self.private_view.lookup, child_path)
                            except OSError:
                                continue
                            if not _pyfuse3.readdir_reply(
                                token, name.encode(), _host_attributes(child), index
                            ):
                                return
                        return
                    except OSError as error:
                        raise _fuse_error(error) from error
                if self.host_view is None:
                    return
                path = "." if fh == ROOT_INODE else self.host_view.node_path(fh)
                try:
                    names = await self._host_call(self.host_view.listdir, path)
                    for index, name in enumerate(names, start=1):
                        if index <= start_id:
                            continue
                        child_path = name if path == "." else f"{path}/{name}"
                        try:
                            child = await self._host_call(self.host_view.lookup, child_path)
                        except OSError:
                            continue
                        if not _pyfuse3.readdir_reply(
                            token, name.encode(), _host_attributes(child), index
                        ):
                            return
                except OSError as error:
                    raise _fuse_error(error) from error

        async def setattr(self, inode: int, attr: Any, fields: Any, fh: int, ctx: Any) -> Any:
            del attr, ctx
            with RequestLease(self.state.budget, 1):
                if self.private_view is None:
                    del inode, fields, fh
                    raise _pyfuse3.FUSEError(errno.EROFS)
                try:
                    if getattr(fields, "update_mode", False):
                        target = (
                            fh
                            if fh
                            else self.private_view.open(
                                self.private_view.node_path(inode), os.O_RDONLY
                            )
                        )
                        try:
                            self.private_view.chmod(target, fields.mode)
                        finally:
                            if not fh:
                                self.private_view.release(target)
                    if getattr(fields, "update_size", False):
                        target = (
                            fh
                            if fh
                            else self.private_view.open(
                                self.private_view.node_path(inode), os.O_RDWR
                            )
                        )
                        try:
                            self.private_view.truncate(target, fields.size)
                        finally:
                            if not fh:
                                self.private_view.release(target)
                    return _host_attributes(
                        self.private_view.lookup(self.private_view.node_path(inode))
                    )
                except OSError as error:
                    raise _fuse_error(error) from error

        async def statfs(self, ctx: Any) -> Any:
            del ctx
            with RequestLease(self.state.budget, 1):
                result = _pyfuse3.StatvfsData()
                result.f_bsize = 4096
                result.f_frsize = 4096
                if self.private_view is None:
                    result.f_blocks = 1
                    result.f_bfree = 1
                    result.f_bavail = 1
                    result.f_files = 1024
                    result.f_ffree = 1024
                    result.f_favail = 1024
                else:
                    result.f_blocks = max(1, (self.private_view.max_bytes + 4095) // 4096)
                    result.f_bfree = max(
                        0, result.f_blocks - (self.private_view.used_bytes + 4095) // 4096
                    )
                    result.f_bavail = result.f_bfree
                    result.f_files = self.private_view.max_files
                    result.f_ffree = max(0, result.f_files - self.private_view.file_count)
                    result.f_favail = result.f_ffree
                result.f_namemax = 255
                return result

        async def read(self, fh: int, off: int, size: int) -> bytes:
            with RequestLease(self.state.budget, size):
                if self.private_view is not None:
                    try:
                        return self.private_view.read(fh, off, size)
                    except OSError as error:
                        raise _fuse_error(error) from error
                if self.host_view is None:
                    raise _pyfuse3.FUSEError(errno.EIO)
                try:
                    path = self._host_handles[fh]
                    result = await self._host_call(self.host_view.read, path, off, size)
                    if not isinstance(result, bytes):
                        raise OSError(errno.EIO, "host read returned invalid data")
                    return result
                except KeyError as error:
                    raise _pyfuse3.FUSEError(errno.EBADF) from error
                except OSError as error:
                    raise _fuse_error(error) from error

        async def _host_call(self, function: Callable[..., Any], *args: Any) -> Any:
            import trio  # type: ignore[import-not-found]

            try:
                return await trio.to_thread.run_sync(function, *args, abandon_on_cancel=True)
            except trio.Cancelled:
                if self.host_view is not None:
                    self.host_view.cancel_pending()
                raise

        async def write(self, fh: int, off: int, buf: bytes) -> int:
            with RequestLease(self.state.budget, len(buf)):
                if self.private_view is None:
                    raise _pyfuse3.FUSEError(errno.EROFS)
                try:
                    return self.private_view.write(fh, buf, off)
                except OSError as error:
                    raise _fuse_error(error) from error

        async def fsync(self, fh: int, datasync: bool) -> None:
            del datasync
            with RequestLease(self.state.budget, 1):
                if self.private_view is None:
                    raise _pyfuse3.FUSEError(errno.EROFS)
                try:
                    self.private_view.fsync(fh)
                except OSError as error:
                    raise _fuse_error(error) from error

        async def create(
            self, parent_inode: int, name: bytes, mode: int, flags: int, ctx: Any
        ) -> Any:
            del ctx
            if self.private_view is None:
                raise _pyfuse3.FUSEError(errno.EROFS)
            with RequestLease(self.state.budget, len(name)):
                try:
                    parent = self.private_view.node_path(parent_inode)
                    component = name.decode("utf-8")
                    path = component if parent == "." else f"{parent}/{component}"
                    node = self.private_view.create(path, mode)
                    handle = self.private_view.open(path, flags & ~os.O_CREAT & ~os.O_EXCL)
                    return _pyfuse3.FileInfo(fh=handle), _host_attributes(node)
                except UnicodeDecodeError as error:
                    raise _fuse_error(OSError(errno.EINVAL, "invalid UTF-8 name")) from error
                except OSError as error:
                    raise _fuse_error(error) from error

        async def mkdir(self, parent_inode: int, name: bytes, mode: int, ctx: Any) -> Any:
            del ctx
            if self.private_view is None:
                raise _pyfuse3.FUSEError(errno.EROFS)
            with RequestLease(self.state.budget, len(name)):
                try:
                    parent = self.private_view.node_path(parent_inode)
                    component = name.decode("utf-8")
                    path = component if parent == "." else f"{parent}/{component}"
                    return _host_attributes(self.private_view.mkdir(path, mode))
                except UnicodeDecodeError as error:
                    raise _fuse_error(OSError(errno.EINVAL, "invalid UTF-8 name")) from error
                except OSError as error:
                    raise _fuse_error(error) from error

        async def unlink(self, parent_inode: int, name: bytes, ctx: Any) -> None:
            del ctx
            if self.private_view is None:
                raise _pyfuse3.FUSEError(errno.EROFS)
            with RequestLease(self.state.budget, len(name)):
                try:
                    parent = self.private_view.node_path(parent_inode)
                    component = name.decode("utf-8")
                    path = component if parent == "." else f"{parent}/{component}"
                    self.private_view.unlink(path)
                except UnicodeDecodeError as error:
                    raise _fuse_error(OSError(errno.EINVAL, "invalid UTF-8 name")) from error
                except OSError as error:
                    raise _fuse_error(error) from error

        async def rmdir(self, parent_inode: int, name: bytes, ctx: Any) -> None:
            del ctx
            if self.private_view is None:
                raise _pyfuse3.FUSEError(errno.EROFS)
            with RequestLease(self.state.budget, len(name)):
                try:
                    parent = self.private_view.node_path(parent_inode)
                    component = name.decode("utf-8")
                    path = component if parent == "." else f"{parent}/{component}"
                    self.private_view.unlink(path, directory=True)
                except UnicodeDecodeError as error:
                    raise _fuse_error(OSError(errno.EINVAL, "invalid UTF-8 name")) from error
                except OSError as error:
                    raise _fuse_error(error) from error

        async def rename(
            self,
            parent_inode: int,
            name: bytes,
            new_parent_inode: int,
            new_name: bytes,
            flags: int,
            ctx: Any,
        ) -> None:
            del flags, ctx
            if self.private_view is None:
                raise _pyfuse3.FUSEError(errno.EROFS)
            with RequestLease(self.state.budget, len(name) + len(new_name)):
                try:
                    old_parent = self.private_view.node_path(parent_inode)
                    new_parent = self.private_view.node_path(new_parent_inode)
                    old_component = name.decode("utf-8")
                    new_component = new_name.decode("utf-8")
                    old = old_component if old_parent == "." else f"{old_parent}/{old_component}"
                    new = new_component if new_parent == "." else f"{new_parent}/{new_component}"
                    self.private_view.rename(old, new)
                except UnicodeDecodeError as error:
                    raise _fuse_error(OSError(errno.EINVAL, "invalid UTF-8 name")) from error
                except OSError as error:
                    raise _fuse_error(error) from error

        async def destroy(self) -> None:
            with RequestLease(self.state.budget, 1):
                self.state.close()
                if self.host_view is not None:
                    self.host_view.close()
                if self.private_view is not None:
                    self.private_view.close()

else:

    class ProjectedHomeOperations:  # type: ignore[no-redef]
        """Import-safe placeholder when libfuse development/runtime is absent."""

        def __init__(
            self,
            state: EmptyProjectedHome | None = None,
            host_view: HostReadonlyView | None = None,
            private_view: PrivateWritableBackend | None = None,
            overlay_view: OverlayBackend | None = None,
            profile: Profile | None = None,
        ) -> None:
            del state, host_view, private_view, overlay_view, profile
            raise FuseUnavailable("pyfuse3 is not installed")


def _mount_operations(  # pragma: no cover - exercised by installed FUSE acceptance
    mountpoint: str | os.PathLike[str],
    operations: Any,
    *,
    debug: bool = False,
    hardening_roots: Sequence[tuple[Path, bool]] = (),
    writable_tmp: bool = True,
) -> None:
    if _pyfuse3 is None:
        raise FuseUnavailable("pyfuse3 is not installed")
    import trio

    path = Path(mountpoint)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    options = set(_pyfuse3.default_options)
    options.update({"fsname=aspr-homed", "nodev", "nosuid", "noexec"})
    if operations.private_view is None:
        options.add("ro")
    if debug:
        options.add("debug")
    policy = HardeningPolicy.for_plan([(path, True), *hardening_roots], writable_tmp=writable_tmp)
    initialized = False
    try:
        _pyfuse3.init(operations, os.fspath(path), options)
        initialized = True
        enforce(policy)
        trio.run(_pyfuse3.main)
    finally:
        operations.state.close()
        if operations.host_view is not None:
            operations.host_view.close()
        if initialized:
            _pyfuse3.close(unmount=False)


def mount_empty(  # pragma: no cover - exercised by installed FUSE acceptance
    mountpoint: str | os.PathLike[str], *, debug: bool = False
) -> None:
    """Run empty projected-home FUSE loop until unmounted or interrupted."""
    _mount_operations(mountpoint, ProjectedHomeOperations(), debug=debug)


def mount_private(  # pragma: no cover - exercised by installed FUSE acceptance
    mountpoint: str | os.PathLike[str],
    storage_root: str | os.PathLike[str],
    profile: Profile,
    *,
    max_bytes: int = 64 * 1024 * 1024,
    max_files: int = 16_384,
    debug: bool = False,
) -> None:
    """Run private writable projected home backed by persistent profile state."""
    view = PrivateWritableBackend(storage_root, profile, max_bytes=max_bytes, max_files=max_files)
    try:
        _mount_operations(
            mountpoint,
            ProjectedHomeOperations(private_view=view),
            debug=debug,
            hardening_roots=((Path(storage_root), True),),
        )
    finally:
        view.close()


def mount_overlay(  # pragma: no cover - exercised by installed FUSE acceptance
    mountpoint: str | os.PathLike[str],
    lower_root: str | os.PathLike[str],
    upper_root: str | os.PathLike[str],
    *,
    profile: Profile | None = None,
    debug: bool = False,
) -> None:
    """Run writable descriptor-confined overlay projected home."""
    view = OverlayBackend(lower_root, upper_root, profile)
    try:
        _mount_operations(
            mountpoint,
            ProjectedHomeOperations(overlay_view=view),
            debug=debug,
            hardening_roots=((Path(lower_root), False), (Path(upper_root), True)),
            writable_tmp=False,
        )
    finally:
        view.close()


def mount_composite(  # pragma: no cover - exercised by installed FUSE acceptance
    mountpoint: str | os.PathLike[str],
    root: str | os.PathLike[str],
    profile: Profile,
    *,
    storage_root: str | os.PathLike[str] | None = None,
    overlay_root: str | os.PathLike[str] | None = None,
    debug: bool = False,
    mediator: UnknownPathMediator | RemoteUnknownPathMediator | None = None,
    session_id: str = "default",
) -> None:
    """Mount one policy-routed namespace over all configured backing roots."""
    host = HostReadonlyView(root, profile, mediator=mediator, session_id=session_id)
    private = None if storage_root is None else PrivateWritableBackend(storage_root, profile)
    overlay = None if overlay_root is None else OverlayBackend(root, overlay_root, profile)
    try:
        roots: list[tuple[Path, bool]] = [(Path(root), False)]
        if storage_root is not None:
            roots.append((Path(storage_root), True))
        if overlay_root is not None:
            roots.append((Path(overlay_root), True))
        _mount_operations(
            mountpoint,
            ProjectedHomeOperations(
                host_view=host, private_view=private, overlay_view=overlay, profile=profile
            ),
            debug=debug,
            hardening_roots=roots,
            writable_tmp=False,
        )
    finally:
        # Composite owns all non-null backends once construction succeeds; these
        # closes retain cleanup for failures before Operations takes ownership.
        for view in (host, private, overlay):
            if view is not None:
                view.close()


def mount_host_readonly(  # pragma: no cover - exercised by installed FUSE acceptance
    mountpoint: str | os.PathLike[str],
    root: str | os.PathLike[str],
    profile: Profile,
    *,
    debug: bool = False,
    mediator: UnknownPathMediator | RemoteUnknownPathMediator | None = None,
    session_id: str = "default",
) -> None:
    """Run projected home backed by explicit rules and bounded unknown mediation."""
    view = HostReadonlyView(root, profile, mediator=mediator, session_id=session_id)
    _mount_operations(
        mountpoint,
        ProjectedHomeOperations(host_view=view),
        debug=debug,
        hardening_roots=((Path(root), False),),
        writable_tmp=False,
    )


def cleanup_stale_mount(  # pragma: no cover - exercised by installed FUSE acceptance
    mountpoint: str | os.PathLike[str],
) -> bool:
    """Lazily detach only an active FUSE mount at an explicit mountpoint."""
    path = os.path.realpath(os.fspath(mountpoint))
    mounted = False
    try:
        mounts = Path("/proc/self/mountinfo").read_text(encoding="utf-8")
    except OSError:
        return False
    for line in mounts.splitlines():
        fields = line.split(" ")
        if len(fields) > 4 and fields[4] == path:
            mounted = True
            break
    if not mounted:
        return False
    result = subprocess.run(
        ["fusermount3", "-u", "-z", path], capture_output=True, check=False, timeout=5.0
    )
    return result.returncode == 0
