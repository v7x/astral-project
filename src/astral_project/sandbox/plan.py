"""Typed, bounded local bubblewrap plans."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import AccessMode


class NetworkMode(StrEnum):
    INHERIT = "inherit"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class RemoteBinding:
    """One already-created daemon mount exposed at one fixed sandbox path."""

    mount_id: str
    host_path: Path
    target: str
    mode: AccessMode

    def __post_init__(self) -> None:
        if not self.mount_id or "/" in self.mount_id or "\x00" in self.mount_id:
            raise _error("sandbox mount identifier is invalid")
        if not self.host_path.is_absolute() or not self.host_path.is_dir():
            raise _error("sandbox remote mount path is unavailable")
        _target(self.target)
        if not isinstance(self.mode, AccessMode):
            raise _error("sandbox remote access mode is invalid")
        if not os.path.ismount(self.host_path):
            raise _error("sandbox remote path is not a mounted daemon view")


@dataclass(frozen=True, slots=True)
class LocalSandboxPlan:
    """All sandbox authority fixed before bubblewrap is executed."""

    command: tuple[str, ...]
    network: NetworkMode
    remotes: tuple[RemoteBinding, ...] = ()
    session_socket: Path | None = None
    session_id: str | None = None
    projected_home: Path | None = None
    projected_home_writable: bool = False
    socket_paths: tuple[Path, ...] = ()
    bwrap_binary: Path = Path("/usr/bin/bwrap")
    launcher_binary: Path = Path("/usr/libexec/astral-project/aspr-bwrap-launch")

    def __post_init__(self) -> None:
        if not self.command or any(not value or "\x00" in value for value in self.command):
            raise _error("sandbox command must be non-empty and NUL-free")
        if not isinstance(self.network, NetworkMode):
            raise _error("sandbox network mode must be inherit or none")
        if self.bwrap_binary != Path("/usr/bin/bwrap"):
            raise _error("sandbox executable is fixed to /usr/bin/bwrap")
        if self.launcher_binary != Path("/usr/libexec/astral-project/aspr-bwrap-launch"):
            raise _error("sandbox launcher is fixed to the installed Astral launcher")
        if not isinstance(self.projected_home_writable, bool):
            raise _error("sandbox projected home mutability flag is invalid")
        if self.projected_home_writable and self.projected_home is None:
            raise _error("sandbox writable home requires a projected home")
        for socket_path in self.socket_paths:
            if (
                not socket_path.is_absolute()
                or socket_path == Path("/")
                or "\x00" in os.fspath(socket_path)
                or ".." in socket_path.parts
                or str(socket_path) != os.fspath(socket_path)
                or not socket_path.is_socket()
            ):
                raise _error("sandbox socket path is unavailable or not exact")
        if self.projected_home is not None and (
            not self.projected_home.is_absolute()
            or not self.projected_home.is_dir()
            or not os.path.ismount(self.projected_home)
        ):
            raise _error("sandbox projected home is unavailable or not mounted")
        if self.session_socket is not None and (
            not self.session_socket.is_absolute() or not self.session_socket.exists()
        ):
            raise _error("sandbox session socket is unavailable")
        if self.session_id is not None and (
            self.session_socket is None
            or not self.session_id
            or "\x00" in self.session_id
            or len(self.session_id.encode()) > 4096
        ):
            raise _error("sandbox session identity is invalid")
        if self.session_socket is not None and self.session_id is None:
            raise _error("sandbox session identity is required")
        targets = tuple(binding.target for binding in self.remotes)
        if len(set(targets)) != len(targets):
            raise _error("sandbox remote targets collide")
        for index, left in enumerate(targets):
            for right in targets[index + 1 :]:
                if left.startswith(right + "/") or right.startswith(left + "/"):
                    raise _error("sandbox remote targets overlap")

    def launcher_argv(self) -> list[str]:
        """Invoke only fixed launcher; plan authority travels through its bounded stdin ABI."""
        return [str(self.launcher_binary)]

    def plan_bytes(self) -> bytes:
        """Serialize bounded plan for fixed launcher, with no raw bwrap options."""
        payload = bytearray(b"ASPRSB01")
        payload.extend(
            struct.pack("!BI", 1 if self.network is NetworkMode.NONE else 0, len(self.command))
        )
        for value in self.command:
            encoded = value.encode("utf-8")
            if not 0 < len(encoded) <= 4096:
                raise _error("sandbox command argument is too long")
            payload.extend(struct.pack("!I", len(encoded)))
            payload.extend(encoded)
        payload.extend(struct.pack("!I", len(self.remotes)))
        for binding in self.remotes:
            payload.extend(struct.pack("!B", 1 if binding.mode is AccessMode.READ_WRITE else 0))
            for value in (binding.mount_id, str(binding.host_path), binding.target):
                encoded = value.encode("utf-8")
                if not 0 < len(encoded) <= 4096:
                    raise _error("sandbox remote field is too long")
                payload.extend(struct.pack("!I", len(encoded)))
                payload.extend(encoded)
        payload.extend(struct.pack("!I", len(self.socket_paths)))
        for socket_path in self.socket_paths:
            encoded = str(socket_path).encode("utf-8")
            if not 0 < len(encoded) <= 4096:
                raise _error("sandbox socket path is too long")
            payload.extend(struct.pack("!I", len(encoded)))
            payload.extend(encoded)
        if self.session_socket is None:
            payload.extend(b"\x00")
        else:
            encoded = str(self.session_socket).encode("utf-8")
            if not 0 < len(encoded) <= 4096:
                raise _error("sandbox session socket path is too long")
            payload.extend(b"\x01")
            payload.extend(struct.pack("!I", len(encoded)))
            payload.extend(encoded)
        if self.session_id is None:
            payload.extend(b"\x00")
        else:
            encoded = self.session_id.encode("utf-8")
            payload.extend(b"\x01")
            payload.extend(struct.pack("!I", len(encoded)))
            payload.extend(encoded)
        if self.projected_home is None:
            payload.extend(b"\x00")
        else:
            encoded = str(self.projected_home).encode("utf-8")
            if not 0 < len(encoded) <= 4096:
                raise _error("sandbox projected home path is too long")
            payload.extend(b"\x01")
            payload.extend(struct.pack("!I", len(encoded)))
            payload.extend(encoded)
            payload.extend(b"\x01" if self.projected_home_writable else b"\x00")
        if len(payload) > 64 * 1024:
            raise _error("sandbox plan exceeds size limit")
        return bytes(payload)

    def argv(self) -> list[str]:
        """Build fixed bubblewrap argv for audit tests; launcher is production path."""
        argv = [
            str(self.bwrap_binary),
            "--die-with-parent",
            "--new-session",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--ro-bind",
            "/usr",
            "/usr",
            "--symlink",
            "/usr/bin",
            "/bin",
            "--symlink",
            "/usr/sbin",
            "/sbin",
            "--symlink",
            "/usr/lib",
            "/lib",
            "--symlink",
            "/usr/lib64",
            "/lib64",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--tmpfs",
            "/tmp",
            "--tmpfs",
            "/home",
            "--dir",
            "/home/sandbox",
            "--setenv",
            "HOME",
            "/home/sandbox",
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin",
            "--clearenv",
            "--setenv",
            "HOME",
            "/home/sandbox",
            "--setenv",
            "PATH",
            "/usr/local/bin:/usr/bin:/bin",
            "--cap-drop",
            "ALL",
        ]
        if self.network is NetworkMode.NONE:
            argv.append("--unshare-net")
        for binding in self.remotes:
            argv.extend(
                [
                    "--bind" if binding.mode is AccessMode.READ_WRITE else "--ro-bind",
                    str(binding.host_path),
                    binding.target,
                ]
            )
        for socket_path in self.socket_paths:
            # AF_UNIX clients need a writable bind mount to connect; the bind is
            # still exact-path and namespace-local, so the host pathname cannot
            # be replaced from inside the sandbox.
            argv.extend(["--bind", str(socket_path), str(socket_path)])
        if self.projected_home is not None:
            argv.extend(
                [
                    "--bind" if self.projected_home_writable else "--ro-bind",
                    str(self.projected_home),
                    "/home/sandbox",
                ]
            )
        if self.session_socket is not None:
            argv.extend(
                [
                    "--dir",
                    "/run",
                    "--dir",
                    "/run/astral-project",
                    "--setenv",
                    "ASPR_SESSION_SOCKET",
                    "/run/astral-project/session.sock",
                    "--setenv",
                    "ASPR_SESSION_ID",
                    self.session_id or "",
                ]
            )
        argv.extend(["--", *self.command])
        return argv


def _target(value: str) -> str:
    path = PurePosixPath(value)
    if (
        not value.startswith("/")
        or value == "/"
        or "\x00" in value
        or ".." in path.parts
        or str(path) != value
        or len(value.encode()) > 4096
        or any(len(part.encode()) > 255 for part in path.parts)
    ):
        raise _error("sandbox target must be absolute normalized non-root path")
    return value


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PATH_RESOLUTION,
        message=message,
        security_result="sandbox was not started",
        unsafe_reason="sandbox paths and authority must be fixed before execution",
        next_action="inspect sandbox arguments and retry with bounded paths",
    )
