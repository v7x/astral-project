"""Supervise projected-home FUSE process and clean stale mounts."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

from astral_project.homed.fuse import FuseUnavailable, cleanup_stale_mount
from astral_project.profile import Profile


class ProjectedHomeProcess:  # pragma: no cover - exercised by installed FUSE acceptance
    """One daemon-owned projected-home mount bound for one sandbox lifetime."""

    def __init__(self, mountpoint: Path, process: subprocess.Popen[bytes]) -> None:
        self.mountpoint = mountpoint
        self.process = process

    @classmethod
    def start(
        cls,
        runtime: Path,
        *,
        timeout: float = 5.0,
        root: Path | None = None,
        profile: Profile | None = None,
        mediation_socket: Path | None = None,
        session_id: str = "default",
        storage_root: Path | None = None,
        overlay_root: Path | None = None,
    ) -> ProjectedHomeProcess:
        if root is not None and profile is None:
            raise ValueError("host projected home requires root and profile together")
        if root is None and profile is not None and storage_root is None:
            raise ValueError("host projected home requires root and profile together")
        if (storage_root is not None or overlay_root is not None) and profile is None:
            raise ValueError("writable projected home requires a profile")
        if overlay_root is not None and root is None:
            raise ValueError("overlay projected home requires a lower root")
        if not session_id:
            raise ValueError("projected home session identity is required")
        mountpoint = Path(temp_dir(runtime, "projected-home-"))
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
        environment["ASPR_HOMED_MOUNTPOINT"] = str(mountpoint)
        environment["ASPR_HOMED_SESSION_ID"] = session_id
        if root is not None:
            environment["ASPR_HOMED_ROOT"] = os.fspath(root)
        if profile is not None:
            environment["ASPR_HOMED_PROFILE"] = profile.to_toml()
        if storage_root is not None:
            environment["ASPR_HOMED_STORAGE_ROOT"] = os.fspath(storage_root)
        if overlay_root is not None:
            environment["ASPR_HOMED_OVERLAY_ROOT"] = os.fspath(overlay_root)
        if mediation_socket is not None:
            environment["ASPR_HOMED_MEDIATION_SOCKET"] = os.fspath(mediation_socket)
        program = Path("/usr/libexec/astral-project/aspr-homed")
        if not program.is_file() or not os.access(program, os.X_OK):
            raise FuseUnavailable("installed aspr-homed runtime is unavailable")
        process = subprocess.Popen(
            [os.fspath(program)],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if mountpoint.is_mount():
                return cls(mountpoint, process)
            if process.poll() is not None:
                diagnostic = (
                    process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
                )
                mountpoint.rmdir()
                if "pyfuse3 is not installed" in diagnostic:
                    raise FuseUnavailable(diagnostic.strip())
                raise OSError("aspr-homed exited before mounting: " + diagnostic.strip())
            time.sleep(0.05)
        cls._terminate(process)
        cleanup_stale_mount(mountpoint)
        mountpoint.rmdir()
        raise TimeoutError("aspr-homed did not mount within startup deadline")

    def healthy(self) -> bool:
        """Daemon death revokes projected-home authority immediately."""
        return self.process.poll() is None and self.mountpoint.is_mount()

    def close(self) -> None:
        self._terminate(self.process)
        cleanup_stale_mount(self.mountpoint)
        from contextlib import suppress

        with suppress(OSError):
            self.mountpoint.rmdir()

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2.0)


def temp_dir(runtime: Path, prefix: str) -> str:  # pragma: no cover - lifecycle helper
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    import tempfile

    return tempfile.mkdtemp(prefix=prefix, dir=runtime)
