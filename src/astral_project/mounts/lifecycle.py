"""Daemon-owned rclone mount creation, shutdown, and recovery."""

from __future__ import annotations

import json
import os
import secrets
import signal
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import SessionId
from astral_project.core.paths import ensure_private_directory
from astral_project.crypto.grants import AccessMode, SignedGrant
from astral_project.state.sqlite import StateDatabase


class MountState(StrEnum):
    CREATING = "creating"
    READY = "ready"
    DRAINING = "draining"
    FAILED = "failed"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class RemoteMount:
    mount_id: str
    session_id: str
    grant_id: str
    mount_path: Path
    state: MountState
    mode: AccessMode
    virtual_target: str
    pid: int | None
    config_path: Path
    cache_path: Path
    transport_capability: str
    failure_reason: str | None = None
    flush_warning: str | None = None


class MountManager:
    """Own every rclone process and every ephemeral mount credential."""

    def __init__(
        self,
        database: StateDatabase,
        runtime: Path,
        *,
        rclone_binary: Path = Path("/usr/bin/rclone"),
        transport_program: Path = Path("/usr/libexec/astral-project/aspr-transport"),
        fusermount_binary: Path = Path("/usr/bin/fusermount3"),
        ssh_binary: Path = Path("/usr/bin/ssh"),
        readiness_timeout: float = 30.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not rclone_binary.is_absolute() or not transport_program.is_absolute():
            raise _error("mount executable paths must be absolute")
        if readiness_timeout <= 0:
            raise _error("mount readiness timeout must be positive")
        self.database = database
        self.runtime = runtime
        self.rclone_binary = rclone_binary
        self.transport_program = transport_program
        self.fusermount_binary = fusermount_binary
        self.ssh_binary = ssh_binary
        self.readiness_timeout = readiness_timeout
        self.clock = clock
        self._processes: dict[str, subprocess.Popen[bytes]] = {}
        self._transports: dict[str, tuple[object, threading.Thread]] = {}

    def open(
        self,
        *,
        session_id: str,
        signed_grant: SignedGrant,
        mount_path: Path,
        virtual_target: str,
        host: str,
        identity_file: Path,
        port: int,
        mode: AccessMode | None = None,
    ) -> RemoteMount:
        """Create a private config, start fixed rclone, and require positive readiness."""
        now = int(self.clock())
        grant = signed_grant.grant
        if (
            not virtual_target.startswith("/")
            or "\x00" in virtual_target
            or str(PurePosixPath(virtual_target)) != virtual_target
            or any(part in {".", ".."} for part in virtual_target.split("/"))
            or (virtual_target != "/" and virtual_target.endswith("/"))
        ):
            raise _error("mount target path is not normalized", ErrorCode.DAEMON_AUTH)
        if self.database.grant_is_revoked(str(grant.grant_id)):
            raise _error("revoked grant cannot create a mount", ErrorCode.DAEMON_AUTH)
        if now < grant.not_before or now >= grant.expires_at:
            raise _error("expired grant cannot create a mount", ErrorCode.CRYPTO_CONTEXT)
        matches = [
            item for item in grant.exports if _path_contains(item.virtual_target, virtual_target)
        ]
        if not matches:
            raise _error("mount target is outside signed grant", ErrorCode.DAEMON_AUTH)
        longest = max(len(item.virtual_target) for item in matches)
        selected = [item for item in matches if len(item.virtual_target) == longest]
        if len(selected) != 1:
            raise _error("mount target selects ambiguous signed exports", ErrorCode.DAEMON_AUTH)
        export = selected[0]
        if mode is not None and not isinstance(mode, AccessMode):
            raise _error("mount mode is invalid")
        requested_mode = export.access_mode if mode is None else mode
        if requested_mode is AccessMode.READ_WRITE and export.access_mode is AccessMode.READ_ONLY:
            raise _error("read-write mount exceeds read-only grant", ErrorCode.DAEMON_AUTH)
        _validate_mountpoint(mount_path)
        if not identity_file.is_absolute() or not identity_file.exists():
            raise _error("mount identity file is unavailable", ErrorCode.DAEMON_AUTH)
        ensure_private_directory(self.runtime)
        mount_id = secrets.token_hex(16)
        config_path = self.runtime / f"mount-{mount_id}.conf"
        cache_path = self.runtime / f"cache-{mount_id}"
        ensure_private_directory(cache_path)
        from astral_project.rclone.listing import SftpRemoteConfig, write_sftp_config
        from astral_project.session.contracts import RemoteSessionRequestV1
        from astral_project.transport.local import (
            PrivateTransportServer,
            ProcessStream,
            TransportCapability,
            open_remote_sftp_stream,
        )

        remote = SftpRemoteConfig(
            host=host,
            remote_user=grant.remote_user,
            identity_file=identity_file,
            transport_program=self.transport_program,
            port=port,
        )
        write_sftp_config(config_path, remote)
        record = {
            "mount_id": mount_id,
            "session_id": session_id,
            "grant_id": str(grant.grant_id),
            "mount_path": str(mount_path),
            "state": MountState.CREATING.value,
            "mode": requested_mode.value,
            "virtual_target": virtual_target,
            "pid": None,
            "config_path": str(config_path),
            "cache_path": str(cache_path),
            "transport_capability": "rclone_sftp_external_ssh_v1",
            "created_at": now,
            "updated_at": now,
        }
        try:
            self.database.create_mount_runtime(record)
            capability = TransportCapability.create(self.runtime / "t")
            stream_lock = threading.Lock()

            def open_stream() -> ProcessStream:
                with stream_lock:
                    return open_remote_sftp_stream(
                        RemoteSessionRequestV1(
                            SessionId(str(uuid.uuid4())), os.urandom(32), signed_grant
                        ),
                        ssh_binary=self.ssh_binary,
                        identity_file=identity_file,
                        host=host,
                        remote_user=grant.remote_user,
                        port=port,
                    )

            transport_server = PrivateTransportServer(capability, open_stream)
            transport_server.start()
            transport_thread = threading.Thread(target=transport_server.serve_forever, daemon=True)
            transport_thread.start()
            self._transports[mount_id] = (transport_server, transport_thread)
            rc_socket = self.runtime / f"rc-{mount_id}.sock"
            argv = self._argv(
                config_path, cache_path, virtual_target, mount_path, requested_mode, rc_socket
            )
            process = subprocess.Popen(
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env={
                    **{
                        key: value
                        for key, value in os.environ.items()
                        if not key.startswith("RCLONE_")
                    },
                    **capability.environment.as_dict(),
                },
                start_new_session=True,
                close_fds=True,
            )
            self._processes[mount_id] = process
            self.database.update_mount_runtime(
                mount_id, pid=process.pid, updated_at=int(self.clock())
            )
            self._wait_ready(mount_id, mount_path, process)
            self.database.update_mount_runtime(
                mount_id, state=MountState.READY.value, updated_at=int(self.clock())
            )
            _create_authority_marker(mount_path, mount_id)
            return self._record(mount_id)
        except Exception as error:
            self._fail(mount_id, process if "process" in locals() else None, str(error))
            raise

    def close(self, mount_id: str, *, flush_timeout: float = 10.0) -> RemoteMount:
        """Drain, unmount, and terminate; never report clean close after a failed flush."""
        if flush_timeout <= 0:
            raise _error("flush timeout must be positive")
        record = self._record(mount_id)
        if record.state is MountState.CLOSED:
            return record
        self.database.update_mount_runtime(
            mount_id, state=MountState.DRAINING.value, updated_at=int(self.clock())
        )
        rc_socket = self.runtime / f"rc-{mount_id}.sock"
        try:
            self._wait_for_vfs_uploads(rc_socket, flush_timeout)
            self._unmount(record.mount_path, flush_timeout)
        except Exception as error:
            warning = f"possible unflushed writes: {error}"
            self.database.update_mount_runtime(
                mount_id,
                state=MountState.DRAINING.value,
                updated_at=int(self.clock()),
                flush_warning=warning,
            )
            return self._record(mount_id)
        process = self._processes.pop(mount_id, None)
        if process is None and record.pid is not None:
            _terminate_pid(record.pid, flush_timeout)
        elif process is not None:
            try:
                process.wait(timeout=flush_timeout)
            except subprocess.TimeoutExpired:
                _terminate(process, flush_timeout)
        self._close_transport(mount_id)
        _remove_authority_marker(record.mount_path, mount_id)
        self.database.update_mount_runtime(
            mount_id,
            state=MountState.CLOSED.value,
            pid=None,
            ended_at=int(self.clock()),
            updated_at=int(self.clock()),
            flush_warning=None,
        )
        _unlink_private(record.config_path)
        _unlink_private(rc_socket)
        _remove_private_tree(record.cache_path)
        return self._record(mount_id)

    def health(self, mount_id: str) -> RemoteMount:
        record = self._record(mount_id)
        grant = self.database.signed_grant(record.grant_id).grant
        if self.database.grant_is_revoked(record.grant_id) or int(self.clock()) >= grant.expires_at:
            return self.close(mount_id)
        process = self._processes.get(mount_id)
        alive = (
            process is not None and process.poll() is None
            if process is not None
            else record.pid is not None and _pid_alive(record.pid)
        )
        if record.state is MountState.READY and (
            not alive or not os.path.ismount(record.mount_path)
        ):
            self.database.update_mount_runtime(
                mount_id,
                state=MountState.FAILED.value,
                updated_at=int(self.clock()),
                failure_reason="rclone process or mount disappeared",
            )
            return self._record(mount_id)
        return record

    def recover(self) -> tuple[RemoteMount, ...]:
        """Reconcile durable records after daemon restart; stale resources fail closed."""
        recovered: list[RemoteMount] = []
        for raw in self.database.list_mount_runtime():
            record = self._record(str(raw["mount_id"]))
            if record.state not in {MountState.CREATING, MountState.READY, MountState.DRAINING}:
                recovered.append(record)
                continue
            alive = record.pid is not None and _pid_alive(record.pid)
            failure_reason = "daemon restart found stale mount"
            if alive and os.path.ismount(record.mount_path):
                assert record.pid is not None
                failure_reason = "daemon restart cannot reattach private transport"
                with suppress(AstralError):
                    self._unmount(record.mount_path, 5.0)
                _terminate_pid(record.pid, 5.0)
            self.database.update_mount_runtime(
                record.mount_id,
                state=MountState.FAILED.value,
                updated_at=int(self.clock()),
                failure_reason=failure_reason,
                pid=None,
            )
            _unlink_private(record.config_path)
            _remove_private_tree(record.cache_path)
            recovered.append(self._record(record.mount_id))
        return tuple(recovered)

    def enforce_grant_lifecycle(self) -> tuple[RemoteMount, ...]:
        """Close mounts whose grant expired or was revoked."""
        closed: list[RemoteMount] = []
        now = int(self.clock())
        for record in self.database.list_mount_runtime():
            mount = self._record(str(record["mount_id"]))
            grant = self.database.signed_grant(mount.grant_id).grant
            if self.database.grant_is_revoked(mount.grant_id) or now >= grant.expires_at:
                closed.append(self.close(mount.mount_id))
        return tuple(closed)

    def _argv(
        self,
        config: Path,
        cache: Path,
        target: str,
        mount_path: Path,
        mode: AccessMode,
        rc_socket: Path | None = None,
    ) -> list[str]:
        argv = [
            str(self.rclone_binary),
            "mount",
            f"aspr-session:{target}",
            str(mount_path),
            "--config",
            str(config),
            "--cache-dir",
            str(cache),
            "--log-level",
            "ERROR",
            "--log-file",
            str(cache / "rclone.log"),
            "--sftp-connections",
            "1",
            "--sftp-concurrency",
            "1",
            "--vfs-cache-mode",
            "writes",
            "--vfs-write-back",
            "1s",
            "--dir-cache-time",
            "1s",
        ]
        if rc_socket is not None:
            if not rc_socket.is_absolute():
                raise _error("rclone remote-control socket path is invalid")
            argv.extend(["--rc", "--rc-no-auth", "--rc-addr", f"unix://{rc_socket}"])
        if not isinstance(mode, AccessMode):
            raise _error("mount mode is invalid")
        if mode is AccessMode.READ_ONLY:
            argv.append("--read-only")
        return argv

    def _wait_for_vfs_uploads(self, rc_socket: Path, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        time.sleep(min(1.1, timeout))
        while time.monotonic() < deadline:
            try:
                result = subprocess.run(
                    [
                        str(self.rclone_binary),
                        "rc",
                        "--unix-socket",
                        str(rc_socket),
                        "vfs/stats",
                    ],
                    capture_output=True,
                    check=False,
                    timeout=min(2.0, max(0.1, deadline - time.monotonic())),
                )
                payload = json.loads(result.stdout)
                cache = payload.get("diskCache")
                if result.returncode != 0 or not isinstance(cache, dict):
                    raise _error("rclone VFS upload status is unavailable")
                queued = cache.get("uploadsQueued")
                active = cache.get("uploadsInProgress")
                if not isinstance(queued, int) or not isinstance(active, int):
                    raise _error("rclone VFS upload status is invalid")
                if queued == 0 and active == 0:
                    return
                if queued > 0:
                    queue_result = subprocess.run(
                        [
                            str(self.rclone_binary),
                            "rc",
                            "--unix-socket",
                            str(rc_socket),
                            "vfs/queue",
                        ],
                        capture_output=True,
                        check=False,
                        timeout=min(2.0, max(0.1, deadline - time.monotonic())),
                    )
                    queue_payload = json.loads(queue_result.stdout)
                    queue = queue_payload.get("queue")
                    if queue_result.returncode != 0 or not isinstance(queue, list):
                        raise _error("rclone VFS upload queue is unavailable")
                    for item in queue:
                        if not isinstance(item, dict) or not isinstance(item.get("id"), int):
                            raise _error("rclone VFS upload queue is invalid")
                        expiry_result = subprocess.run(
                            [
                                str(self.rclone_binary),
                                "rc",
                                "--unix-socket",
                                str(rc_socket),
                                "vfs/queue-set-expiry",
                                f"id={item['id']}",
                                "expiry=0",
                            ],
                            capture_output=True,
                            check=False,
                            timeout=min(2.0, max(0.1, deadline - time.monotonic())),
                        )
                        if expiry_result.returncode != 0:
                            detail = expiry_result.stderr.decode("utf-8", "replace").strip()
                            raise _error(
                                "rclone VFS upload expiry update failed: "
                                f"{detail or 'unknown error'}"
                            )
            except (
                OSError,
                subprocess.TimeoutExpired,
                subprocess.CalledProcessError,
                json.JSONDecodeError,
            ) as error:
                raise _error("rclone VFS upload status could not be read") from error
            time.sleep(0.05)
        raise _error("rclone VFS writes did not drain before close", ErrorCode.DAEMON_UNAVAILABLE)

    def _wait_ready(
        self, mount_id: str, mount_path: Path, process: subprocess.Popen[bytes]
    ) -> None:
        deadline = time.monotonic() + self.readiness_timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                detail = process.stderr.read().decode("utf-8", "replace") if process.stderr else ""
                raise _error(
                    f"rclone mount exited before readiness: {detail}", ErrorCode.DAEMON_UNAVAILABLE
                )
            if os.path.ismount(mount_path):
                return
            time.sleep(0.05)
        raise _error("rclone mount did not become ready", ErrorCode.DAEMON_UNAVAILABLE)

    def _unmount(self, mount_path: Path, timeout: float) -> None:
        if not os.path.ismount(mount_path):
            return
        result = subprocess.run(
            [str(self.fusermount_binary), "-u", str(mount_path)],
            capture_output=True,
            check=False,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise _error(
                f"unmount failed: {result.stderr.decode('utf-8', 'replace')}",
                ErrorCode.DAEMON_UNAVAILABLE,
            )
        deadline = time.monotonic() + timeout
        while os.path.ismount(mount_path) and time.monotonic() < deadline:
            time.sleep(0.05)
        if os.path.ismount(mount_path):
            raise _error(
                "unmount returned success but mount remains attached",
                ErrorCode.DAEMON_UNAVAILABLE,
            )

    def _fail(self, mount_id: str, process: subprocess.Popen[bytes] | None, reason: str) -> None:
        if process is not None:
            _terminate(process, 1.0)
        self._processes.pop(mount_id, None)
        self._close_transport(mount_id)
        _unlink_private(self.runtime / f"rc-{mount_id}.sock")
        with suppress(AstralError):
            self.database.update_mount_runtime(
                mount_id,
                state=MountState.FAILED.value,
                pid=None,
                updated_at=int(self.clock()),
                failure_reason=reason,
            )

    def _close_transport(self, mount_id: str) -> None:
        transport = self._transports.pop(mount_id, None)
        if transport is None:
            return
        server, thread = transport
        server.close()  # type: ignore[attr-defined]
        thread.join(timeout=5)

    def _record(self, mount_id: str) -> RemoteMount:
        raw = self.database.mount_runtime(mount_id)
        try:
            state = MountState(str(raw["state"]))
            mode = AccessMode(str(raw["mode"]))
        except ValueError as error:
            raise _error("mount runtime state or mode is invalid") from error
        return RemoteMount(
            mount_id=mount_id,
            session_id=str(raw["session_id"]),
            grant_id=str(raw["grant_id"]),
            mount_path=Path(str(raw["mount_path"])),
            state=state,
            mode=mode,
            virtual_target=str(raw["virtual_target"]),
            pid=None if raw["pid"] is None else int(str(raw["pid"])),
            config_path=Path(str(raw["config_path"])),
            cache_path=Path(str(raw["cache_path"])),
            transport_capability=str(raw["transport_capability"]),
            failure_reason=None if raw["failure_reason"] is None else str(raw["failure_reason"]),
            flush_warning=None if raw["flush_warning"] is None else str(raw["flush_warning"]),
        )


def _path_contains(root: str, value: str) -> bool:
    return root == value or root == "/" or value.startswith(root.rstrip("/") + "/")


def _error(message: str, code: ErrorCode = ErrorCode.DAEMON_PROTOCOL) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="remote mount was not changed or was closed conservatively",
        unsafe_reason="mount authority and writeback state must remain daemon-owned",
        next_action="inspect `aspr session show` and retry after repairing dependency",
    )


def _validate_mountpoint(path: Path) -> None:
    if not path.is_absolute() or "\x00" in str(path) or not path.exists() or not path.is_dir():
        raise _error("mountpoint must be an existing absolute directory")
    details = path.stat()
    if details.st_uid != os.getuid() or details.st_mode & 0o077:
        raise _error("mountpoint must be owned by caller and private")
    if os.path.ismount(path):
        raise _error("mountpoint is already mounted")


def _terminate(process: subprocess.Popen[bytes], timeout: float) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=timeout)


def _authority_marker(mount_path: Path, mount_id: str) -> Path:
    return mount_path.parent / f".aspr-mount-{mount_id}"


def _create_authority_marker(mount_path: Path, mount_id: str) -> None:
    marker = _authority_marker(mount_path, mount_id)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(marker, flags, 0o600)
        try:
            os.write(descriptor, mount_id.encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, UnicodeEncodeError) as error:
        with suppress(OSError, UnicodeEncodeError):
            marker.unlink(missing_ok=True)
        raise _error("daemon mount authority marker could not be created") from error


def _remove_authority_marker(mount_path: Path, mount_id: str) -> None:
    _authority_marker(mount_path, mount_id).unlink(missing_ok=True)


def _terminate_pid(pid: int, timeout: float) -> None:
    with suppress(ProcessLookupError):
        os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + max(0.0, timeout)
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.05)
    if _pid_alive(pid):
        with suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
        kill_deadline = time.monotonic() + max(timeout, 0.1)
        while _pid_alive(pid) and time.monotonic() < kill_deadline:
            time.sleep(0.05)
        if _pid_alive(pid):
            raise _error("mount child did not terminate", ErrorCode.DAEMON_UNAVAILABLE)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _unlink_private(path: Path) -> None:
    with suppress(FileNotFoundError):
        path.unlink()


def _remove_private_tree(path: Path) -> None:
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_dir():
            _remove_private_tree(child)
        else:
            _unlink_private(child)
    with suppress(OSError):
        path.rmdir()
