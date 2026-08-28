"""Same-UID local daemon control socket."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import selectors
import socket
import stat
import struct
import subprocess
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from astral_project.audit.events import PathMode
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import ensure_private_directory
from astral_project.crypto.grants import AccessMode, SignedGrant
from astral_project.crypto.keys import public_key_from_bytes
from astral_project.daemon.protocol import encode, make_response, parse_request, receive
from astral_project.namespace.planner import build_namespace_plan
from astral_project.sandbox.hardening import (
    HardeningError,
    HardeningPolicy,
    HardeningStatus,
    RootRole,
    dependency_versions,
    enforce,
)
from astral_project.sandbox.hardening import (
    status as hardening_status,
)
from astral_project.session.listing import SessionListingScope
from astral_project.state.sqlite import ActiveListingSession, StateDatabase
from astral_project.transport.local import fixed_ssh_audit_argv

if TYPE_CHECKING:
    from astral_project.mounts import MountManager


_REMOTE_AUDIT_RESPONSE_LIMIT = 1024 * 1024


class _RemoteAuditOutputTooLarge(ValueError):
    """Raised before remote audit output can exceed its bounded buffer."""


def _bounded_remote_audit_run(
    argv: list[str], *, input_data: bytes, env: Mapping[str, str], timeout: float
) -> tuple[int, bytes]:
    """Run the enrolled transport while bounding stdout before buffering it."""
    process = subprocess.Popen(
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=dict(env),
    )
    assert process.stdin is not None and process.stdout is not None
    selector = selectors.DefaultSelector()
    output = bytearray()
    try:
        process.stdin.write(input_data)
        process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            if not selector.select(remaining):
                raise subprocess.TimeoutExpired(argv, timeout)
            chunk = os.read(
                process.stdout.fileno(),
                min(65536, _REMOTE_AUDIT_RESPONSE_LIMIT + 1 - len(output)),
            )
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > _REMOTE_AUDIT_RESPONSE_LIMIT:
                raise _RemoteAuditOutputTooLarge("remote audit export response is too large")
        returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        return returncode, bytes(output)
    except BaseException:
        with suppress(OSError):
            process.kill()
        with suppress(OSError):
            process.wait()
        raise
    finally:
        selector.close()


@dataclass(frozen=True, slots=True)
class DaemonPaths:
    runtime: Path
    state: Path

    @property
    def socket(self) -> Path:
        return self.runtime / "daemon.sock"

    @property
    def lock(self) -> Path:
        return self.runtime / "daemon.lock"


def _error(code: ErrorCode, message: str) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="daemon operation was rejected",
        unsafe_reason="main daemon control requires private same-user IPC",
        next_action="run `aspr doctor` and repair private runtime state",
    )


def _socket_runtime_path(runtime: Path) -> Path:
    return runtime.with_name(f"{runtime.name}-sockets")


def _check_private_socket(path: Path) -> None:
    details = path.lstat()
    if (
        not stat.S_ISSOCK(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_mode & 0o077
    ):
        raise _error(ErrorCode.DAEMON_STARTUP, "daemon socket has unsafe ownership, type, or mode")


def peer_uid(connection: socket.socket) -> int:
    """Read Linux peer UID; no fallback exists for trusted daemon IPC."""
    credentials = connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
    )
    return int(struct.unpack("3i", credentials)[1])


class DaemonLock:
    """Advisory lock whose kernel lifetime prevents daemon-start races."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._descriptor: int | None = None

    def acquire(self) -> None:
        try:
            descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            with suppress(UnboundLocalError):
                os.close(descriptor)
            raise _error(ErrorCode.DAEMON_STARTUP, "another daemon owns startup lock") from error
        self._descriptor = descriptor

    def close(self) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None


def _path_contains(root: str, value: str) -> bool:
    return root == value or root == "/" or value.startswith(root.rstrip("/") + "/")


def _select_source_export(grant: SignedGrant, source: str) -> tuple[object, str]:
    if (
        not source.startswith("/")
        or "\x00" in source
        or str(PurePosixPath(source)) != source
        or any(part in {".", ".."} for part in source.split("/"))
        or (source != "/" and source.endswith("/"))
    ):
        raise _error(ErrorCode.DAEMON_AUTH, "remote source path is not normalized")
    matches = [
        export for export in grant.grant.exports if _path_contains(export.requested_source, source)
    ]
    if not matches:
        raise _error(ErrorCode.DAEMON_AUTH, "remote source is outside selected signed export")
    longest = max(len(export.requested_source) for export in matches)
    selected = [export for export in matches if len(export.requested_source) == longest]
    if len(selected) != 1:
        raise _error(ErrorCode.DAEMON_AUTH, "remote source selects ambiguous signed exports")
    export = selected[0]
    suffix = source[len(export.requested_source) :]
    virtual_target = export.virtual_target.rstrip("/") + suffix or "/"
    return export, virtual_target


def _mount_payload(mount: object) -> Mapping[str, object]:
    from astral_project.mounts import RemoteMount

    if not isinstance(mount, RemoteMount):
        raise _error(ErrorCode.DAEMON_PROTOCOL, "mount response is invalid")
    return {
        "mount_id": mount.mount_id,
        "session_id": mount.session_id,
        "grant_id": mount.grant_id,
        "mount_path": str(mount.mount_path),
        "state": mount.state.value,
        "mode": mount.mode.value,
        "virtual_target": mount.virtual_target,
        "pid": mount.pid,
        "config_path": str(mount.config_path),
        "cache_path": str(mount.cache_path),
        "transport_capability": mount.transport_capability,
        "failure_reason": mount.failure_reason,
        "flush_warning": mount.flush_warning,
    }


class DaemonServer:
    """Small control daemon; only liveness/status operations exist in Packet 5."""

    def __init__(
        self,
        paths: DaemonPaths,
        *,
        listing_handler: Callable[[Mapping[str, object]], Mapping[str, object]] | None = None,
        listing_scope: SessionListingScope | None = None,
        rclone_binary: Path = Path("/usr/bin/rclone"),
        transport_program: Path = Path("/usr/libexec/astral-project/aspr-transport"),
        ssh_binary: Path = Path("/usr/bin/ssh"),
    ) -> None:
        self.paths = paths
        self._rclone_binary = rclone_binary
        self._transport_program = transport_program
        self._ssh_binary = ssh_binary
        requires_listing_scope = listing_handler is None
        if listing_handler is None:

            def default_listing_handler(payload: Mapping[str, object]) -> Mapping[str, object]:
                return self._default_listing_handler(payload)

            listing_handler = default_listing_handler
        self._listing_handler = listing_handler
        self._requires_listing_scope = requires_listing_scope
        self._listing_scope = listing_scope
        self._listing_session: ActiveListingSession | None = None
        self._listener: socket.socket | None = None
        self._lock = DaemonLock(paths.lock)
        self._database: StateDatabase | None = None
        self._mounts: MountManager | None = None
        self._hardening: HardeningStatus | None = None

    def start(self) -> None:
        ensure_private_directory(self.paths.runtime)
        self._lock.acquire()
        try:
            self._repair_stale_socket()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(self.paths.socket))
            os.chmod(self.paths.socket, 0o600)
            _check_private_socket(self.paths.socket)
            listener.listen()
            listener.settimeout(1.0)
            self._listener = listener
            from astral_project.mounts import MountManager

            self._database = StateDatabase.open(self.paths.state)
            hardening = hardening_status(required=True)
            self._hardening = hardening
            self._database.record_audit(
                "hardening.status",
                "daemon",
                "local",
                hardening.to_dict(),
            )
            if not hardening.landlock_available:
                self._database.record_audit(
                    "hardening.failure",
                    "process",
                    "local-daemon",
                    {"error_code": ErrorCode.HARDENING_UNAVAILABLE.string},
                )
                raise _error(ErrorCode.HARDENING_UNAVAILABLE, hardening.reason)
            try:
                ssh_state = Path.home() / ".ssh"
                socket_runtime = _socket_runtime_path(self.paths.runtime)
                ensure_private_directory(socket_runtime)
                roots: list[tuple[Path, RootRole | bool]] = [
                    (self.paths.runtime, True),
                    (self.paths.state.parent, True),
                    (socket_runtime, RootRole.SOCKET_RUNTIME),
                ]
                if ssh_state.exists():  # pragma: no branch - optional SSH trust root
                    roots.append((ssh_state, False))
                enforced = enforce(HardeningPolicy.for_plan(tuple(roots)))
                self._hardening = enforced
            except HardeningError as error:
                self._database.record_audit(
                    "hardening.failure",
                    "process",
                    "local-daemon",
                    {"error_code": error.code.string},
                )
                raise
            self._database.record_audit(
                "hardening.enforced",
                "process",
                "local-daemon",
                enforced.to_dict(),
            )
            self._mounts = MountManager(
                self._database,
                self.paths.runtime,
                rclone_binary=self._rclone_binary,
                transport_program=self._transport_program,
                readiness_timeout=30.0,
                socket_runtime=socket_runtime,
            )
            if hasattr(self._database, "list_mount_runtime"):
                self._mounts.recover()
            if self._requires_listing_scope and self._listing_scope is None:
                self._listing_session = self._database.active_listing_session()
                if self._listing_session is not None:
                    grant = self._listing_session.signed_grant.grant
                    self._listing_scope = SessionListingScope(
                        str(grant.grant_id),
                        tuple(export.virtual_target for export in grant.exports),
                    )
        except Exception:
            self.close()
            raise

    def _default_listing_handler(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        from astral_project.rclone.listing import daemon_bound_listing_handler

        session = self._listing_session
        if session is None:
            raise _error(ErrorCode.DAEMON_AUTH, "no active remote session is available")
        metadata = session.host_metadata
        address = metadata.get("address")
        identity = metadata.get("identity_file")
        port = metadata.get("port", 22)
        if (
            not isinstance(address, str)
            or not isinstance(identity, str)
            or not isinstance(port, int)
            or isinstance(port, bool)
        ):
            raise _error(ErrorCode.STATE_CORRUPT, "active host transport metadata is invalid")
        if session.signed_grant.grant.host_id.value != session.host_id:
            raise _error(ErrorCode.DAEMON_AUTH, "active grant host binding is invalid")
        if session.signed_grant.grant.remote_user != session.remote_user:
            raise _error(ErrorCode.DAEMON_AUTH, "active grant user binding is invalid")
        if self._database is not None:
            self._database.record_audit(
                "transport.started",
                "session",
                session.session_id,
                {"grant_id": session.signed_grant.grant.grant_id.value},
            )
        try:
            result = daemon_bound_listing_handler(
                payload,
                session_id=session.session_id,
                signed_grant=session.signed_grant,
                host=address,
                remote_user=session.remote_user,
                identity_file=Path(identity),
                port=port,
                binary=self._rclone_binary,
                runtime=self.paths.runtime,
                socket_runtime=_socket_runtime_path(self.paths.runtime),
                transport_program=self._transport_program,
                ssh_binary=self._ssh_binary,
            )
        except Exception as error:
            if self._database is not None:
                self._database.record_audit(
                    "transport.failed",
                    "session",
                    session.session_id,
                    {"error_type": type(error).__name__},
                )
                self._database.record_audit(
                    "degraded.mode",
                    "session",
                    session.session_id,
                    {"reason": "transport failure"},
                )
            raise
        if self._database is not None:
            self._database.record_audit(
                "transport.completed",
                "session",
                session.session_id,
                {
                    "effective_export_hash": hashlib.sha256(
                        build_namespace_plan(session.signed_grant.grant).canonical_bytes()
                    ).hexdigest()
                },
            )
        return result

    def _remote_audit_export(self, payload: Mapping[str, object]) -> Mapping[str, object]:
        if self._database is None:
            raise _error(ErrorCode.DAEMON_STARTUP, "state database is unavailable")
        host_id = payload.get("host_id")
        path_mode = payload.get("path_mode", PathMode.REDACT.value)
        if not isinstance(host_id, str) or not isinstance(path_mode, str):
            raise _error(ErrorCode.DAEMON_PROTOCOL, "remote audit export fields are invalid")
        if path_mode not in {PathMode.REDACT.value, PathMode.HASH.value}:
            raise _error(ErrorCode.DAEMON_PROTOCOL, "remote audit export path mode is invalid")
        remote_user, metadata = self._database.host_transport(host_id)
        address = metadata.get("address")
        identity = metadata.get("identity_file")
        port = metadata.get("port", 22)
        known_hosts = metadata.get("known_hosts")
        if (
            not isinstance(address, str)
            or not isinstance(identity, str)
            or not isinstance(port, int)
            or isinstance(port, bool)
            or (known_hosts is not None and not isinstance(known_hosts, str))
        ):
            raise _error(ErrorCode.STATE_CORRUPT, "enrolled host transport metadata is invalid")
        argv = fixed_ssh_audit_argv(
            ssh_binary=self._ssh_binary,
            identity_file=Path(identity),
            host=address,
            remote_user=remote_user,
            port=port,
            known_hosts=None if known_hosts is None else Path(known_hosts),
        )
        try:
            returncode, stdout = _bounded_remote_audit_run(
                argv,
                input_data=json.dumps({"version": 1, "path_mode": path_mode}).encode(),
                timeout=15,
                env={"PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
            )
        except _RemoteAuditOutputTooLarge as error:
            raise _error(
                ErrorCode.DAEMON_PROTOCOL, "remote audit export response is invalid"
            ) from error
        except (OSError, subprocess.TimeoutExpired) as error:
            raise _error(
                ErrorCode.DAEMON_UNAVAILABLE, "remote audit export transport failed"
            ) from error
        if returncode != 0:
            raise _error(ErrorCode.DAEMON_UNAVAILABLE, "remote audit export was rejected")
        try:
            response = json.loads(stdout)
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise _error(
                ErrorCode.DAEMON_PROTOCOL, "remote audit export response is invalid"
            ) from error
        if (
            not isinstance(response, dict)
            or response.get("version") != 1
            or response.get("ok") is not True
            or not isinstance(response.get("export"), str)
            or len(response["export"].encode()) > 1024 * 1024
        ):
            raise _error(ErrorCode.DAEMON_PROTOCOL, "remote audit export response is invalid")
        return {"host_id": host_id, "path_mode": path_mode, "export": response["export"]}

    def serve_forever(self) -> None:
        """Serve until process shutdown; trusted entry point owns lifecycle."""
        while True:
            self.serve_once()

    def serve_once(self) -> None:
        if self._listener is None:
            raise _error(ErrorCode.DAEMON_STARTUP, "daemon is not started")
        try:
            connection, _ = self._listener.accept()
        except TimeoutError:
            self._refresh_lifecycle()
            return
        with connection:
            if peer_uid(connection) != os.getuid():
                return
            request = None
            try:
                request = parse_request(receive(connection))
                self._refresh_lifecycle()
                response = self._response(request.operation, request.payload)
                connection.sendall(encode(make_response(request, ok=True, result=response)))
            except AstralError as error:
                if request is not None:
                    connection.sendall(
                        encode(
                            make_response(
                                request,
                                ok=False,
                                result={
                                    "error_code": error.code.string,
                                    "dependency_error": error.dependency_error,
                                    "message": error.message,
                                },
                            )
                        )
                    )
                else:
                    connection.sendall(
                        encode(
                            {
                                "kind": "error",
                                "message": error.message,
                                "version": 1,
                            }
                        )
                    )

    def _refresh_lifecycle(self) -> None:
        if self._database is None:
            return
        self._database.retire_expired_sessions(now=int(time.time()))
        if self._mounts is not None:
            self._mounts.enforce_grant_lifecycle()
        self._listing_session = self._database.active_listing_session()
        if self._listing_session is None:
            self._listing_scope = None
            return
        grant = self._listing_session.signed_grant.grant
        self._listing_scope = SessionListingScope(
            str(grant.grant_id), tuple(export.virtual_target for export in grant.exports)
        )

    def _response(
        self, operation: str, payload: Mapping[str, object] | None = None
    ) -> Mapping[str, object]:
        if operation == "ping":
            return {"alive": True}
        if operation == "status":
            if self._database is None:
                raise _error(ErrorCode.DAEMON_STARTUP, "state database is unavailable")
            return {
                "alive": True,
                "state_version": self._database.state_version,
                "hardening": (
                    hardening_status(required=True).to_dict()
                    if self._hardening is None
                    else self._hardening.to_dict()
                ),
                "dependencies": dependency_versions(("cbor2", "cryptography")),
            }
        if operation == "cancel":
            return {"cancelled": True}
        if operation == "grant.list":
            if self._database is None:
                raise _error(ErrorCode.DAEMON_STARTUP, "state database is unavailable")
            include_revoked = bool((payload or {}).get("include_revoked", False))
            return {
                "grants": [
                    {
                        "grant_id": item.grant.grant_id.value,
                        "host_id": item.grant.host_id.value,
                        "remote_user": item.grant.remote_user,
                        "expires_at": item.grant.expires_at,
                        "revoked": self._database.grant_is_revoked(item.grant.grant_id.value),
                    }
                    for item in self._database.list_signed_grants(include_revoked=include_revoked)
                ]
            }
        if operation == "grant.show":
            if self._database is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "grant show payload is missing")
            grant = self._database.signed_grant(str(payload.get("grant_id", "")))
            return {
                "grant_id": grant.grant.grant_id.value,
                "cbor_b64": base64.b64encode(grant.to_cbor()).decode("ascii"),
                "revoked": self._database.grant_is_revoked(grant.grant.grant_id.value),
            }
        if operation == "grant.import":
            if self._database is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "grant import payload is missing")
            encoded = payload.get("cbor_b64")
            if not isinstance(encoded, str):
                raise _error(ErrorCode.DAEMON_PROTOCOL, "grant import envelope is invalid")
            issuer_encoded = payload.get("issuer_key_b64")
            if not isinstance(issuer_encoded, str):
                raise _error(ErrorCode.CRYPTO_SIGNATURE, "grant issuer key is missing")
            try:
                signed = SignedGrant.from_cbor(base64.b64decode(encoded, validate=True))
                issuer_key = public_key_from_bytes(base64.b64decode(issuer_encoded, validate=True))
            except (ValueError, TypeError, AstralError) as error:
                raise _error(ErrorCode.GRANT_INVALID, "grant import envelope is invalid") from error
            self._database.import_signed_grant(signed, issuer_key=issuer_key)
            return {"grant_id": signed.grant.grant_id.value, "imported": True}
        if operation == "grant.validate":
            if self._database is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "grant validate payload is missing")
            grant = self._database.signed_grant(str(payload.get("grant_id", "")))
            self._database.validate_signed_grant(
                grant,
                issuer_key=self._database.issuer_public_key(grant.grant.grant_id.value),
                context=self._database.grant_verification_context(
                    grant.grant.grant_id.value, now=int(time.time())
                ),
            )
            self._database.record_audit(
                "grant.validated",
                "grant",
                grant.grant.grant_id.value,
                {"expires_at": grant.grant.expires_at},
            )
            return {
                "grant_id": grant.grant.grant_id.value,
                "signature_verified": True,
                "expires_at": grant.grant.expires_at,
                "revoked": self._database.grant_is_revoked(grant.grant.grant_id.value),
            }
        if operation == "grant.revoke":
            if self._database is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "grant revoke payload is missing")
            grant_id = str(payload.get("grant_id", ""))
            return {
                "grant_id": grant_id,
                "remote_state": self._database.revoke_grant(
                    grant_id, reason=str(payload.get("reason", "user request"))
                ),
            }
        if operation == "audit.remote.export":
            if payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "remote audit export payload is missing")
            return self._remote_audit_export(payload)
        if operation == "audit.list":
            if self._database is None:
                raise _error(ErrorCode.DAEMON_STARTUP, "state database is unavailable")
            return {
                "events": [
                    event.to_dict(path_mode=PathMode.REDACT)
                    for event in self._database.list_audit_events()
                ],
                "chain_errors": list(self._database.audit_chain_errors()),
            }
        if operation == "audit.show":
            if self._database is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "audit show payload is missing")
            event = self._database.audit_event(str(payload.get("event_id", "")))
            return event.to_dict(path_mode=PathMode.REDACT)
        if operation == "audit.export":
            if self._database is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "audit export payload is missing")
            requested_mode = str(payload.get("path_mode", PathMode.REDACT.value))
            try:
                path_mode = PathMode(requested_mode)
            except ValueError as error:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "audit path mode is invalid") from error
            return {"export": self._database.export_audit(path_mode=path_mode)}
        if operation == "audit.record":
            if self._database is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "audit record payload is missing")
            kind = payload.get("kind")
            subject_type = payload.get("subject_type")
            subject_id = payload.get("subject_id")
            event_payload = payload.get("payload")
            if (
                not isinstance(kind, str)
                or not isinstance(subject_type, str)
                or not isinstance(subject_id, str)
                or not isinstance(event_payload, dict)
            ):
                raise _error(ErrorCode.DAEMON_PROTOCOL, "audit record fields are invalid")
            self._database.record_audit(kind, subject_type, subject_id, event_payload)
            return {"recorded": True}
        if operation == "session.open":
            if self._database is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "session open payload is missing")
            session_id = self._database.open_session(str(payload.get("grant_id", "")))
            return {"session_id": session_id, "state": "active"}
        if operation == "session.list":
            if self._database is None:
                raise _error(ErrorCode.DAEMON_STARTUP, "state database is unavailable")
            return {"sessions": list(self._database.list_sessions())}
        if operation == "session.show":
            if self._database is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "session show payload is missing")
            session_id = str(payload.get("session_id", ""))
            matches = [
                item for item in self._database.list_sessions() if item["session_id"] == session_id
            ]
            if not matches:
                raise _error(ErrorCode.DAEMON_AUTH, "session was not found")
            return matches[0]
        if operation == "session.close":
            if self._database is None or payload is None or self._mounts is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "session close service is unavailable")
            session_id = str(payload.get("session_id", ""))
            for item in self._database.list_mount_runtime():
                if str(item["session_id"]) == session_id and str(item["state"]) not in {
                    "closed",
                    "failed",
                }:
                    self._mounts.close(str(item["mount_id"]))
            self._database.close_session(session_id)
            return {"session_id": session_id, "state": "closed"}
        if operation == "mount.open":
            if self._database is None or self._mounts is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "mount service is unavailable")
            session = self._database.active_listing_session()
            if session is None:
                raise _error(ErrorCode.DAEMON_AUTH, "no active session is available")
            metadata = session.host_metadata
            address = metadata.get("address")
            identity = metadata.get("identity_file")
            port = metadata.get("port", 22)
            if (
                not isinstance(address, str)
                or not isinstance(identity, str)
                or not isinstance(port, int)
            ):
                raise _error(ErrorCode.STATE_CORRUPT, "active host transport metadata is invalid")
            try:
                mode = AccessMode(str(payload.get("mode", "ro")))
            except ValueError as error:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "mount mode is invalid") from error
            virtual_target = str(payload.get("virtual_target", ""))
            source_path = payload.get("source_path")
            if isinstance(source_path, str):
                _export, virtual_target = _select_source_export(session.signed_grant, source_path)
            elif source_path is not None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "remote source path is invalid")
            mount = self._mounts.open(
                session_id=session.session_id,
                signed_grant=session.signed_grant,
                mount_path=Path(str(payload.get("mount_path", ""))),
                virtual_target=virtual_target,
                host=address,
                identity_file=Path(identity),
                port=port,
                mode=mode,
            )
            return _mount_payload(mount)
        if operation == "mount.list":
            if self._database is None or self._mounts is None:
                raise _error(ErrorCode.DAEMON_STARTUP, "mount service is unavailable")
            return {
                "mounts": [
                    _mount_payload(self._mounts._record(str(item["mount_id"])))
                    for item in self._database.list_mount_runtime()
                ]
            }
        if operation == "mount.show":
            if self._mounts is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "mount show payload is missing")
            return _mount_payload(self._mounts.health(str(payload.get("mount_id", ""))))
        if operation == "mount.close":
            if self._mounts is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "mount close payload is missing")
            return _mount_payload(self._mounts.close(str(payload.get("mount_id", ""))))
        if operation == "ls":
            if self._listing_handler is None or payload is None:
                raise _error(ErrorCode.DAEMON_PROTOCOL, "listing service is unavailable")
            if self._requires_listing_scope and self._listing_scope is None:
                raise _error(ErrorCode.DAEMON_AUTH, "no active session grants listing authority")
            if self._listing_scope is not None:
                from astral_project.session.listing import constrain_listing_payload

                target, _ = constrain_listing_payload(payload, self._listing_scope)
                scoped_payload = dict(payload)
                scoped_payload["target"] = target
                return self._listing_handler(scoped_payload)
            return self._listing_handler(payload)
        raise _error(ErrorCode.DAEMON_PROTOCOL, "request operation is not permitted")

    def _repair_stale_socket(self) -> None:
        if not self.paths.socket.exists():
            return
        _check_private_socket(self.paths.socket)
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.1)
            probe.connect(str(self.paths.socket))
        except OSError:
            self.paths.socket.unlink()
        else:
            raise _error(ErrorCode.DAEMON_STARTUP, "daemon socket is already active")
        finally:
            probe.close()

    def close(self) -> None:
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        with suppress(FileNotFoundError):
            self.paths.socket.unlink()
        self._lock.close()
