"""Public sandbox command orchestration around daemon-owned remote mounts."""

from __future__ import annotations

import base64
import binascii
import os
import shutil
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from astral_project.approval.terminal import ApprovalController
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import AccessMode, GrantExport, SignedGrant
from astral_project.homed.fuse import FuseUnavailable
from astral_project.homed.lifecycle import ProjectedHomeProcess
from astral_project.homed.mediation import PendingRequest, UnknownPathMediator
from astral_project.profile import Operation, Profile, ProfileError
from astral_project.sandbox.environment import EnvironmentPolicy
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode, RemoteBinding
from astral_project.sandbox.resources import ResourcePolicy
from astral_project.sandbox.runner import hardening_policy, run_plan
from astral_project.sandbox.session_api import SessionApiServer
from astral_project.session.listing import (
    SessionListingScope,
    constrain_session_listing_payload,
)

DaemonRequest = Callable[[str, Mapping[str, object] | None], dict[str, object]]


@dataclass(frozen=True, slots=True)
class RemoteSpec:
    grant_id: str | None
    source: str
    target: str
    mode: AccessMode


@dataclass(frozen=True, slots=True)
class SandboxArguments:
    network: NetworkMode
    grant_id: str | None
    remotes: tuple[RemoteSpec, ...]
    command: tuple[str, ...]
    approval_socket: Path | None = None
    profile_path: Path | None = None
    home_root: Path | None = None
    private_root: Path | None = None
    overlay_root: Path | None = None


def parse_arguments(arguments: Sequence[str]) -> SandboxArguments:
    network: NetworkMode | None = None
    grant_id: str | None = None
    remotes: list[RemoteSpec] = []
    command: tuple[str, ...] = ("/bin/sh",)
    approval_socket: Path | None = None
    profile_path: Path | None = None
    home_root: Path | None = None
    private_root: Path | None = None
    overlay_root: Path | None = None
    index = 1
    while index < len(arguments):
        value = arguments[index]
        if value == "--":
            command = tuple(arguments[index + 1 :])
            if not command:
                raise _error("sandbox command after -- is empty")
            break
        if value == "--network":
            index += 1
            if index >= len(arguments):
                raise _error("--network requires inherit or none")
            try:
                network = NetworkMode(arguments[index])
            except ValueError as error:
                raise _error("--network must be inherit or none") from error
        elif value == "--grant":
            index += 1
            if index >= len(arguments) or not arguments[index]:
                raise _error("--grant requires a grant identifier")
            grant_id = arguments[index]
        elif value == "--remote":
            index += 1
            if index >= len(arguments):
                raise _error("--remote requires GRANT:/source=/target[:ro|rw]")
            remotes.append(_parse_remote(arguments[index]))
        elif value == "--approval-socket":
            index += 1
            if index >= len(arguments):
                raise _error("--approval-socket requires an absolute path")
            approval_socket = Path(arguments[index])
            if not approval_socket.is_absolute():
                raise _error("--approval-socket requires an absolute path")
        elif value == "--profile":
            index += 1
            if index >= len(arguments):
                raise _error("--profile requires an absolute profile file")
            profile_path = Path(arguments[index])
            if not profile_path.is_absolute():
                raise _error("--profile requires an absolute profile file")
        elif value == "--home-root":
            index += 1
            if index >= len(arguments):
                raise _error("--home-root requires an absolute directory")
            home_root = Path(arguments[index])
            if not home_root.is_absolute():
                raise _error("--home-root requires an absolute directory")
        elif value in {"--private-root", "--overlay-root"}:
            index += 1
            if index >= len(arguments):
                raise _error(f"{value} requires an absolute directory")
            writable_root = Path(arguments[index])
            if not writable_root.is_absolute():
                raise _error(f"{value} requires an absolute directory")
            if value == "--private-root":
                private_root = writable_root
            else:
                overlay_root = writable_root
        elif value.startswith("-"):
            raise _error(f"unknown sandbox option {value!r}")
        else:
            raise _error("sandbox command must follow --")
        index += 1
    if network is None:
        raise _error("sandbox requires explicit --network inherit|none")
    inferred = {item.grant_id for item in remotes if item.grant_id is not None}
    if len(inferred) > 1:
        raise _error("sandbox accepts one signed grant in version 1")
    if grant_id is None and inferred:
        grant_id = next(iter(inferred))
    if any(item.grant_id not in {None, grant_id} for item in remotes):
        raise _error("all sandbox remotes must use selected signed grant")
    if remotes and grant_id is None:
        raise _error("--grant is required when --remote omits grant prefix")
    if (profile_path is None) != (home_root is None):
        raise _error("--profile and --home-root must be provided together")
    if (private_root is not None or overlay_root is not None) and (
        profile_path is None or home_root is None
    ):
        raise _error("writable projected home requires --profile and --home-root")
    return SandboxArguments(
        network,
        grant_id,
        tuple(remotes),
        command,
        approval_socket,
        profile_path,
        home_root,
        private_root,
        overlay_root,
    )


def _host_rx_target(profile: Profile | None, command: tuple[str, ...]) -> str | None:
    """Admit a projected-HOME executable only through an explicit host-rx rule."""
    target = command[0]
    prefix = "/home/sandbox/"
    if not target.startswith(prefix):
        return None
    if profile is None:
        raise _error("projected-HOME command requires an explicit profile", ErrorCode.DAEMON_AUTH)
    relative = target.removeprefix(prefix)
    if not relative or not profile.decision(relative, Operation.EXECUTE).allowed:
        raise _error(
            "projected-HOME command lacks an exact host-rx authorization", ErrorCode.DAEMON_AUTH
        )
    return target


def _write_host_rx_manifest(runtime: Path, target: str | None) -> tuple[Path | None, Path | None]:
    """Create one private, exact-command manifest for the native executor."""
    if target is None:
        return None, None
    directory = Path(tempfile.mkdtemp(prefix="sandbox-host-rx-", dir=runtime))
    manifest = directory / "host-rx.allow"
    descriptor = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
    try:
        encoded = (target + "\n").encode("utf-8")
        if os.write(descriptor, encoded) != len(encoded):
            raise _error("host-rx manifest could not be written", ErrorCode.DAEMON_UNAVAILABLE)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return manifest, directory


def _remove_host_rx_directory(directory: Path | None) -> None:
    if directory is not None:
        shutil.rmtree(directory, ignore_errors=True)


def _projected_home_inputs(parsed: SandboxArguments) -> tuple[Profile | None, Path | None]:
    if parsed.profile_path is None or parsed.home_root is None:
        return None, None
    if not parsed.home_root.is_dir():
        raise _error("sandbox home root is not an existing directory")
    try:
        profile = Profile.from_toml(parsed.profile_path.read_bytes())
    except (OSError, ProfileError) as error:
        raise _error("sandbox profile could not be loaded") from error
    return profile, parsed.home_root


def _approval_endpoint(runtime: Path, requested: Path | None) -> tuple[Path, Path | None]:
    if requested is not None:
        return requested, None
    runtime.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix="sandbox-approval-", dir=runtime))
    return directory / "approval.sock", directory


def _start_projected_home(
    runtime: Path,
    *,
    root: Path | None,
    profile: Profile | None,
    mediation_socket: Path | None,
    session_id: str,
    private_root: Path | None = None,
    overlay_root: Path | None = None,
) -> ProjectedHomeProcess | None:
    try:
        return ProjectedHomeProcess.start(
            runtime,
            root=root,
            profile=profile,
            mediation_socket=mediation_socket,
            session_id=session_id,
            storage_root=private_root,
            overlay_root=overlay_root,
        )
    except FuseUnavailable as error:
        if profile is not None:
            raise _error(
                "host projected home is unavailable", ErrorCode.DAEMON_UNAVAILABLE
            ) from error
        return None


def run_sandbox(
    arguments: Sequence[str],
    *,
    daemon_request: DaemonRequest,
    runtime: Path,
    approval_observer: Callable[[PendingRequest], None] | None = None,
    approval_input_fd: int | None = None,
    approval_mediator: UnknownPathMediator | None = None,
    environment_policy: EnvironmentPolicy | None = None,
    session_id: str | None = None,
    audit_sink: Callable[[str, str, str, dict[str, object]], None] | None = None,
) -> int:
    parsed = parse_arguments(arguments)
    profile, home_root = _projected_home_inputs(parsed)
    host_rx_target = _host_rx_target(profile, parsed.command)
    projected_writable = parsed.private_root is not None or parsed.overlay_root is not None
    resource_policy = None if profile is None else ResourcePolicy(profile)
    if profile is not None and resource_policy is not None and profile.raw_socket:
        decision = resource_policy.raw_socket()
        raise _error(decision.reason, ErrorCode.DAEMON_AUTH)
    approved_sockets = () if resource_policy is None else resource_policy.approved_sockets()
    if profile is None or (not profile.environment_allow and not profile.environment_unset):
        profile_environment = environment_policy
    else:
        profile_environment = EnvironmentPolicy(
            allowed_names=frozenset(profile.environment_allow)
            if profile.environment_allow
            else EnvironmentPolicy().allowed_names,
            unset_names=frozenset(profile.environment_unset),
        )
    if parsed.grant_id is None:
        projected = None
        session_id = session_id or uuid.uuid4().hex
        mediation_socket, mediation_directory = _approval_endpoint(runtime, None)
        mediator = approval_mediator or UnknownPathMediator(observer=approval_observer)
        approval = ApprovalController(
            session_id=session_id,
            mediator=mediator,
            approval_socket=parsed.approval_socket,
            mediation_socket=mediation_socket,
            input_fd=0 if approval_input_fd is None else approval_input_fd,
            audit_sink=audit_sink,
        )
        host_rx_directory: Path | None = None
        try:
            projected = _start_projected_home(
                runtime,
                root=home_root,
                profile=profile,
                mediation_socket=mediation_socket,
                session_id=session_id,
                private_root=parsed.private_root,
                overlay_root=parsed.overlay_root,
            )
            host_rx_manifest, host_rx_directory = _write_host_rx_manifest(runtime, host_rx_target)
            plan = LocalSandboxPlan(
                parsed.command,
                parsed.network,
                projected_home=None if projected is None else projected.mountpoint,
                projected_home_writable=projected_writable,
                host_rx_manifest=host_rx_manifest,
                socket_paths=approved_sockets,
            )
            return run_plan(
                plan,
                health_check=None
                if projected is None
                else getattr(projected, "healthy", lambda: True),
                approval=approval,
                environment_policy=profile_environment,
                hardening=hardening_policy(plan),
                audit_sink=audit_sink,
            )
        finally:
            if projected is not None:
                projected.close()
            _remove_host_rx_directory(host_rx_directory)
            if mediation_directory is not None:
                shutil.rmtree(mediation_directory, ignore_errors=True)
    grant_id = parsed.grant_id
    grant = _load_grant(grant_id, daemon_request)
    if not parsed.remotes:
        if len(grant.grant.exports) != 1:
            raise _error(
                "--grant shorthand requires exactly one signed export",
                ErrorCode.DAEMON_AUTH,
            )
        export = grant.grant.exports[0]
        parsed = replace(
            parsed,
            remotes=(
                RemoteSpec(None, export.requested_source, "/workspace/remote", export.access_mode),
            ),
        )
    session_id, owns_session = _ensure_session(grant_id, daemon_request)
    mount_ids: list[str] = []
    mount_paths: list[Path] = []
    session_socket = Path(tempfile.mkdtemp(prefix="sandbox-session-", dir=runtime)) / "session.sock"
    api: SessionApiServer | None = None
    projected = None
    host_rx_directory = None
    mediation_socket, mediation_directory = _approval_endpoint(runtime, None)
    mediator = approval_mediator or UnknownPathMediator(observer=approval_observer)
    approval = ApprovalController(
        session_id=session_id,
        mediator=mediator,
        approval_socket=parsed.approval_socket,
        mediation_socket=mediation_socket,
        input_fd=0 if approval_input_fd is None else approval_input_fd,
        audit_sink=audit_sink,
    )
    try:
        projected = _start_projected_home(
            runtime,
            root=home_root,
            profile=profile,
            mediation_socket=mediation_socket,
            session_id=session_id,
            private_root=parsed.private_root,
            overlay_root=parsed.overlay_root,
        )
        host_rx_manifest, host_rx_directory = _write_host_rx_manifest(runtime, host_rx_target)
        for index, remote in enumerate(parsed.remotes):
            _export, virtual_target = _select_export(grant, remote.source)
            mount_path = Path(tempfile.mkdtemp(prefix=f"sandbox-mount-{index}-", dir=runtime))
            mount_paths.append(mount_path)
            result = daemon_request(
                "mount.open",
                {
                    "mode": remote.mode.value,
                    "mount_path": str(mount_path),
                    "source_path": remote.source,
                    "virtual_target": virtual_target,
                },
            )
            mount_id = _string(result, "mount_id")
            if _string(result, "state") != "ready":
                raise _error("daemon mount did not become ready", ErrorCode.DAEMON_UNAVAILABLE)
            mount_ids.append(mount_id)
        api = SessionApiServer(
            session_socket,
            session_id=session_id,
            describe=lambda: _session_description(session_id, daemon_request),
            mounts=lambda: _session_mounts(session_id, daemon_request),
            expiry=lambda: grant.grant.expires_at,
            close=lambda: _close_session(session_id, daemon_request),
            run_ls=lambda payload: _session_run_ls(grant, payload, daemon_request),
        )
        api.start()
        bindings = tuple(
            RemoteBinding(
                mount_id=mount_id,
                host_path=path,
                target=remote.target,
                mode=remote.mode,
            )
            for mount_id, path, remote in zip(mount_ids, mount_paths, parsed.remotes, strict=True)
        )
        plan = LocalSandboxPlan(
            parsed.command,
            parsed.network,
            bindings,
            session_socket,
            session_id,
            projected_home=None if projected is None else projected.mountpoint,
            projected_home_writable=projected_writable,
            host_rx_manifest=host_rx_manifest,
            socket_paths=approved_sockets,
        )
        return run_plan(
            plan,
            health_check=lambda: (
                _mounts_healthy(mount_ids, daemon_request)
                and (projected is None or getattr(projected, "healthy", lambda: True)())
            ),
            approval=approval,
            environment_policy=profile_environment,
            hardening=hardening_policy(plan),
            audit_sink=audit_sink,
        )
    finally:
        if api is not None:
            api.close()
        if projected is not None:
            projected.close()
        cleanup_error = _cleanup_remote_mounts(mount_ids, mount_paths, daemon_request)
        if owns_session:
            with suppress(AstralError):
                daemon_request("session.close", {"session_id": session_id})
        shutil.rmtree(session_socket.parent, ignore_errors=True)
        _remove_host_rx_directory(host_rx_directory)
        assert mediation_directory is not None
        shutil.rmtree(mediation_directory, ignore_errors=True)
        if cleanup_error is not None:
            raise cleanup_error


def _cleanup_remote_mounts(
    mount_ids: Sequence[str],
    mount_paths: Sequence[Path],
    request: DaemonRequest,
) -> AstralError | None:
    errors: list[AstralError] = []
    for mount_id in mount_ids:
        try:
            request("mount.close", {"mount_id": mount_id})
        except AstralError as error:
            errors.append(error)
    for path in mount_paths:
        try:
            mounted = path.is_mount()
        except OSError as error:
            errors.append(
                _error(
                    f"cannot verify remote mount detachment for {path}: {error}",
                    ErrorCode.DAEMON_UNAVAILABLE,
                )
            )
            continue
        if mounted:
            errors.append(
                _error(
                    f"remote mount remains attached at {path}; local path was preserved",
                    ErrorCode.DAEMON_UNAVAILABLE,
                )
            )
            continue
        try:
            path.rmdir()
        except FileNotFoundError:
            continue
        except OSError as error:
            errors.append(
                _error(
                    f"cannot remove detached remote mount directory {path}: {error}",
                    ErrorCode.DAEMON_UNAVAILABLE,
                )
            )
    return errors[0] if errors else None


def _parse_remote(value: str) -> RemoteSpec:
    left, separator, right = value.partition("=")
    if not separator or not left or not right:
        raise _error("--remote requires GRANT:/source=/target[:ro|rw]")
    mode = AccessMode.READ_WRITE
    if right.endswith(":ro"):
        right, mode = right[:-3], AccessMode.READ_ONLY
    elif right.endswith(":rw"):
        right = right[:-3]
    grant_id: str | None = None
    source = left
    if ":" in left:
        grant_id, source = left.split(":", 1)
        if not grant_id:
            raise _error("remote grant prefix is empty")
    if not source.startswith("/") or not right.startswith("/"):
        raise _error("remote source and sandbox target must be absolute")
    _validate_cli_path(source, root_allowed=True)
    _validate_cli_path(right, root_allowed=False)
    return RemoteSpec(grant_id, source, right, mode)


def _validate_cli_path(value: str, *, root_allowed: bool) -> None:
    path = PurePosixPath(value)
    if (
        not value.startswith("/")
        or "\x00" in value
        or (not root_allowed and value == "/")
        or str(path) != value
        or any(part in {".", ".."} for part in path.parts)
        or (value != "/" and value.endswith("/"))
    ):
        raise _error("remote path must be absolute and normalized")


def _path_contains(root: str, value: str) -> bool:
    return root == value or root == "/" or value.startswith(root.rstrip("/") + "/")


def _select_export(grant: SignedGrant, source: str) -> tuple[GrantExport, str]:
    matches = [
        export for export in grant.grant.exports if _path_contains(export.requested_source, source)
    ]
    if not matches:
        raise _error("remote source is outside selected signed grant", ErrorCode.DAEMON_AUTH)
    longest = max(len(export.requested_source) for export in matches)
    selected = [export for export in matches if len(export.requested_source) == longest]
    if len(selected) != 1:
        raise _error("remote source selects ambiguous signed exports", ErrorCode.DAEMON_AUTH)
    export = selected[0]
    suffix = source[len(export.requested_source) :].lstrip("/")
    virtual_target_path = PurePosixPath(export.virtual_target)
    if suffix:
        virtual_target_path /= suffix
    return export, str(virtual_target_path)


def _ensure_session(grant_id: str, request: DaemonRequest) -> tuple[str, bool]:
    sessions = _list_maps(request("session.list", None), "sessions")
    active = [item for item in sessions if item.get("state") == "active"]
    if active:
        if len(active) != 1 or active[0].get("grant_id") != grant_id:
            raise _error("another signed grant already owns active session", ErrorCode.DAEMON_AUTH)
        return _string(active[0], "session_id"), False
    result = request("session.open", {"grant_id": grant_id})
    return _string(result, "session_id"), True


def _load_grant(grant_id: str, request: DaemonRequest) -> SignedGrant:
    result = request("grant.show", {"grant_id": grant_id})
    encoded = result.get("cbor_b64")
    if not isinstance(encoded, str):
        raise _error("daemon grant response is invalid")
    try:
        return SignedGrant.from_cbor(base64.b64decode(encoded, validate=True))
    except (binascii.Error, ValueError, AstralError) as error:
        raise _error("daemon grant response cannot be verified") from error


def _session_mounts(session_id: str, request: DaemonRequest) -> list[Mapping[str, object]]:
    public: list[Mapping[str, object]] = []
    for item in _list_maps(request("mount.list", None), "mounts"):
        if item.get("session_id") != session_id:
            continue
        visible = {
            key: item[key]
            for key in ("state", "mode", "virtual_target")
            if key in item and isinstance(item[key], (str, int, float, bool))
        }
        public.append(visible)
    return public


def _session_run_ls(
    grant: SignedGrant, payload: Mapping[str, object], request: DaemonRequest
) -> Mapping[str, object]:
    scope = SessionListingScope(
        str(grant.grant.grant_id),
        tuple(export.virtual_target for export in grant.grant.exports),
    )
    target, _options = constrain_session_listing_payload(payload, scope)
    scoped_payload = dict(payload)
    scoped_payload["target"] = f"{grant.grant.grant_id}:{target.removeprefix('aspr-session:')}"
    return request("ls", scoped_payload)


def _session_description(session_id: str, request: DaemonRequest) -> Mapping[str, object]:
    result = request("session.show", {"session_id": session_id})
    return {
        key: result[key]
        for key in ("session_id", "grant_id", "state", "expires_at")
        if key in result
    }


def _session_show(session_id: str, request: DaemonRequest) -> Mapping[str, object]:
    return request("session.show", {"session_id": session_id})


def _close_session(session_id: str, request: DaemonRequest) -> Mapping[str, object]:
    return request("session.close", {"session_id": session_id})


def _mounts_healthy(mount_ids: Sequence[str], request: DaemonRequest) -> bool:
    for mount_id in mount_ids:
        try:
            state = _string(request("mount.show", {"mount_id": mount_id}), "state")
        except AstralError:
            return False
        if state != "ready":
            return False
    return True


def _list_maps(result: Mapping[str, object], field: str) -> list[Mapping[str, object]]:
    value = result.get(field)
    if not isinstance(value, list) or not all(isinstance(item, Mapping) for item in value):
        raise _error(f"daemon {field} response is invalid")
    return [item for item in value if isinstance(item, Mapping)]


def _string(result: Mapping[str, object], field: str) -> str:
    value = result.get(field)
    if not isinstance(value, str) or not value:
        raise _error(f"daemon response field {field} is invalid")
    return value


def _error(message: str, code: ErrorCode = ErrorCode.DAEMON_PROTOCOL) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="sandbox was not started or was closed conservatively",
        unsafe_reason="local sandbox receives only verified daemon-created remote views",
        next_action="repair sandbox arguments or daemon state and retry",
    )
