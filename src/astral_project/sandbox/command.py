"""Public sandbox command orchestration around daemon-owned remote mounts."""

from __future__ import annotations

import base64
import binascii
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.grants import AccessMode, GrantExport, SignedGrant
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode, RemoteBinding
from astral_project.sandbox.runner import run_plan
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


def parse_arguments(arguments: Sequence[str]) -> SandboxArguments:
    network: NetworkMode | None = None
    grant_id: str | None = None
    remotes: list[RemoteSpec] = []
    command: tuple[str, ...] = ("/bin/sh",)
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
    return SandboxArguments(network, grant_id, tuple(remotes), command)


def run_sandbox(
    arguments: Sequence[str],
    *,
    daemon_request: DaemonRequest,
    runtime: Path,
) -> int:
    parsed = parse_arguments(arguments)
    if parsed.grant_id is None:
        return run_plan(LocalSandboxPlan(parsed.command, parsed.network))
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
    try:
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
        return run_plan(
            LocalSandboxPlan(
                parsed.command,
                parsed.network,
                bindings,
                session_socket,
                session_id,
            ),
            health_check=lambda: _mounts_healthy(mount_ids, daemon_request),
        )
    finally:
        if api is not None:
            api.close()
        cleanup_error = _cleanup_remote_mounts(mount_ids, mount_paths, daemon_request)
        if owns_session:
            with suppress(AstralError):
                daemon_request("session.close", {"session_id": session_id})
        shutil.rmtree(session_socket.parent, ignore_errors=True)
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
    suffix = source[len(export.requested_source) :]
    virtual_target = export.virtual_target.rstrip("/") + suffix
    if not virtual_target:
        virtual_target = "/"
    return export, virtual_target


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
