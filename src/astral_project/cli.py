"""Public command-line interface."""

from __future__ import annotations

import base64
import binascii
import json
import os
import platform
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import BinaryIO, TextIO, cast

from astral_project import PROTOCOL_VERSION, TARGET_PLATFORM, __version__
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import resolve_xdg_paths
from astral_project.daemon.client import DaemonClient
from astral_project.daemon.server import DaemonPaths, DaemonServer
from astral_project.host.probe import run_ssh_probe, subprocess_runner
from astral_project.host.records import HostRecord
from astral_project.learner import LearnerError, ProfileLearner
from astral_project.profile import Profile, ProfileError
from astral_project.profile_lifecycle import ProfileStore
from astral_project.sandbox.command import run_sandbox
from astral_project.sandbox.session_api import SessionApiClient
from astral_project.server.entry import run_ssh_entry
from astral_project.state.sqlite import StateDatabase
from astral_project.transport.local import run_transport

_INTERNAL_MODES = frozenset({"daemon", "homed", "server", "transport"})


def _git_revision() -> str:
    """Return current Git revision when repository metadata is available."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            check=False,
            text=True,
            timeout=1.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"

    revision = result.stdout.strip()
    if result.returncode != 0 or not revision:
        return "unavailable"
    return revision


def version_payload() -> dict[str, object]:
    """Build version schema shared by both public command names."""
    return {
        "git_revision": _git_revision(),
        "package_version": __version__,
        "protocol_version": PROTOCOL_VERSION,
        "python_version": platform.python_version(),
        "target_platform": TARGET_PLATFORM,
    }


def _write_version(*, as_json: bool, stdout: TextIO) -> None:
    payload = version_payload()
    if as_json:
        stdout.write(json.dumps(payload, separators=(",", ":"), sort_keys=True))
        stdout.write("\n")
        return

    stdout.write("Astral Project\n")
    for key, value in payload.items():
        stdout.write(f"{key}: {value}\n")


def _write_unknown_command(command: str, stderr: TextIO) -> int:
    error = AstralError(
        code=ErrorCode.CLI_UNKNOWN_COMMAND,
        message=f"unknown command {command!r}",
        security_result="command was not run",
        unsafe_reason="public command surface is fixed",
        next_action="run `aspr version` for available command",
    )
    stderr.write(f"{error.to_text()}\n")
    return 2


def _daemon_paths() -> DaemonPaths:
    paths = resolve_xdg_paths(os.environ)
    return DaemonPaths(runtime=paths.runtime, state=paths.state / "state.sqlite3")


def _write_bytes(stream: TextIO, value: bytes) -> None:
    binary = getattr(stream, "buffer", None)
    if binary is not None:
        binary.write(value)
        binary.flush()
    else:
        stream.write(value.decode("utf-8", "replace"))
        stream.flush()


def _ls_payload(arguments: Sequence[str]) -> dict[str, object]:
    if len(arguments) < 2:
        raise AstralError(
            code=ErrorCode.DAEMON_PROTOCOL,
            message="aspr ls requires one target",
            security_result="listing was not started",
            unsafe_reason="listing target must be explicit and bounded",
            next_action="use `aspr ls <grant>:/path`",
        )
    target = arguments[1]
    values: dict[str, object] = {
        "filters": [],
        "json_output": False,
        "max_depth": None,
        "no_header": False,
        "raw_output": False,
        "recursive": False,
        "reverse": False,
        "sort": "path",
        "stat": False,
        "target": target,
        "timeout_seconds": None,
    }
    index = 2
    while index < len(arguments):
        option = arguments[index]
        if option in {"--recursive", "-R"}:
            values["recursive"] = True
        elif option == "--stat":
            values["stat"] = True
        elif option == "--json":
            values["json_output"] = True
        elif option == "--raw":
            values["raw_output"] = True
        elif option == "--no-header":
            values["no_header"] = True
        elif option == "--reverse":
            values["reverse"] = True
        elif option in {"--max-depth", "--timeout", "--sort", "--filter"}:
            index += 1
            if index >= len(arguments):
                raise AstralError(
                    code=ErrorCode.DAEMON_PROTOCOL,
                    message=f"{option} requires a value",
                    security_result="listing was not started",
                    unsafe_reason="listing options must be complete typed values",
                    next_action="supply a value for the option",
                )
            value = arguments[index]
            if option == "--max-depth":
                try:
                    values["max_depth"] = int(value)
                except ValueError as error:
                    raise AstralError(
                        code=ErrorCode.DAEMON_PROTOCOL,
                        message="--max-depth must be an integer",
                        security_result="listing was not started",
                        unsafe_reason="listing depth must be bounded integer",
                        next_action="supply an integer depth",
                    ) from error
            elif option == "--timeout":
                try:
                    values["timeout_seconds"] = float(value)
                except ValueError as error:
                    raise AstralError(
                        code=ErrorCode.DAEMON_PROTOCOL,
                        message="--timeout must be numeric",
                        security_result="listing was not started",
                        unsafe_reason="listing timeout must be bounded numeric value",
                        next_action="supply a positive timeout",
                    ) from error
            elif option == "--sort":
                values["sort"] = value
            else:
                cast_filters = values["filters"]
                assert isinstance(cast_filters, list)
                cast_filters.append(value)
        else:
            raise AstralError(
                code=ErrorCode.CLI_UNKNOWN_COMMAND,
                message=f"unknown ls option {option!r}",
                security_result="listing was not started",
                unsafe_reason="listing option surface is fixed",
                next_action="use documented `aspr ls` options",
            )
        index += 1
    return values


def _daemon_request(
    operation: str, payload: Mapping[str, object] | None = None
) -> dict[str, object]:
    result = DaemonClient(_daemon_paths().socket).request(
        request_id=operation,
        cancellation_id=operation,
        operation=operation,
        payload=payload,
    )
    if not isinstance(result, dict):
        raise AstralError(
            code=ErrorCode.DAEMON_PROTOCOL,
            message="daemon returned invalid result",
            security_result="daemon result was discarded",
            unsafe_reason="control responses must be versioned maps",
            next_action="restart compatible daemon",
        )
    return dict(result)


def _run_json_operation(
    operation: str,
    payload: Mapping[str, object] | None,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    try:
        result = _daemon_request(operation, payload)
    except AstralError as error:
        stderr.write(f"{error.to_text()}\n")
        return 70
    stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
    stdout.write("\n")
    return 0


def _profile_store() -> ProfileStore:
    paths = resolve_xdg_paths(os.environ)
    database = StateDatabase.open(paths.state / "state.sqlite3")
    return ProfileStore(paths.config, audit_sink=database.record_audit)


def _profile_json(profile: Profile) -> str:
    return json.dumps(
        {
            "id": profile.profile_id,
            "name": profile.name,
            "revision": profile.revision,
            "sealed": profile.sealed,
            "rules": len(profile.rules),
            "provenance": len(profile.provenance),
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def _run_profile(arguments: Sequence[str], stdout: TextIO, stderr: TextIO) -> int:
    if len(arguments) < 2:
        return _write_unknown_command("profile", stderr)
    command = arguments[1]
    store = _profile_store()
    if command == "learn":
        if len(arguments) < 4 or "--" not in arguments[3:]:
            return _write_unknown_command("profile learn", stderr)
        separator = arguments.index("--", 3)
        options = list(arguments[3:separator])
        external_only = False
        grant_id: str | None = None
        remotes: list[str] = []
        index = 0
        while index < len(options):
            option = options[index]
            if option == "--external" and not external_only:
                external_only = True
            elif option == "--grant" and grant_id is None and index + 1 < len(options):
                index += 1
                grant_id = options[index]
            elif option == "--remote" and index + 1 < len(options):
                index += 1
                remotes.append(options[index])
            else:
                return _write_unknown_command("profile learn", stderr)
            index += 1
        if bool(remotes) != (grant_id is not None):
            return _write_unknown_command("profile learn", stderr)
        learner = ProfileLearner(store, state_root=resolve_xdg_paths(os.environ).state)
        return learner.run(
            arguments[2],
            arguments[separator + 1 :],
            runtime=resolve_xdg_paths(os.environ).runtime,
            approval_socket=Path(os.environ["ASPR_APPROVAL_SOCKET"])
            if os.environ.get("ASPR_APPROVAL_SOCKET")
            else None,
            external_only=external_only,
            session_id=os.environ.get("ASPR_LEARN_SESSION_ID"),
            grant_id=grant_id,
            remotes=remotes,
            daemon_request=_daemon_request,
        )
    if command == "create" and len(arguments) in {3, 5}:
        name = None
        if len(arguments) == 5 and arguments[3] == "--name":
            name = arguments[4]
        elif len(arguments) == 5:
            return _write_unknown_command("profile create", stderr)
        stdout.write(_profile_json(store.create(arguments[2], name=name)) + "\n")
        return 0
    if command == "list" and len(arguments) == 2:
        values = [json.loads(_profile_json(profile)) for profile in store.list()]
        stdout.write(json.dumps(values, separators=(",", ":"), sort_keys=True) + "\n")
        return 0
    if command in {"review", "seal", "unseal", "archive"} and len(arguments) == 3:
        profile_id = arguments[2]
        if command == "review":
            value = store.review(profile_id)
            stdout.write(value)
            if not value.endswith("\n"):
                stdout.write("\n")
            return 0
        if command == "archive":
            stdout.write(json.dumps({"archive": str(store.archive_profile(profile_id))}) + "\n")
        else:
            profile = store.seal(profile_id) if command == "seal" else store.unseal(profile_id)
            stdout.write(_profile_json(profile) + "\n")
        return 0
    if command == "diff" and len(arguments) == 4:
        stdout.write(store.diff(arguments[2], Path(arguments[3])))
        return 0
    if command == "edit" and len(arguments) == 3:
        stdout.write(_profile_json(store.edit(arguments[2])) + "\n")
        return 0
    if command == "export" and len(arguments) == 4:
        store.export(arguments[2], Path(arguments[3]))
        stdout.write(json.dumps({"export": arguments[3]}) + "\n")
        return 0
    if command == "import" and len(arguments) in {3, 4}:
        requested_id = arguments[3] if len(arguments) == 4 else None
        profile = store.import_profile(Path(arguments[2]), profile_id=requested_id)
        stdout.write(_profile_json(profile) + "\n")
        return 0
    return _write_unknown_command(" ".join(arguments[:2]), stderr)


def _run_audit(arguments: Sequence[str], stdout: TextIO, stderr: TextIO) -> int:
    if len(arguments) < 2:
        return _write_unknown_command("audit", stderr)
    command = arguments[1]
    if command == "list" and len(arguments) == 2:
        return _run_json_operation("audit.list", None, stdout, stderr)
    if command == "show" and len(arguments) == 3:
        return _run_json_operation("audit.show", {"event_id": arguments[2]}, stdout, stderr)
    if command == "export" and len(arguments) in {2, 3}:
        if len(arguments) == 3 and arguments[2] != "--hash":
            return _write_unknown_command("audit export", stderr)
        mode = "hash" if len(arguments) == 3 else "redact"
        return _run_json_operation("audit.export", {"path_mode": mode}, stdout, stderr)
    return _write_unknown_command(" ".join(arguments[:2]), stderr)


def _run_lifecycle(arguments: Sequence[str], stdout: TextIO, stderr: TextIO) -> int:
    if len(arguments) >= 2 and arguments[0] == "grant":
        command = arguments[1]
        if command == "list":
            include_revoked = "--all" in arguments[2:]
            return _run_json_operation(
                "grant.list", {"include_revoked": include_revoked}, stdout, stderr
            )
        if command in {"import", "create"} and len(arguments) in {3, 4}:
            try:
                envelope = base64.b64encode(Path(arguments[2]).read_bytes()).decode("ascii")
                import_payload: dict[str, object] = {"cbor_b64": envelope}
                if len(arguments) == 4:
                    import_payload["issuer_key_b64"] = base64.b64encode(
                        Path(arguments[3]).read_bytes()
                    ).decode("ascii")
            except OSError as error:
                stderr.write(f"grant input could not be read: {error}\n")
                return 70
            return _run_json_operation("grant.import", import_payload, stdout, stderr)
        if command == "show" and len(arguments) == 3:
            return _run_json_operation("grant.show", {"grant_id": arguments[2]}, stdout, stderr)
        if command == "validate" and len(arguments) == 3:
            return _run_json_operation("grant.validate", {"grant_id": arguments[2]}, stdout, stderr)
        if command == "revoke" and len(arguments) in {3, 5}:
            reason = "user request"
            if len(arguments) == 5 and arguments[3] == "--reason":
                reason = arguments[4]
            return _run_json_operation(
                "grant.revoke", {"grant_id": arguments[2], "reason": reason}, stdout, stderr
            )
    if len(arguments) >= 2 and arguments[0] == "session":
        command = arguments[1]
        if command == "list" and len(arguments) == 2:
            return _run_json_operation("session.list", None, stdout, stderr)
        if command in {"open", "show"} and len(arguments) == 3:
            operation = "session.open" if command == "open" else "session.show"
            key = "grant_id" if command == "open" else "session_id"
            return _run_json_operation(operation, {key: arguments[2]}, stdout, stderr)
        if command == "close" and len(arguments) == 3:
            return _run_json_operation(
                "session.close", {"session_id": arguments[2]}, stdout, stderr
            )
    if len(arguments) >= 2 and arguments[0] == "mount":
        command = arguments[1]
        if command == "list" and len(arguments) == 2:
            return _run_json_operation("mount.list", None, stdout, stderr)
        if command == "show" and len(arguments) == 3:
            return _run_json_operation("mount.show", {"mount_id": arguments[2]}, stdout, stderr)
        if command == "close" and len(arguments) == 3:
            return _run_json_operation("mount.close", {"mount_id": arguments[2]}, stdout, stderr)
        if command == "open" and len(arguments) in {5, 6}:
            payload: dict[str, object] = {
                "mount_path": arguments[2],
                "virtual_target": arguments[3],
                "mode": arguments[4],
            }
            if len(arguments) == 6 and arguments[5] != "--read-write":
                raise AstralError(
                    code=ErrorCode.CLI_UNKNOWN_COMMAND,
                    message="mount open accepts only --read-write as optional flag",
                    security_result="mount was not started",
                    unsafe_reason="mount mode must be explicit and fixed",
                    next_action="use `aspr mount open PATH TARGET ro|rw [--read-write]`",
                )
            return _run_json_operation("mount.open", payload, stdout, stderr)
    return _write_unknown_command(" ".join(arguments[:2]), stderr)


def _run_ls(arguments: Sequence[str], stdout: TextIO, stderr: TextIO) -> int:
    try:
        payload = _ls_payload(arguments)
        session_socket = os.environ.get("ASPR_SESSION_SOCKET")
        session_id = os.environ.get("ASPR_SESSION_ID")
        if session_socket is not None or session_id is not None:
            if not session_socket or not session_id:
                raise AstralError(
                    code=ErrorCode.DAEMON_AUTH,
                    message="sandbox session discovery environment is incomplete",
                    security_result="listing was not started",
                    unsafe_reason="sandbox listing requires both fixed session variables",
                    next_action="run listing inside a valid Astral sandbox",
                )
            result = SessionApiClient(Path(session_socket), session_id=session_id).request(
                "RunLs", payload
            )
        else:
            result = DaemonClient(_daemon_paths().socket).request(
                request_id="ls", cancellation_id="ls", operation="ls", payload=payload
            )
        if set(result) != {"stderr_b64", "stdout_b64", "version"} or result["version"] != 1:
            raise AstralError(
                code=ErrorCode.DAEMON_PROTOCOL,
                message="daemon listing response is invalid",
                security_result="listing output was discarded",
                unsafe_reason="daemon output must be bounded versioned bytes",
                next_action="restart compatible daemon",
            )
        if not isinstance(result["stdout_b64"], str) or not isinstance(result["stderr_b64"], str):
            raise AstralError(
                code=ErrorCode.DAEMON_PROTOCOL,
                message="daemon listing response fields are invalid",
                security_result="listing output was discarded",
                unsafe_reason="daemon output encoding must be text",
                next_action="restart compatible daemon",
            )
        try:
            output = base64.b64decode(result["stdout_b64"], validate=True)
            diagnostic = base64.b64decode(result["stderr_b64"], validate=True)
        except (binascii.Error, TypeError) as error:
            raise AstralError(
                code=ErrorCode.DAEMON_PROTOCOL,
                message="daemon listing response encoding is invalid",
                security_result="listing output was discarded",
                unsafe_reason="daemon output encoding must be strict",
                next_action="restart compatible daemon",
            ) from error
        _write_bytes(stdout, output)
        _write_bytes(stderr, diagnostic)
        return 0
    except AstralError as error:
        stderr.write(f"{error.to_text()}\n")
        return 70


def _run_internal(mode: str, stderr: TextIO) -> int:
    """Run hidden trusted-process mode without exposing public command surface."""
    if mode == "homed":
        from astral_project.homed.fuse import (
            FuseUnavailable,
            mount_composite,
            mount_empty,
            mount_host_readonly,
            mount_private,
        )
        from astral_project.homed.mediation import RemoteUnknownPathMediator
        from astral_project.profile import Profile

        mountpoint = os.environ.get("ASPR_HOMED_MOUNTPOINT")
        if not mountpoint:
            stderr.write("ASPR_HOMED_MOUNTPOINT is required for internal homed mode\n")
            return 70
        try:
            root = os.environ.get("ASPR_HOMED_ROOT")
            storage_root = os.environ.get("ASPR_HOMED_STORAGE_ROOT")
            overlay_root = os.environ.get("ASPR_HOMED_OVERLAY_ROOT")
            profile_text = os.environ.get("ASPR_HOMED_PROFILE")
            mediation_socket = os.environ.get("ASPR_HOMED_MEDIATION_SOCKET")
            debug = os.environ.get("ASPR_HOMED_DEBUG") == "1"
            if profile_text is None:
                mount_empty(mountpoint, debug=debug)
            else:
                profile = Profile.from_toml(profile_text)
                if root is not None and (storage_root is not None or overlay_root is not None):
                    mediator = (
                        RemoteUnknownPathMediator(mediation_socket) if mediation_socket else None
                    )
                    mount_composite(
                        mountpoint,
                        root,
                        profile,
                        storage_root=storage_root,
                        overlay_root=overlay_root,
                        mediator=mediator,
                        session_id=os.environ.get("ASPR_HOMED_SESSION_ID", "default"),
                        debug=debug,
                    )
                elif storage_root is not None:
                    mount_private(mountpoint, storage_root, profile, debug=debug)
                elif root is not None:
                    mediator = (
                        RemoteUnknownPathMediator(mediation_socket) if mediation_socket else None
                    )
                    mount_host_readonly(
                        mountpoint,
                        root,
                        profile,
                        mediator=mediator,
                        session_id=os.environ.get("ASPR_HOMED_SESSION_ID", "default"),
                        debug=debug,
                    )
                else:
                    raise ValueError("projected-home root configuration is incomplete")
        except (FuseUnavailable, OSError, ValueError) as error:
            stderr.write(f"aspr-homed could not start: {error}\n")
            return 70
        return 0
    if mode == "daemon":
        daemon = DaemonServer(_daemon_paths())
        try:
            daemon.start(apply_hardening=True)
            daemon.serve_forever()
        except AstralError as error:
            stderr.write(f"{error.to_text()}\n")
            return 70
        finally:
            daemon.close()
    unavailable = AstralError(
        code=ErrorCode.CLI_INTERNAL_UNAVAILABLE,
        message=f"internal mode {mode!r} is unavailable",
        security_result="internal mode was not started",
        unsafe_reason="this build has no trusted implementation for mode",
        next_action="install compatible Astral Project build",
    )
    stderr.write(f"{unavailable.to_text()}\n")
    return 70


def run(argv: Sequence[str], *, stdout: TextIO, stderr: TextIO) -> int:
    """Run CLI with explicit streams for deterministic launcher behavior."""
    arguments = list(argv)
    session_discovered = (
        os.environ.get("ASPR_SESSION_SOCKET") is not None
        or os.environ.get("ASPR_SESSION_ID") is not None
    )
    if session_discovered and arguments and arguments[0] not in {"version", "ls"}:
        error = AstralError(
            code=ErrorCode.DAEMON_AUTH,
            message="sandbox session exposes only `aspr ls`",
            security_result="sandbox command was not run",
            unsafe_reason="sandbox session bearer capability cannot administer host state",
            next_action="use `aspr ls /path` inside the sandbox",
        )
        stderr.write(f"{error.to_text()}\n")
        return 70
    if arguments == ["version"]:
        _write_version(as_json=False, stdout=stdout)
        return 0
    if arguments in (["version", "--json"], ["--json", "version"]):
        _write_version(as_json=True, stdout=stdout)
        return 0
    if arguments in (["host", "update-server"], ["host", "remove"]):
        error = AstralError(
            code=ErrorCode.CLI_INTERNAL_UNAVAILABLE,
            message=f"{arguments[1]!r} is reserved for trusted enrollment service",
            security_result="remote host was not changed",
            unsafe_reason="host lifecycle requires daemon-owned enrollment state",
            next_action="use compatible daemon enrollment command",
        )
        stderr.write(f"{error.to_text()}\n")
        return 70
    if len(arguments) == 3 and arguments[:2] == ["host", "probe"]:
        try:
            report, fingerprint = run_ssh_probe(arguments[2], subprocess_runner)
        except AstralError as error:
            stderr.write(f"{error.to_text()}\n")
            return 70
        stdout.write(
            json.dumps(
                {"probe": report.to_dict(), "ssh_host_fingerprint": fingerprint},
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        stdout.write("\n")
        return 0
    if arguments == ["host", "doctor", "--probe-file"]:
        return _write_unknown_command("host doctor", stderr)
    if len(arguments) == 4 and arguments[:3] == ["host", "doctor", "--probe-file"]:
        try:
            record = HostRecord.load(Path(arguments[3]))
        except AstralError as error:
            stderr.write(f"{error.to_text()}\n")
            return 70
        stdout.write(json.dumps(record.probe.to_dict(), separators=(",", ":"), sort_keys=True))
        stdout.write("\n")
        return 0
    if len(arguments) == 4 and arguments[:3] == ["server", "ssh-entry", "--transport-key"]:
        return run_ssh_entry(
            arguments[3],
            stdin=sys.stdin.buffer,
            stdout=sys.stdout.buffer,
            stderr=stderr,
            environment=os.environ,
        )
    if arguments and arguments[0] == "ls":
        return _run_ls(arguments, stdout, stderr)
    if arguments and arguments[0] == "profile":
        try:
            return _run_profile(arguments, stdout, stderr)
        except (ProfileError, LearnerError, AstralError) as error:
            stderr.write(f"{error}\n")
            return 70
    if arguments and arguments[0] == "audit":
        try:
            return _run_audit(arguments, stdout, stderr)
        except AstralError as error:
            stderr.write(f"{error.to_text()}\n")
            return 70
    if arguments and arguments[0] in {"grant", "session", "mount"}:
        try:
            return _run_lifecycle(arguments, stdout, stderr)
        except AstralError as error:
            stderr.write(f"{error.to_text()}\n")
            return 70
    if arguments and arguments[0] == "sandbox":
        try:

            def sandbox_request(
                operation: str, payload: Mapping[str, object] | None = None
            ) -> dict[str, object]:
                return _daemon_request(operation, payload)

            def sandbox_audit(
                kind: str,
                subject_type: str,
                subject_id: str,
                payload: dict[str, object],
            ) -> None:
                try:
                    _daemon_request(
                        "audit.record",
                        {
                            "kind": kind,
                            "subject_type": subject_type,
                            "subject_id": subject_id,
                            "payload": payload,
                        },
                    )
                except AstralError:
                    StateDatabase.open(_daemon_paths().state).record_audit(
                        kind, subject_type, subject_id, payload
                    )

            return run_sandbox(
                arguments,
                daemon_request=sandbox_request,
                runtime=_daemon_paths().runtime,
                audit_sink=sandbox_audit,
            )
        except AstralError as error:
            stderr.write(f"{error.to_text()}\n")
            return 70
    if arguments and arguments[0] == "transport":
        return run_transport(
            arguments[1:],
            environment=os.environ,
            stdin=cast(
                BinaryIO,
                getattr(
                    getattr(sys.stdin, "buffer", sys.stdin),
                    "raw",
                    getattr(sys.stdin, "buffer", sys.stdin),
                ),
            ),
            stdout=cast(
                BinaryIO,
                getattr(
                    getattr(sys.stdout, "buffer", sys.stdout),
                    "raw",
                    getattr(sys.stdout, "buffer", sys.stdout),
                ),
            ),
            stderr=cast(BinaryIO, getattr(sys.stderr, "buffer", sys.stderr)),
        )
    if arguments == ["doctor"]:
        try:
            result = DaemonClient(_daemon_paths().socket).request(
                request_id="doctor", cancellation_id="doctor", operation="status"
            )
        except AstralError as error:
            stderr.write(f"{error.to_text()}\n")
            return 70
        stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True))
        stdout.write("\n")
        return 0
    if len(arguments) == 2 and arguments[0] == "__internal" and arguments[1] in _INTERNAL_MODES:
        return _run_internal(arguments[1], stderr)
    if arguments:
        return _write_unknown_command(arguments[0], stderr)
    return _write_unknown_command("", stderr)


def main() -> None:
    """Console-script entry point shared by `astral-project` and `aspr`."""
    raise SystemExit(run(sys.argv[1:], stdout=sys.stdout, stderr=sys.stderr))
