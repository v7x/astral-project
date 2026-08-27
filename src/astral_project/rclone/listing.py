"""Bounded rclone lsjson execution and terminal-safe Astral listing output."""

from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import tempfile
import threading
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import SessionId
from astral_project.core.paths import atomic_write_private, check_private_path
from astral_project.crypto.grants import SignedGrant
from astral_project.sandbox.environment import sanitize_subprocess_environment

MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 100_000


@dataclass(frozen=True, slots=True)
class SftpRemoteConfig:
    """Daemon-owned values used to render one ephemeral rclone SFTP remote."""

    host: str
    remote_user: str
    identity_file: Path
    transport_program: Path
    port: int = 22

    def __post_init__(self) -> None:
        if (
            not self.host
            or not self.remote_user
            or any(character.isspace() for character in self.host + self.remote_user)
            or not self.identity_file.is_absolute()
            or not self.transport_program.is_absolute()
            or not 1 <= self.port <= 65535
        ):
            raise _error("rclone SFTP remote configuration is invalid")


_SORT_KEYS = frozenset({"path", "name", "size", "modified", "type"})


@dataclass(frozen=True, slots=True)
class ListingOptions:
    recursive: bool = False
    stat: bool = False
    max_depth: int | None = None
    filters: tuple[str, ...] = ()
    timeout_seconds: float | None = None
    json_output: bool = False
    raw_output: bool = False
    no_header: bool = False
    sort: str = "path"
    reverse: bool = False

    def __post_init__(self) -> None:
        if self.max_depth is not None and not 0 <= self.max_depth <= 1024:
            raise _error("listing max depth is invalid")
        if self.timeout_seconds is not None and not 0 < self.timeout_seconds <= 86400:
            raise _error("listing timeout is invalid")
        if self.sort not in _SORT_KEYS:
            raise _error("listing sort key is invalid")
        if self.json_output and self.raw_output:
            raise _error("--json and --raw are mutually exclusive")
        if any(not item or "\x00" in item for item in self.filters):
            raise _error("listing filter is invalid")


@dataclass(frozen=True, slots=True)
class RcloneEntry:
    path: str
    name: str
    size: int
    modified: str | None
    is_dir: bool
    mime_type: str | None = None
    hashes: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "is_dir": self.is_dir,
            "mime_type": self.mime_type,
            "modified": self.modified,
            "name": self.name,
            "path": self.path,
            "size": self.size,
        }


DEFAULT_LISTING_OPTIONS = ListingOptions()


@dataclass(frozen=True, slots=True)
class RcloneOutput:
    stdout: bytes
    stderr: bytes
    returncode: int


Runner = Callable[[Sequence[str], Mapping[str, str], float | None], RcloneOutput]


def parse_lsjson(data: bytes, *, max_bytes: int = MAX_JSON_BYTES) -> tuple[RcloneEntry, ...]:
    """Parse bounded rclone JSON and normalize hostile or optional fields."""
    if not 1 <= max_bytes <= MAX_JSON_BYTES or len(data) > max_bytes:
        raise _error("rclone JSON exceeds configured limit")
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _error("rclone returned malformed JSON") from error
    if not isinstance(payload, list) or len(payload) > MAX_ENTRIES:
        raise _error("rclone JSON root or entry count is invalid")
    entries: list[RcloneEntry] = []
    for raw in payload:
        if not isinstance(raw, dict):
            raise _error("rclone JSON entry is not an object")
        entries.append(_entry(raw))
    return tuple(entries)


def render_sftp_config(remote: SftpRemoteConfig) -> str:
    """Render fixed SFTP config without token, grant, or private socket values."""
    return "\n".join(
        (
            "[aspr-session]",
            "type = sftp",
            f"host = {remote.host}",
            f"user = {remote.remote_user}",
            f"port = {remote.port}",
            f"key_file = {remote.identity_file}",
            f"ssh = {remote.transport_program}",
            "disable_hashcheck = true",
            "",
        )
    )


def write_sftp_config(path: Path, remote: SftpRemoteConfig) -> Path:
    """Atomically create daemon-owned ephemeral config with restrictive mode."""
    if not path.is_absolute():
        raise _error("rclone config path must be absolute")
    return atomic_write_private(path, render_sftp_config(remote).encode("utf-8"))


def build_lsjson_argv(
    *,
    binary: Path,
    target: str,
    config: Path,
    options: ListingOptions = DEFAULT_LISTING_OPTIONS,
) -> list[str]:
    """Build fixed rclone argv; config and backend cannot be replaced by target."""
    if not binary.is_absolute() or not config.is_absolute() or not target or "\x00" in target:
        raise _error("rclone listing input is invalid")
    argv = [
        str(binary),
        "--config",
        str(config),
        "--log-level",
        "ERROR",
        "--transfers",
        "1",
        "--checkers",
        "1",
        "--sftp-connections",
        "1",
        "--sftp-concurrency",
        "1",
        "lsjson",
    ]
    if options.recursive:
        argv.append("--recursive")
    if options.stat:
        argv.append("--stat")
    if options.max_depth is not None:
        argv.extend(["--max-depth", str(options.max_depth)])
    for filter_value in options.filters:
        argv.extend(["--filter", filter_value])
    argv.append(target)
    return argv


def run_rclone(
    argv: Sequence[str],
    environment: Mapping[str, str],
    timeout_seconds: float | None,
) -> RcloneOutput:
    """Run pinned rclone with secret-free, visible-PATH environment."""
    capability_environment = {
        key: value
        for key, value in environment.items()
        if key in {"ASPR_TRANSPORT_SOCKET", "ASPR_TRANSPORT_TOKEN"}
    }
    clean = sanitize_subprocess_environment(
        environment,
        visible_paths=(Path("/usr"), Path("/bin"), Path("/sbin"), Path("/lib"), Path("/lib64")),
        capability_environment=capability_environment,
    )
    try:
        with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
            process = subprocess.Popen(
                list(argv),
                stdout=stdout_file,
                stderr=stderr_file,
                env=clean,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as error:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, 9)
                process.wait()
                raise _error("rclone listing timed out") from error
            stdout_file.seek(0)
            stderr_file.seek(0)
            return RcloneOutput(stdout_file.read(), stderr_file.read(), returncode)
    except OSError as error:
        raise _error("rclone executable could not be started") from error


def render_listing(
    entries: Sequence[RcloneEntry], *, options: ListingOptions = DEFAULT_LISTING_OPTIONS
) -> bytes:
    """Render normalized JSON, exact raw output elsewhere, or safe deterministic table."""
    ordered = sorted(
        entries, key=lambda item: _sort_key(item, options.sort), reverse=options.reverse
    )
    if options.json_output:
        payload = {
            "entries": [entry.to_dict() for entry in ordered],
            "version": 1,
        }
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        return (encoded + "\n").encode("utf-8")
    widths = (
        max([4, *(len("dir" if item.is_dir else "file") for item in ordered)]),
        max([4, *(len(_display_size(item.size, item.is_dir)) for item in ordered)]),
    )
    lines: list[str] = []
    if not options.no_header:
        lines.append(
            f"{'TYPE':<{widths[0]}}  {'SIZE':<{widths[1]}}  MODIFIED                  PATH"
        )
    for item in ordered:
        kind = "dir" if item.is_dir else "file"
        size = _display_size(item.size, item.is_dir)
        modified = item.modified or "-"
        lines.append(
            f"{kind:<{widths[0]}}  {size:<{widths[1]}}  {modified:<25} {_safe_path(item.path)}"
        )
    return ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")


def listing_options_from_payload(payload: Mapping[str, object]) -> tuple[str, ListingOptions]:
    """Decode daemon listing payload; no binary, config, or transport selector is accepted."""
    allowed = {
        "filters",
        "json_output",
        "max_depth",
        "no_header",
        "raw_output",
        "recursive",
        "reverse",
        "sort",
        "stat",
        "target",
        "timeout_seconds",
    }
    if set(payload) != allowed or not isinstance(payload.get("target"), str):
        raise _error("listing request fields are invalid")
    filters = payload.get("filters")
    if not isinstance(filters, list) or not all(isinstance(item, str) for item in filters):
        raise _error("listing filters are invalid")
    max_depth = payload.get("max_depth")
    if max_depth is not None and (isinstance(max_depth, bool) or not isinstance(max_depth, int)):
        raise _error("listing max depth is invalid")
    timeout = payload.get("timeout_seconds")
    if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float))):
        raise _error("listing timeout is invalid")
    booleans = ["recursive", "stat", "json_output", "raw_output", "no_header", "reverse"]
    if any(not isinstance(payload[name], bool) for name in booleans):
        raise _error("listing boolean field is invalid")
    sort = payload.get("sort")
    if not isinstance(sort, str):
        raise _error("listing sort is invalid")
    return cast(str, payload["target"]), ListingOptions(
        recursive=cast(bool, payload["recursive"]),
        stat=cast(bool, payload["stat"]),
        max_depth=max_depth,
        filters=tuple(filters),
        timeout_seconds=None if timeout is None else float(timeout),
        json_output=cast(bool, payload["json_output"]),
        raw_output=cast(bool, payload["raw_output"]),
        no_header=cast(bool, payload["no_header"]),
        sort=sort,
        reverse=cast(bool, payload["reverse"]),
    )


def daemon_listing_handler(
    payload: Mapping[str, object],
    *,
    binary: Path,
    config: Path,
    environment: Mapping[str, str] | None = None,
) -> Mapping[str, object]:
    """Run one daemon-owned listing with fixed binary/config and base64 wire output."""
    target, options = listing_options_from_payload(payload)
    stdout, stderr = run_listing(
        binary=binary,
        config=config,
        target=target,
        options=options,
        environment=environment,
    )
    return {
        "stderr_b64": base64.b64encode(stderr).decode("ascii"),
        "stdout_b64": base64.b64encode(stdout).decode("ascii"),
        "version": 1,
    }


def daemon_bound_listing_handler(
    payload: Mapping[str, object],
    *,
    session_id: str,
    signed_grant: SignedGrant,
    host: str,
    remote_user: str,
    identity_file: Path,
    port: int,
    binary: Path,
    runtime: Path,
    transport_program: Path,
    ssh_binary: Path = Path("/usr/bin/ssh"),
    runner: Runner = run_rclone,
) -> Mapping[str, object]:
    """Run rclone through one daemon-owned capability and bound remote session."""
    from astral_project.session.contracts import RemoteSessionRequestV1
    from astral_project.transport.local import (
        PrivateTransportServer,
        TransportCapability,
        open_remote_sftp_stream,
    )

    target, options = listing_options_from_payload(payload)
    if not identity_file.is_absolute() or not transport_program.is_absolute():
        raise _error("daemon remote identity paths are invalid")
    try:
        check_private_path(identity_file)
        session = RemoteSessionRequestV1(
            SessionId(session_id),
            secrets.token_bytes(32),
            signed_grant,
        )
    except (OSError, ValueError, AstralError) as error:
        raise _error("active remote session is invalid") from error
    capability = TransportCapability.create(runtime / "transport")
    server = PrivateTransportServer(
        capability,
        lambda: open_remote_sftp_stream(
            session,
            ssh_binary=ssh_binary,
            identity_file=identity_file,
            host=host,
            remote_user=remote_user,
            port=port,
        ),
    )
    config = runtime / f"rclone-{secrets.token_hex(12)}.conf"
    server.start()
    serving = threading.Thread(target=server.serve_forever, daemon=True)
    serving.start()
    try:
        write_sftp_config(
            config,
            SftpRemoteConfig(
                host=host,
                remote_user=remote_user,
                identity_file=identity_file,
                transport_program=transport_program,
                port=port,
            ),
        )
        stdout, stderr = run_listing(
            binary=binary,
            config=config,
            target=target,
            options=options,
            environment={**os.environ, **capability.environment.as_dict()},
            capability_environment=capability.environment.as_dict(),
            runner=runner,
        )
    finally:
        server.close()
        serving.join(timeout=5)
        with suppress(FileNotFoundError):
            config.unlink()
    return {
        "stderr_b64": base64.b64encode(stderr).decode("ascii"),
        "stdout_b64": base64.b64encode(stdout).decode("ascii"),
        "version": 1,
    }


def run_listing(
    *,
    binary: Path,
    config: Path,
    target: str,
    options: ListingOptions,
    environment: Mapping[str, str] | None = None,
    capability_environment: Mapping[str, str] | None = None,
    runner: Runner = run_rclone,
) -> tuple[bytes, bytes]:
    """Execute one bounded listing and return stdout plus diagnostic stderr."""
    argv = build_lsjson_argv(binary=binary, target=target, config=config, options=options)
    source_environment = os.environ if environment is None else environment
    clean_environment = sanitize_subprocess_environment(
        source_environment,
        visible_paths=(Path("/usr"), Path("/bin"), Path("/sbin"), Path("/lib"), Path("/lib64")),
        capability_environment=capability_environment,
    )
    result = runner(argv, clean_environment, options.timeout_seconds)
    if result.returncode != 0:
        raise _error(
            "rclone listing failed",
            dependency_error=result.stderr.decode("utf-8", "replace"),
        )
    if options.raw_output:
        return result.stdout, result.stderr
    return render_listing(parse_lsjson(result.stdout), options=options), result.stderr


def _entry(raw: Mapping[str, Any]) -> RcloneEntry:
    path = raw.get("Path")
    name = raw.get("Name", path)
    size = raw.get("Size", -1)
    modified = raw.get("ModTime")
    is_dir = raw.get("IsDir")
    if not isinstance(path, str) or not path or "\x00" in path:
        raise _error("rclone entry path is invalid")
    if not isinstance(name, str) or "\x00" in name:
        raise _error("rclone entry name is invalid")
    if isinstance(size, bool) or not isinstance(size, int) or size < -1:
        raise _error("rclone entry size is invalid")
    if not isinstance(is_dir, bool):
        raise _error("rclone entry directory flag is invalid")
    if modified is not None and not isinstance(modified, str):
        raise _error("rclone entry modification time is invalid")
    hashes = raw.get("Hashes", {})
    if not isinstance(hashes, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in hashes.items()
    ):
        raise _error("rclone entry hashes are invalid")
    mime_type = raw.get("MimeType") if isinstance(raw.get("MimeType"), str) else None
    return RcloneEntry(path, name, size, modified, is_dir, mime_type, hashes)


def _sort_key(entry: RcloneEntry, sort: str) -> tuple[str, str]:
    if sort == "name":
        return (entry.name, "")
    if sort == "size":
        return (f"{entry.size:020d}", entry.path)
    if sort == "modified":
        return (entry.modified or "", entry.path)
    if sort == "type":
        return ("0" if entry.is_dir else "1", entry.path)
    return (entry.path, "")


def _safe_path(path: str) -> str:
    return "".join(
        character
        if character.isprintable() and character not in "\x1b\t\r\n"
        else f"\\x{ord(character):02x}"
        for character in path
    )


def _display_size(size: int, is_dir: bool) -> str:
    if is_dir or size < 0:
        return "-"
    units = ("B", "KiB", "MiB", "GiB", "TiB")
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{size} B"
        value /= 1024
    return "-"  # pragma: no cover


def _error(message: str, dependency_error: str | None = None) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_PROTOCOL,
        message=message,
        security_result="rclone listing was rejected",
        unsafe_reason="listing must use bounded typed output and fixed daemon-owned configuration",
        next_action="repair rclone output or retry through trusted daemon",
        dependency_error=dependency_error,
    )
