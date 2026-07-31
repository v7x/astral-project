"""Public command-line interface."""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import TextIO

from astral_project import PROTOCOL_VERSION, TARGET_PLATFORM, __version__
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import resolve_xdg_paths
from astral_project.daemon.client import DaemonClient
from astral_project.daemon.server import DaemonPaths, DaemonServer
from astral_project.host.probe import run_ssh_probe, subprocess_runner
from astral_project.host.records import HostRecord
from astral_project.server.entry import run_ssh_entry

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


def _run_internal(mode: str, stderr: TextIO) -> int:
    """Run hidden trusted-process mode without exposing public command surface."""
    if mode == "daemon":
        daemon = DaemonServer(_daemon_paths())
        try:
            daemon.start()
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
