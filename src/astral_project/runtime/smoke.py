"""Packet 15C fixed-loader SFTP handshake smoke test."""

from __future__ import annotations

import os
import select
import struct
import subprocess
import time
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode

_SFTP_INIT = 1
_SFTP_VERSION = 2


def run_sftp_handshake(runtime: Path, *, timeout_seconds: float = 5.0) -> int:
    """Start fixed loader/server argv and require one SFTP version response."""
    return _run_handshake(
        [
            str(runtime / "ld.so"),
            "--library-path",
            str(runtime / "lib"),
            str(runtime / "sftp-server"),
            "-e",
            "-l",
            "INFO",
        ],
        timeout_seconds,
    )


def run_closure_only_sftp_handshake(runtime: Path, *, timeout_seconds: float = 5.0) -> int:
    """Require SFTP success after `unshare --root`; host `/usr`, `/lib`, `/etc` are absent."""
    return _run_handshake(
        [
            "/usr/bin/unshare",
            "--mount",
            "--user",
            "--map-root-user",
            "--net",
            "--fork",
            f"--root={runtime}",
            "--wd=/",
            "/ld.so",
            "--library-path",
            "/lib",
            "/sftp-server",
            "-e",
            "-l",
            "INFO",
        ],
        timeout_seconds,
    )


def _run_handshake(command: list[str], timeout_seconds: float) -> int:
    if timeout_seconds <= 0:
        raise _error("SFTP smoke timeout is invalid")
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"HOME": "/", "LANG": "C", "PATH": "/usr/bin:/bin"},
    )
    try:
        assert process.stdin is not None
        assert process.stdout is not None
        process.stdin.write(struct.pack(">I", 5) + bytes([_SFTP_INIT]) + struct.pack(">I", 3))
        process.stdin.flush()
        response = _read_exact(process.stdout.fileno(), 4, timeout_seconds)
        length = struct.unpack(">I", response)[0]
        if not 5 <= length <= 1024:
            raise _error("SFTP smoke response length is invalid")
        payload = _read_exact(process.stdout.fileno(), length, timeout_seconds)
        if payload[0] != _SFTP_VERSION:
            raise _error("fixed workload did not return SFTP version")
        return int(struct.unpack(">I", payload[1:5])[0])
    except (OSError, subprocess.SubprocessError) as error:
        raise _error("fixed workload handshake failed", str(error)) from error
    finally:
        process.terminate()
        try:
            process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def _read_exact(descriptor: int, length: int, timeout_seconds: float) -> bytes:
    deadline = time.monotonic() + timeout_seconds
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        wait = deadline - time.monotonic()
        if wait <= 0 or not select.select([descriptor], [], [], wait)[0]:
            raise _error("fixed workload handshake timed out")
        chunk = os.read(descriptor, remaining)
        if not chunk:
            raise _error("fixed workload ended during handshake")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _error(message: str, detail: str | None = None) -> AstralError:
    return AstralError(
        code=ErrorCode.PROTOCOL_FRAME,
        message=message,
        security_result="fixed SFTP runtime smoke test failed",
        unsafe_reason="runtime closure must start exact workload without ambient host libraries",
        next_action="rebuild and verify fixed runtime closure",
        dependency_error=detail,
    )
