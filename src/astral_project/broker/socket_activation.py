"""Strict systemd socket-activation adoption; exactly one AF_UNIX stream listener."""

from __future__ import annotations

import os
import socket
from collections.abc import Mapping

from astral_project.core.errors import AstralError, ErrorCode

_SYSTEMD_LISTEN_FD = 3


def take_systemd_listener(environment: Mapping[str, str] | None = None) -> socket.socket:
    values = os.environ if environment is None else environment
    if values.get("LISTEN_PID") != str(os.getpid()) or values.get("LISTEN_FDS") != "1":
        raise _error("systemd did not provide exactly one listener")
    try:
        listener = socket.fromfd(_SYSTEMD_LISTEN_FD, socket.AF_UNIX, socket.SOCK_STREAM)
    except OSError as error:
        raise _error("systemd listener descriptor is unavailable") from error
    if (
        listener.family != socket.AF_UNIX
        or listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM
    ):
        listener.close()
        raise _error("systemd listener has wrong socket type")
    return listener


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="broker socket activation was rejected",
        unsafe_reason="broker accepts only its sole systemd-provided AF_UNIX listener",
        next_action="repair systemd broker socket unit",
    )
