"""Systemd listener activation checks."""

from __future__ import annotations

import os
import socket

import pytest

from astral_project.broker import socket_activation
from astral_project.core.errors import AstralError


def test_listener_requires_exact_environment() -> None:
    with pytest.raises(AstralError):
        socket_activation.take_systemd_listener({})
    with pytest.raises(AstralError):
        socket_activation.take_systemd_listener({"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "2"})


def test_listener_accepts_one_unix_stream(monkeypatch: pytest.MonkeyPatch) -> None:
    listener = socket.socketpair()[0]
    monkeypatch.setattr(
        "astral_project.broker.socket_activation.socket.fromfd", lambda *_args: listener
    )
    result = socket_activation.take_systemd_listener(
        {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1"}
    )
    assert result is listener
    result.close()


def test_listener_rejects_unavailable_and_wrong_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "astral_project.broker.socket_activation.socket.fromfd",
        lambda *_args: (_ for _ in ()).throw(OSError()),
    )
    env = {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1"}
    with pytest.raises(AstralError):
        socket_activation.take_systemd_listener(env)

    class BadSocket:
        family = socket.AF_INET
        type = socket.SOCK_STREAM

        def close(self) -> None:
            return None

    monkeypatch.setattr(
        "astral_project.broker.socket_activation.socket.fromfd", lambda *_args: BadSocket()
    )
    with pytest.raises(AstralError):
        socket_activation.take_systemd_listener(env)
