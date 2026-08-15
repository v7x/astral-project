"""Broker control client framing and descriptor-transfer failures."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from astral_project.broker import client
from astral_project.core.errors import AstralError


class _Connection:
    def __init__(self, response: bytes, *, sent: int = 1) -> None:
        self.response = bytearray(response)
        self.sent = sent
        self.closed = False

    def connect(self, _path: str) -> None:
        return None

    def sendmsg(self, *_args: object) -> int:
        return self.sent

    def sendall(self, _payload: bytes) -> None:
        return None

    def recv(self, length: int) -> bytes:
        result = bytes(self.response[:length])
        del self.response[:length]
        return result

    def close(self) -> None:
        self.closed = True


def _request() -> object:
    return type("Request", (), {"canonical_bytes": lambda self: b"request"})()


def test_request_namespace_rejects_invalid_descriptor() -> None:
    with pytest.raises(AstralError):
        client.request_namespace(Path("/socket"), _request(), stream_descriptor=-1)  # type: ignore[arg-type]


def test_read_exact_rejects_eof() -> None:
    connection = _Connection(b"")
    with pytest.raises(AstralError):
        client._read_exact(connection, 1)  # type: ignore[arg-type]


def test_request_namespace_rejects_invalid_response_length(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _Connection(struct.pack(">I", 0))
    monkeypatch.setattr("astral_project.broker.client.socket.socket", lambda *_args: connection)
    with pytest.raises(AstralError):
        client.request_namespace(Path("/socket"), _request(), stream_descriptor=3)  # type: ignore[arg-type]
    assert connection.closed


def test_request_namespace_rejects_send_no_progress(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = _Connection(b"", sent=0)
    monkeypatch.setattr("astral_project.broker.client.socket.socket", lambda *_args: connection)
    with pytest.raises(AstralError):
        client.request_namespace(Path("/socket"), _request(), stream_descriptor=3)  # type: ignore[arg-type]


def test_request_namespace_translates_socket_error(monkeypatch: pytest.MonkeyPatch) -> None:
    class Failing:
        def connect(self, _path: str) -> None:
            raise OSError("offline")

        def close(self) -> None:
            return None

    monkeypatch.setattr("astral_project.broker.client.socket.socket", lambda *_args: Failing())
    with pytest.raises(AstralError):
        client.request_namespace(Path("/socket"), _request(), stream_descriptor=3)  # type: ignore[arg-type]
