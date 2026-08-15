"""Bridge error-path tests."""

from __future__ import annotations

import io
import socket
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

from astral_project.core.errors import AstralError
from astral_project.server import broker_bridge
from astral_project.session.broker import BrokerBackendId, NamespaceReadyV1


class _Stream:
    def __init__(self, *, fail: bool = False) -> None:
        self.sent: list[bytes] = []
        self.shutdown_calls: list[int] = []
        self.fail = fail

    def sendall(self, chunk: bytes) -> None:
        if self.fail:
            raise OSError("closed")
        self.sent.append(chunk)

    def shutdown(self, how: int) -> None:
        self.shutdown_calls.append(how)


def test_copy_stdin_sends_all_and_half_closes() -> None:
    stream = _Stream()
    broker_bridge._copy_stdin_to_stream(io.BytesIO(b"abc"), stream)  # type: ignore[arg-type]
    assert stream.sent == [b"abc"]
    assert stream.shutdown_calls == [1]


def test_copy_stdin_swallows_socket_and_value_errors() -> None:
    stream = _Stream(fail=True)
    broker_bridge._copy_stdin_to_stream(io.BytesIO(b"abc"), stream)  # type: ignore[arg-type]

    class BrokenInput:
        def read(self, _size: int) -> bytes:
            raise ValueError("closed")

    broker_bridge._copy_stdin_to_stream(BrokenInput(), stream)  # type: ignore[arg-type]
    assert stream.sent == []


def _request() -> Any:
    return SimpleNamespace(
        session_id=SimpleNamespace(value="00000000-0000-4000-8000-000000000004"),
        signed_grant=SimpleNamespace(to_cbor=lambda: b"grant"),
        session_nonce=b"n" * 32,
    )


def _ready(session_id: bytes) -> NamespaceReadyV1:
    return NamespaceReadyV1(
        b"r" * 16,
        session_id,
        BrokerBackendId.ADMIN_BOOTSTRAPPED_V1,
        b"e" * 32,
        b"m" * 32,
        1,
    )


def test_open_broker_stream_accepts_ready_and_closes_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = socket.socketpair()
    monkeypatch.setattr(
        "astral_project.server.broker_bridge.socket.socketpair", lambda *_args: pair
    )
    monkeypatch.setattr(
        broker_bridge,
        "request_namespace",
        lambda *_args, **_kwargs: _ready(uuid.UUID(_request().session_id.value).bytes),
    )
    bridge = broker_bridge.open_broker_sftp_stream(_request())
    assert bridge.fileno() >= 0
    bridge.close()


def test_open_broker_stream_rejects_bad_broker_result(monkeypatch: pytest.MonkeyPatch) -> None:
    pair = socket.socketpair()
    monkeypatch.setattr(
        "astral_project.server.broker_bridge.socket.socketpair", lambda *_args: pair
    )
    monkeypatch.setattr(broker_bridge, "request_namespace", lambda *_args, **_kwargs: object())
    with pytest.raises(AstralError):
        broker_bridge.open_broker_sftp_stream(_request())
    assert pair[0].fileno() == -1


def test_open_broker_stream_rejects_mismatched_session(monkeypatch: pytest.MonkeyPatch) -> None:
    pair = socket.socketpair()
    monkeypatch.setattr(
        "astral_project.server.broker_bridge.socket.socketpair", lambda *_args: pair
    )
    monkeypatch.setattr(
        broker_bridge,
        "request_namespace",
        lambda *_args, **_kwargs: _ready(b"x" * 16),
    )
    with pytest.raises(AstralError):
        broker_bridge.open_broker_sftp_stream(_request())
    assert pair[0].fileno() == -1
