from __future__ import annotations

import socket
import struct

import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.daemon.protocol import MAX_FRAME_BYTES, encode, parse_request, receive


def test_frame_round_trip_and_request_validation() -> None:
    left, right = socket.socketpair()
    try:
        left.sendall(
            encode(
                {
                    "cancellation_id": "cancel-1",
                    "kind": "request",
                    "operation": "ping",
                    "request_id": "request-1",
                    "version": 1,
                }
            )
        )
        request = parse_request(receive(right))
    finally:
        left.close()
        right.close()
    assert request.request_id == "request-1"
    assert request.cancellation_id == "cancel-1"
    assert request.operation == "ping"


@pytest.mark.parametrize(
    ("frame", "message"),
    [
        (struct.pack("!I", 0), "frame length is outside allowed range"),
        (struct.pack("!I", MAX_FRAME_BYTES + 1), "frame length is outside allowed range"),
        (struct.pack("!I", 1) + b"[", "frame payload is not valid JSON"),
        (struct.pack("!I", 2) + b"[]", "frame payload must be an object"),
        (struct.pack("!I", 3) + b"{}", "frame ended before declared length"),
    ],
)
def test_malformed_frames_fail_closed(frame: bytes, message: str) -> None:
    left, right = socket.socketpair()
    try:
        left.sendall(frame)
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(AstralError) as error:
            receive(right)
    finally:
        left.close()
        right.close()
    assert error.value.code is ErrorCode.DAEMON_PROTOCOL
    assert error.value.message == message


def test_protocol_rejects_invalid_schema_and_unserializable_data() -> None:
    with pytest.raises(AstralError) as error:
        parse_request({"kind": "request"})
    assert error.value.code is ErrorCode.DAEMON_PROTOCOL
    with pytest.raises(AstralError):
        parse_request(
            {
                "cancellation_id": "b",
                "kind": "request",
                "operation": "ping",
                "request_id": "a",
                "version": 2,
            }
        )

    with pytest.raises(AstralError) as error:
        encode({"bad": {1}})
    assert error.value.code is ErrorCode.DAEMON_PROTOCOL
