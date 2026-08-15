"""Outer framing boundary tests."""

from __future__ import annotations

import struct
from io import BytesIO

import pytest

from astral_project.core.errors import AstralError
from astral_project.server import protocol


def test_outer_response_reads_bounded_map() -> None:
    payload = b"\xa1\x61x\x01"
    stream = BytesIO(struct.pack(">I", len(payload)) + payload)
    assert protocol.read_outer_response(stream) == {"x": 1}


@pytest.mark.parametrize("payload", [b"", b"x" * (protocol.MAX_OUTER_SESSION_BYTES + 1)])
def test_outer_frame_rejects_empty_or_oversized_payload(payload: bytes) -> None:
    with pytest.raises(AstralError):
        protocol._write_frame(BytesIO(), payload)


def test_outer_response_rejects_truncation_length_and_nonmap() -> None:
    with pytest.raises(AstralError):
        protocol.read_outer_response(BytesIO(b"\x00\x00"))
    with pytest.raises(AstralError):
        protocol.read_outer_response(BytesIO(struct.pack(">I", 0)))
    with pytest.raises(AstralError):
        protocol.read_outer_response(BytesIO(struct.pack(">I", 1) + b"\x01"))
