from __future__ import annotations

import json
import os
import socket
import struct
from pathlib import Path

import pytest

from astral_project.approval.protocol import (
    ApprovalClient,
    ApprovalProtocolError,
    ApprovalRequest,
    ApprovalServer,
    _read_frame,
    _write_frame,
)
from astral_project.homed.mediation import MediationDecision, UnknownPathMediator


def test_protocol_rejects_oversize_types_and_invalid_configuration(tmp_path: Path) -> None:
    with pytest.raises(ApprovalProtocolError):
        ApprovalRequest("x" * 5000, 1, MediationDecision.DENY).to_json()
    for raw in (b"bad\n", b'{"decision":"deny","request_number":true,"session_id":"s"}\n'):
        with pytest.raises(ApprovalProtocolError):
            ApprovalRequest.from_json(raw)
    with pytest.raises(ApprovalProtocolError):
        ApprovalClient(Path("relative"))
    with pytest.raises(ApprovalProtocolError):
        ApprovalClient(tmp_path / "x", timeout=0)
    with pytest.raises(ApprovalProtocolError):
        ApprovalServer(Path("relative"), UnknownPathMediator())
    server = ApprovalServer(tmp_path / "server.sock", UnknownPathMediator())
    server.close()
    server._serve()
    with pytest.raises(ApprovalProtocolError):
        ApprovalServer(Path("/approval.sock"), UnknownPathMediator()).start()


def test_protocol_frame_reader_rejects_incomplete_and_mediation_errors(tmp_path: Path) -> None:
    left, right = socket.socketpair()
    try:
        left.sendall(b"incomplete")
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(ApprovalProtocolError):
            _read_frame(right)
    finally:
        left.close()
        right.close()
    left, right = socket.socketpair()
    try:
        left.sendall(b"x" * 4097)
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(ApprovalProtocolError):
            _read_frame(right)
    finally:
        left.close()
        right.close()

    server = ApprovalServer(tmp_path / "approval.sock", UnknownPathMediator())
    left, right = socket.socketpair()
    try:
        server._handle_mediation(left, json.dumps({"kind": "mediation-request"}).encode() + b"\n")
        assert b'"allowed":false' in right.recv(4096)
    finally:
        left.close()
        right.close()

    left, right = socket.socketpair()
    try:
        server._handle_mediation(
            left,
            b'{"kind":"mediation-request","opaque_ancestor":false,"operation":1,"path":".x","path_component":".x","sensitivity":"other","session_id":"s"}\n',
        )
        assert b'"allowed":false' in right.recv(4096)
    finally:
        left.close()
        right.close()

    left, right = socket.socketpair()
    try:
        server._handle_mediation(
            left,
            b'{"kind":"mediation-request","opaque_ancestor":"bad","operation":"read","path":".x","path_component":".x","sensitivity":"other","session_id":"s"}\n',
        )
        assert b'"allowed":false' in right.recv(4096)
    finally:
        left.close()
        right.close()

    class WrongPeer:
        def getsockopt(self, _level: int, _option: int, _length: int) -> bytes:
            return struct.pack("3i", os.getpid(), os.getuid() + 1, os.getgid())

        def recv(self, _size: int) -> bytes:
            return b""

        def sendall(self, _data: bytes) -> None:
            pass

    server._handle(WrongPeer())  # type: ignore[arg-type]
    left, right = socket.socketpair()
    try:
        with pytest.raises(ApprovalProtocolError):
            _write_frame(left, {"value": "x" * 5000})
    finally:
        left.close()
        right.close()
