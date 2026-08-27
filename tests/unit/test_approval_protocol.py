from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import cast

import pytest

from astral_project.approval.protocol import (
    ApprovalClient,
    ApprovalProtocolError,
    ApprovalRequest,
    ApprovalServer,
)
from astral_project.homed.mediation import (
    MediationDecision,
    MediationResult,
    RemoteUnknownPathMediator,
    UnknownPathMediator,
)
from astral_project.profile import Operation, Sensitivity


def test_approval_request_round_trip_and_strict_fields() -> None:
    request = ApprovalRequest("session", 3, MediationDecision.ALLOW_ONCE)
    assert ApprovalRequest.from_json(request.to_json()) == request
    with pytest.raises(ApprovalProtocolError):
        ApprovalRequest.from_json(b'{"session_id":"s"}\n')
    with pytest.raises(ApprovalProtocolError):
        ApprovalRequest.from_json(b'{"decision":"timeout","request_number":1,"session_id":"s"}\n')
    with pytest.raises(ApprovalProtocolError):
        ApprovalRequest("", 1, MediationDecision.DENY)
    with pytest.raises(ApprovalProtocolError):
        ApprovalRequest.from_json(b"x" * 4097)


def _pending(mediator: UnknownPathMediator) -> tuple[threading.Thread, int]:
    def wait() -> None:
        mediator.request(
            session_id="session",
            path=".secret",
            path_component=".secret",
            operation=Operation.READ,
            sensitivity=Sensitivity.CREDENTIAL,
        )

    thread = threading.Thread(target=wait)
    thread.start()
    for _ in range(100):
        if mediator.pending():
            return thread, mediator.pending()[0].request_number
        time.sleep(0.001)
    raise AssertionError("pending request was not created")


def test_external_approval_accepts_exact_request_and_rejects_stale(tmp_path: Path) -> None:
    mediator = UnknownPathMediator(timeout=1)
    thread, number = _pending(mediator)
    socket_path = tmp_path / "approval.sock"
    server = ApprovalServer(socket_path, mediator)
    server.start()
    try:
        client = ApprovalClient(socket_path)
        assert not client.approve(ApprovalRequest("other", number, MediationDecision.ALLOW_ONCE))
        assert client.approve(ApprovalRequest("session", number, MediationDecision.ALLOW_ONCE))
        thread.join(1)
        assert not thread.is_alive()
        assert socket_path.stat().st_mode & 0o777 == 0o600
    finally:
        server.close()
    assert not socket_path.exists()


def test_remote_mediation_round_trip(tmp_path: Path) -> None:
    parent = UnknownPathMediator(timeout=1)
    socket_path = tmp_path / "mediation.sock"
    server = ApprovalServer(socket_path, parent)
    server.start()
    result: dict[str, object] = {}

    def run() -> None:
        result["value"] = RemoteUnknownPathMediator(str(socket_path)).request(
            session_id="session",
            path=".secret",
            path_component=".secret",
            operation=Operation.READ,
            sensitivity=Sensitivity.CREDENTIAL,
        )

    thread = threading.Thread(target=run)
    thread.start()
    try:
        for _ in range(100):
            if parent.pending():
                break
            time.sleep(0.001)
        request = parent.pending()[0]
        assert ApprovalClient(socket_path).approve(
            ApprovalRequest("session", request.request_number, MediationDecision.ALLOW_ONCE)
        )
        thread.join(1)
        assert cast(MediationResult, result["value"]).allowed is True
    finally:
        server.close()


def test_approval_client_reports_missing_socket_and_server_rejects_bad_frame(
    tmp_path: Path,
) -> None:
    client = ApprovalClient(tmp_path / "missing.sock")
    with pytest.raises(ApprovalProtocolError):
        client.approve(ApprovalRequest("s", 1, MediationDecision.DENY))

    path = tmp_path / "bad.sock"
    server = ApprovalServer(path, UnknownPathMediator())
    server.start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect(str(path))
            connection.sendall(b"bad\n")
            assert b'"accepted":false' in connection.recv(4096)
    finally:
        server.close()
