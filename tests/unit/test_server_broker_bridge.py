"""Forced-entry raw SFTP bridge tests."""

from __future__ import annotations

import io
import socket
import threading

from astral_project.server.broker_bridge import bridge_sftp_stream


def test_bridge_forwards_raw_stdio_after_protocol_phase() -> None:
    bridge, worker = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    observed: list[bytes] = []

    def workload() -> None:
        try:
            observed.append(worker.recv(32))
            worker.sendall(b"SFTP-reply")
            worker.shutdown(socket.SHUT_WR)
        finally:
            worker.close()

    thread = threading.Thread(target=workload)
    thread.start()
    output = io.BytesIO()
    bridge_sftp_stream(bridge, stdin=io.BytesIO(b"SFTP-request"), stdout=output)
    thread.join(timeout=1)

    assert not thread.is_alive()
    assert observed == [b"SFTP-request"]
    assert output.getvalue() == b"SFTP-reply"
