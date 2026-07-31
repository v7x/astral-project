"""Client for daemon control IPC."""

from __future__ import annotations

import socket
from collections.abc import Mapping
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.daemon.protocol import encode, receive


def _error(message: str, dependency_error: str | None = None) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_UNAVAILABLE,
        message=message,
        security_result="daemon request was not sent",
        unsafe_reason="trusted daemon control socket is unavailable",
        next_action="start trusted daemon, then retry",
        dependency_error=dependency_error,
    )


class DaemonClient:
    """One request per short-lived same-user Unix connection."""

    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path

    def request(
        self, *, request_id: str, cancellation_id: str, operation: str
    ) -> Mapping[str, object]:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(str(self.socket_path))
            connection.sendall(
                encode(
                    {
                        "cancellation_id": cancellation_id,
                        "kind": "request",
                        "operation": operation,
                        "request_id": request_id,
                        "version": 1,
                    }
                )
            )
            response = receive(connection)
        except OSError as error:
            raise _error("could not contact daemon", str(error)) from error
        finally:
            connection.close()
        if response.get("kind") != "response" or response.get("request_id") != request_id:
            raise _error("daemon returned invalid response")
        result = response.get("result")
        if response.get("ok") is not True or not isinstance(result, dict):
            raise _error("daemon rejected request")
        return result
