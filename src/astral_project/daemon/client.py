"""Client for daemon control IPC."""

from __future__ import annotations

import json
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
        self,
        *,
        request_id: str,
        cancellation_id: str,
        operation: str,
        payload: Mapping[str, object] | None = None,
    ) -> Mapping[str, object]:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.connect(str(self.socket_path))
            request: dict[str, object] = {
                "cancellation_id": cancellation_id,
                "kind": "request",
                "operation": operation,
                "request_id": request_id,
                "version": 1,
            }
            if payload is not None:
                request["payload"] = dict(payload)
            connection.sendall(encode(request))
            response = receive(connection)
        except OSError as error:
            raise _error("could not contact daemon", str(error)) from error
        finally:
            connection.close()
        if response.get("kind") != "response" or response.get("request_id") != request_id:
            raise _error(
                "daemon returned invalid response "
                + json.dumps(response, separators=(",", ":"), sort_keys=True),
            )
        result = response.get("result")
        if response.get("ok") is not True or not isinstance(result, dict):
            detail = result.get("message") if isinstance(result, dict) else None
            dependency = result.get("dependency_error") if isinstance(result, dict) else None
            suffix = ""
            if isinstance(detail, str):
                suffix += f": {detail}"
            if isinstance(dependency, str) and dependency:
                suffix += f" ({dependency})"
            raise _error(
                "daemon rejected request" + suffix,
                dependency if isinstance(dependency, str) else None,
            )
        return result
