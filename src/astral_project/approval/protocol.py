"""Length-bounded external approval socket, never exposed to sandbox."""

from __future__ import annotations

import json
import os
import socket
import stat
import struct
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from astral_project.homed.mediation import (
    MediationDecision,
    UnknownPathMediator,
)
from astral_project.profile import Operation, Sensitivity

_MAX_FRAME: Final[int] = 4096
_PEERCRED_STRUCT: Final[str] = "3i"


class ApprovalProtocolError(ValueError):
    """Malformed or unauthorized approval protocol message."""


@dataclass(frozen=True, slots=True)
class ApprovalRequest:
    session_id: str
    request_number: int
    decision: MediationDecision

    def __post_init__(self) -> None:
        if (
            not self.session_id
            or self.request_number <= 0
            or self.decision
            not in {
                MediationDecision.ALLOW_ONCE,
                MediationDecision.DENY,
                MediationDecision.HIDE,
            }
        ):
            raise ApprovalProtocolError("approval request fields are invalid")

    def to_json(self) -> bytes:
        payload = {
            "decision": self.decision.value,
            "request_number": self.request_number,
            "session_id": self.session_id,
        }
        encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        if len(encoded) > _MAX_FRAME:
            raise ApprovalProtocolError("approval request is too large")
        return encoded + b"\n"

    @classmethod
    def from_json(cls, raw: bytes) -> ApprovalRequest:
        if len(raw) > _MAX_FRAME or not raw.endswith(b"\n"):
            raise ApprovalProtocolError("approval frame is too large or incomplete")
        try:
            value = json.loads(raw[:-1])
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ApprovalProtocolError("approval frame is not valid JSON") from error
        if not isinstance(value, dict) or set(value) != {
            "decision",
            "request_number",
            "session_id",
        }:
            raise ApprovalProtocolError("approval fields are incomplete or unknown")
        if (
            not isinstance(value["session_id"], str)
            or not isinstance(value["request_number"], int)
            or isinstance(value["request_number"], bool)
            or not isinstance(value["decision"], str)
        ):
            raise ApprovalProtocolError("approval field types are invalid")
        try:
            return cls(
                session_id=value["session_id"],
                request_number=value["request_number"],
                decision=MediationDecision(value["decision"]),
            )
        except (ApprovalProtocolError, ValueError) as error:
            raise ApprovalProtocolError("approval decision is invalid") from error


class ApprovalServer:
    """Serve exact-session approvals from a user-owned trusted runtime socket."""

    def __init__(
        self,
        path: Path,
        mediator: UnknownPathMediator,
        *,
        allow_decisions: bool = True,
        audit_sink: Callable[[str, str, str, dict[str, object]], None] | None = None,
    ) -> None:
        if not path.is_absolute():
            raise ApprovalProtocolError("approval socket path must be absolute")
        self.path = path
        self.mediator = mediator
        self.allow_decisions = allow_decisions
        self.audit_sink = audit_sink
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = self.path.parent.stat()
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) & 0o077:
            raise ApprovalProtocolError("approval socket parent is not private to current user")
        with suppress(FileNotFoundError):
            self.path.unlink()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(os.fspath(self.path))
        os.chmod(self.path, 0o600)
        listener.listen(8)
        listener.settimeout(0.2)
        self._listener = listener
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        listener = self._listener
        if listener is not None:
            listener.close()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2)
        with suppress(FileNotFoundError):
            self.path.unlink()

    def _serve(self) -> None:
        listener = self._listener
        if listener is None:
            return
        while not self._stop.is_set():
            try:
                connection, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            thread = threading.Thread(
                target=self._serve_connection, args=(connection,), daemon=True
            )
            thread.start()

    def _serve_connection(self, connection: socket.socket) -> None:
        with connection:
            self._handle(connection)

    def _handle_mediation(self, connection: socket.socket, raw: bytes) -> None:
        try:
            value = json.loads(raw[:-1])
            if not isinstance(value, dict) or set(value) != {
                "kind",
                "opaque_ancestor",
                "operation",
                "path",
                "path_component",
                "sensitivity",
                "session_id",
            }:
                raise ApprovalProtocolError("mediation fields are incomplete or unknown")
            if any(
                not isinstance(value[key], str)
                for key in ("operation", "path", "path_component", "sensitivity", "session_id")
            ):
                raise ApprovalProtocolError("mediation string fields are invalid")
            if not isinstance(value["opaque_ancestor"], bool):
                raise ApprovalProtocolError("mediation opaque flag is invalid")
            result = self.mediator.request(
                session_id=value["session_id"],
                path=value["path"],
                path_component=value["path_component"],
                operation=Operation(value["operation"]),
                sensitivity=Sensitivity(value["sensitivity"]),
                opaque_ancestor=value["opaque_ancestor"],
            )
            if self.audit_sink is not None:  # pragma: no branch - optional audit integration
                self.audit_sink(
                    "profile.requested",
                    "session",
                    value["session_id"],
                    {
                        "operation": value["operation"],
                        "path": value["path"],
                        "sensitivity": value["sensitivity"],
                    },
                )
                self.audit_sink(
                    "profile.approved" if result.allowed else "profile.denied",
                    "session",
                    value["session_id"],
                    {"decision": result.decision.value},
                )
            _write_frame(
                connection,
                {
                    "allowed": result.allowed,
                    "decision": result.decision.value,
                    "hidden": result.hidden,
                },
            )
        except (
            ApprovalProtocolError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            _write_frame(
                connection,
                {"allowed": False, "decision": "cancelled", "error": str(error), "hidden": True},
            )

    def _handle(self, connection: socket.socket) -> None:
        try:
            uid = struct.unpack(
                _PEERCRED_STRUCT,
                connection.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_PEERCRED,
                    struct.calcsize(_PEERCRED_STRUCT),
                ),
            )[1]
            if uid != os.getuid():
                raise ApprovalProtocolError("approval peer is not current user")
            raw = _read_frame(connection)
            if _is_mediation_frame(raw):
                self._handle_mediation(connection, raw)
                return
            if not self.allow_decisions:
                raise ApprovalProtocolError(
                    "external decisions are disabled on mediation transport"
                )
            request = ApprovalRequest.from_json(raw)
            accepted = self.mediator.decide(
                session_id=request.session_id,
                request_number=request.request_number,
                decision=request.decision,
            )
            if self.audit_sink is not None:  # pragma: no branch - optional audit integration
                self.audit_sink(
                    "profile.approval",
                    "session",
                    request.session_id,
                    {"decision": request.decision.value, "accepted": accepted},
                )
            _write_frame(connection, {"accepted": accepted})
        except (ApprovalProtocolError, OSError, struct.error) as error:
            _write_frame(connection, {"accepted": False, "error": str(error)})


class ApprovalClient:
    """Send one exact approval decision to trusted external controller."""

    def __init__(self, path: Path, *, timeout: float = 2.0) -> None:
        if not path.is_absolute() or timeout <= 0:
            raise ApprovalProtocolError("approval client configuration is invalid")
        self.path = path
        self.timeout = timeout

    def approve(self, request: ApprovalRequest) -> bool:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(os.fspath(self.path))
                connection.sendall(request.to_json())
                response = json.loads(_read_frame(connection)[:-1])
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ApprovalProtocolError("approval socket request failed") from error
        return isinstance(response, dict) and response.get("accepted") is True


def _is_mediation_frame(raw: bytes) -> bool:
    try:
        value = json.loads(raw[:-1])
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    return isinstance(value, dict) and value.get("kind") == "mediation-request"


def _read_frame(connection: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= _MAX_FRAME:
        chunk = connection.recv(1024)
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if not data or len(data) > _MAX_FRAME or b"\n" not in data:
        raise ApprovalProtocolError("approval frame is too large or incomplete")
    return bytes(data).split(b"\n", 1)[0] + b"\n"


def _write_frame(connection: socket.socket, value: dict[str, object]) -> None:
    encoded = json.dumps(value, separators=(",", ":"), sort_keys=True).encode() + b"\n"
    if len(encoded) > _MAX_FRAME:
        raise ApprovalProtocolError("approval response is too large")
    connection.sendall(encoded)
