"""Bounded, fail-closed mediation for unknown projected-home paths."""

from __future__ import annotations

import json
import socket
import time
from collections import deque
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from threading import Condition, RLock
from typing import Final

from astral_project.profile import Operation, Sensitivity


class MediationDecision(StrEnum):
    ALLOW_ONCE = "allow-once"
    DENY = "deny"
    HIDE = "hide"
    TIMEOUT = "timeout"
    QUEUE_FULL = "queue-full"
    RATE_LIMITED = "rate-limited"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class ProvenanceSkeleton:
    """Non-authoritative bounded provenance attached for diagnostics only."""

    source: str = "unknown"
    observer: str | None = None

    def __post_init__(self) -> None:
        if not self.source or len(self.source) > 64:
            raise ValueError("provenance source is invalid")
        if self.observer is not None and len(self.observer) > 64:
            raise ValueError("provenance observer is invalid")


@dataclass(frozen=True, slots=True)
class PendingRequest:
    """Minimal request data safe for approval display or diagnostic observers."""

    session_id: str
    request_number: int
    operation: Operation
    path_component: str
    opaque_ancestor: bool
    sensitivity: Sensitivity
    deadline: float
    provenance: ProvenanceSkeleton = ProvenanceSkeleton()

    @property
    def key(self) -> tuple[str, int]:
        return self.session_id, self.request_number


@dataclass(frozen=True, slots=True)
class MediationResult:
    allowed: bool
    hidden: bool
    decision: MediationDecision
    request: PendingRequest | None = None


@dataclass(slots=True)
class _Pending:
    request: PendingRequest
    full_path: str
    condition: Condition
    result: MediationResult | None = None
    waiters: int = 0


Observer = Callable[[PendingRequest], None]
DecisionObserver = Callable[[PendingRequest, str, MediationDecision], None]
_DEFAULT_TIMEOUT: Final[float] = 5.0


class RemoteUnknownPathMediator:
    """Forward unknown requests to a trusted parent mediator over a private socket."""

    def __init__(self, path: str, *, timeout: float = _DEFAULT_TIMEOUT) -> None:
        if not path or timeout <= 0:
            raise ValueError("remote mediation configuration is invalid")
        self.path = path
        self.timeout = timeout

    def request(
        self,
        *,
        session_id: str,
        path: str,
        path_component: str,
        operation: Operation,
        sensitivity: Sensitivity,
        opaque_ancestor: bool = False,
    ) -> MediationResult:
        payload = {
            "kind": "mediation-request",
            "opaque_ancestor": opaque_ancestor,
            "operation": operation.value,
            "path": path,
            "path_component": path_component,
            "sensitivity": sensitivity.value,
            "session_id": session_id,
        }
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout + 1)
                connection.connect(self.path)
                connection.sendall(json.dumps(payload, separators=(",", ":")).encode() + b"\n")
                raw = _read_socket_line(connection)
                value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("mediation response is not an object")
            decision = MediationDecision(value["decision"])
            return MediationResult(
                bool(value.get("allowed", False)),
                bool(value.get("hidden", True)),
                decision,
            )
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return MediationResult(False, True, MediationDecision.CANCELLED)

    def cancel_session(self, _session_id: str) -> int:
        return 0


class UnknownPathMediator:
    """Coordinate bounded unknown-path decisions without granting persistent policy."""

    def __init__(
        self,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        max_pending: int = 32,
        max_requests_per_session: int = 32,
        observer: Observer | None = None,
        decision_observer: DecisionObserver | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if timeout <= 0 or max_pending <= 0 or max_requests_per_session <= 0:
            raise ValueError("mediation bounds must be positive")
        self.timeout = timeout
        self.max_pending = max_pending
        self.max_requests_per_session = max_requests_per_session
        self._observer = observer
        self._decision_observer = decision_observer
        self._clock = clock
        self._lock = RLock()
        self._pending: dict[tuple[str, int], _Pending] = {}
        self._coalesced: dict[tuple[str, str, Operation], _Pending] = {}
        self._allowed_once: set[tuple[str, str, Operation]] = set()
        self._next_request: dict[str, int] = {}
        self._recent: dict[str, deque[float]] = {}

    def request(
        self,
        *,
        session_id: str,
        path: str,
        path_component: str,
        operation: Operation,
        sensitivity: Sensitivity,
        opaque_ancestor: bool = False,
    ) -> MediationResult:
        """Block until trusted decision or bounded fail-closed completion."""
        if not session_id or not path or not path_component:
            raise ValueError("mediation request identity and path are required")
        now = self._clock()
        key = (session_id, path, operation)
        with self._lock:
            self._prune_recent(session_id, now)
            if key in self._allowed_once and sensitivity is not Sensitivity.CREDENTIAL:
                return MediationResult(True, False, MediationDecision.ALLOW_ONCE)
            existing = self._coalesced.get(key)
            if existing is not None:
                pending = existing
            elif len(self._pending) >= self.max_pending:
                return MediationResult(False, False, MediationDecision.QUEUE_FULL)
            elif len(self._recent.get(session_id, ())) >= self.max_requests_per_session:
                return MediationResult(False, False, MediationDecision.RATE_LIMITED)
            else:
                number = self._next_request.get(session_id, 0) + 1
                self._next_request[session_id] = number
                request = PendingRequest(
                    session_id=session_id,
                    request_number=number,
                    operation=operation,
                    path_component=path_component,
                    opaque_ancestor=opaque_ancestor,
                    sensitivity=sensitivity,
                    deadline=now + self.timeout,
                )
                pending = _Pending(
                    request=request,
                    full_path=path,
                    condition=Condition(self._lock),
                )
                self._pending[request.key] = pending
                self._coalesced[key] = pending
                self._recent.setdefault(session_id, deque()).append(now)
                observer = self._observer
                if observer is not None:
                    with suppress(Exception):
                        observer(request)
            pending.waiters += 1
            try:
                while pending.result is None:
                    remaining = pending.request.deadline - self._clock()
                    if remaining <= 0:
                        self._finish(
                            pending,
                            MediationResult(
                                False, True, MediationDecision.TIMEOUT, pending.request
                            ),
                        )
                        break
                    pending.condition.wait(timeout=remaining)
                result = pending.result
                assert result is not None
                return result
            finally:
                pending.waiters -= 1
                if pending.waiters == 0 and pending.result is not None:
                    self._remove(pending)

    def decide(
        self,
        *,
        session_id: str,
        request_number: int,
        decision: MediationDecision,
    ) -> bool:
        """Apply decision only to exact live session/request identity."""
        if decision not in {
            MediationDecision.ALLOW_ONCE,
            MediationDecision.DENY,
            MediationDecision.HIDE,
        }:
            raise ValueError("only allow-once, deny, or hide may be trusted decisions")
        with self._lock:
            pending = self._pending.get((session_id, request_number))
            if pending is None or pending.result is not None:
                return False
            callback = self._decision_observer
            if callback is not None:
                try:
                    callback(pending.request, pending.full_path, decision)
                except Exception:
                    self._finish(
                        pending,
                        MediationResult(False, True, MediationDecision.CANCELLED, pending.request),
                    )
                    return False
            self._finish(
                pending,
                MediationResult(
                    decision is MediationDecision.ALLOW_ONCE,
                    decision is MediationDecision.HIDE,
                    decision,
                    pending.request,
                ),
            )
            return True

    def cancel_session(self, session_id: str) -> int:
        with self._lock:
            values = [p for p in self._pending.values() if p.request.session_id == session_id]
            for pending in values:
                self._finish(
                    pending,
                    MediationResult(False, True, MediationDecision.CANCELLED, pending.request),
                )
            self._allowed_once = {key for key in self._allowed_once if key[0] != session_id}
            return len(values)

    def pending(self) -> tuple[PendingRequest, ...]:
        with self._lock:
            return tuple(
                pending.request for pending in self._pending.values() if pending.result is None
            )

    def _finish(self, pending: _Pending, result: MediationResult) -> None:
        if pending.result is not None:
            return
        pending.result = result
        if (
            result.decision is MediationDecision.ALLOW_ONCE
            and pending.request.sensitivity is not Sensitivity.CREDENTIAL
        ):
            self._allowed_once.add(
                (pending.request.session_id, pending.full_path, pending.request.operation)
            )
        pending.condition.notify_all()

    def _remove(self, pending: _Pending) -> None:
        self._pending.pop(pending.request.key, None)
        self._coalesced.pop(
            (pending.request.session_id, pending.full_path, pending.request.operation), None
        )

    def _prune_recent(self, session_id: str, now: float) -> None:
        recent = self._recent.setdefault(session_id, deque())
        cutoff = now - self.timeout
        while recent and recent[0] < cutoff:
            recent.popleft()


def _read_socket_line(connection: socket.socket) -> bytes:
    data = bytearray()
    while len(data) <= 4096:
        chunk = connection.recv(1024)
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            break
    if not data or len(data) > 4096 or b"\n" not in data:
        raise ValueError("mediation response is incomplete")
    return bytes(data).split(b"\n", 1)[0]
