from __future__ import annotations

import errno
import socket
import threading
import time
from pathlib import Path
from typing import cast

import pytest

from astral_project.homed.host import HostAccessError, HostReadonlyView
from astral_project.homed.mediation import (
    MediationDecision,
    MediationResult,
    ProvenanceSkeleton,
    RemoteUnknownPathMediator,
    UnknownPathMediator,
    _read_socket_line,
)
from astral_project.profile import Operation, Profile, Sensitivity


def _profile(*, sealed: bool = False) -> Profile:
    return Profile.from_toml(
        f"""
        version = 1
        id = "p"
        name = "p"
        sealed = {str(sealed).lower()}
        unknown_learning = "prompt"
        [[home.rules]]
        path = ".known"
        mode = "host-ro"
        [[home.rules]]
        path = ".opaque/child"
        mode = "host-ro"
        """
    )


def _request(mediator: UnknownPathMediator, path: str = ".secret") -> dict[str, object]:
    result: dict[str, object] = {}

    def run() -> None:
        result["value"] = mediator.request(
            session_id="session",
            path=path,
            path_component=path.rsplit("/", 1)[-1],
            operation=Operation.READ,
            sensitivity=Sensitivity.OTHER,
        )

    thread = threading.Thread(target=run)
    thread.start()
    for _ in range(100):
        if mediator.pending():
            break
        time.sleep(0.001)
    result["thread"] = thread
    return result


def test_provenance_skeleton_is_bounded_and_non_authoritative() -> None:
    assert ProvenanceSkeleton().source == "unknown"
    assert ProvenanceSkeleton("observer", "diagnostic").observer == "diagnostic"
    with pytest.raises(ValueError):
        ProvenanceSkeleton("x" * 65)
    with pytest.raises(ValueError):
        ProvenanceSkeleton("observer", "x" * 65)


def test_mediator_rejects_bad_requests_and_remote_failure(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        UnknownPathMediator().request(
            session_id="",
            path=".x",
            path_component=".x",
            operation=Operation.READ,
            sensitivity=Sensitivity.OTHER,
        )
    with pytest.raises(ValueError):
        RemoteUnknownPathMediator("", timeout=1)
    result = RemoteUnknownPathMediator("/tmp/missing-approval.sock", timeout=0.01).request(
        session_id="s",
        path=".x",
        path_component=".x",
        operation=Operation.READ,
        sensitivity=Sensitivity.OTHER,
    )
    assert result.decision is MediationDecision.CANCELLED
    assert RemoteUnknownPathMediator("/tmp/missing.sock").cancel_session("s") == 0
    path = tmp_path / "bad-response.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen(1)

    def serve_bad() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(4096)
            connection.sendall(b"[]\n")

    thread = threading.Thread(target=serve_bad)
    thread.start()
    assert (
        RemoteUnknownPathMediator(str(path), timeout=1)
        .request(
            session_id="s",
            path=".x",
            path_component=".x",
            operation=Operation.READ,
            sensitivity=Sensitivity.OTHER,
        )
        .decision
        is MediationDecision.CANCELLED
    )
    thread.join(1)
    listener.close()
    left, right = socket.socketpair()
    try:
        left.sendall(b"x" * 4097)
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(ValueError):
            _read_socket_line(right)
    finally:
        left.close()
        right.close()
    left, right = socket.socketpair()
    try:
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(ValueError):
            _read_socket_line(right)
    finally:
        left.close()
        right.close()


def test_mediator_finish_is_idempotent() -> None:
    mediator = UnknownPathMediator(timeout=1)
    result = _request(mediator, ".idempotent")
    pending = next(iter(mediator._pending.values()))
    with mediator._lock:
        mediator._finish(pending, MediationResult(False, True, MediationDecision.HIDE))
        mediator._finish(pending, MediationResult(False, True, MediationDecision.DENY))
    cast(threading.Thread, result["thread"]).join(1)
    assert cast(MediationResult, result["value"]).decision is MediationDecision.HIDE


def test_mediator_approval_is_exact_and_minimal() -> None:
    observed: list[object] = []
    mediator = UnknownPathMediator(timeout=1, observer=observed.append)
    result = _request(mediator)
    request = mediator.pending()[0]
    assert request.path_component == ".secret"
    assert request.provenance.source == "unknown"
    assert not hasattr(request, "full_path")
    assert (
        mediator.decide(
            session_id="other",
            request_number=request.request_number,
            decision=MediationDecision.ALLOW_ONCE,
        )
        is False
    )
    assert mediator.decide(
        session_id="session",
        request_number=request.request_number,
        decision=MediationDecision.ALLOW_ONCE,
    )
    assert not mediator.decide(
        session_id="session",
        request_number=request.request_number,
        decision=MediationDecision.DENY,
    )
    thread = result["thread"]
    assert isinstance(thread, threading.Thread)
    thread.join(1)
    assert cast(MediationResult, result["value"]).allowed is True
    assert observed == [request]
    assert mediator.pending() == ()
    assert mediator.request(
        session_id="session",
        path=".secret",
        path_component=".secret",
        operation=Operation.READ,
        sensitivity=Sensitivity.OTHER,
    ).allowed
    assert mediator.cancel_session("session") == 0


def test_mediator_timeout_hides_and_cancel_is_fail_closed() -> None:
    mediator = UnknownPathMediator(timeout=0.01)
    result = _request(mediator)
    thread = result["thread"]
    assert isinstance(thread, threading.Thread)
    thread.join(1)
    assert cast(MediationResult, result["value"]).decision is MediationDecision.TIMEOUT
    result = _request(mediator, ".other")
    assert mediator.cancel_session("session") == 1
    thread = result["thread"]
    assert isinstance(thread, threading.Thread)
    thread.join(1)
    assert cast(MediationResult, result["value"]).decision is MediationDecision.CANCELLED


def test_mediator_coalesces_and_bounds_queue_and_rate() -> None:
    mediator = UnknownPathMediator(timeout=1, max_pending=1, max_requests_per_session=1)
    first = _request(mediator)
    second = _request(mediator)
    assert len(mediator.pending()) == 1
    assert mediator.decide(session_id="session", request_number=1, decision=MediationDecision.DENY)
    for value in (first["thread"], second["thread"]):
        assert isinstance(value, threading.Thread)
        value.join(1)
    assert cast(MediationResult, first["value"]).allowed is False
    full = _request(mediator, ".full")
    assert mediator.pending() == ()
    cast(threading.Thread, full["thread"]).join(1)
    limited = _request(mediator, ".limited")
    cast(threading.Thread, limited["thread"]).join(1)
    assert cast(MediationResult, limited["value"]).decision is MediationDecision.RATE_LIMITED


def test_mediator_queue_full_and_invalid_decision() -> None:
    mediator = UnknownPathMediator(timeout=1, max_pending=1, max_requests_per_session=4)
    first = _request(mediator, ".first")
    second = _request(mediator, ".second")
    cast(threading.Thread, second["thread"]).join(1)
    assert cast(MediationResult, second["value"]).decision is MediationDecision.QUEUE_FULL
    request = mediator.pending()[0]
    with pytest.raises(ValueError):
        mediator.decide(
            session_id="session",
            request_number=request.request_number,
            decision=MediationDecision.TIMEOUT,
        )
    mediator.decide(
        session_id="session", request_number=request.request_number, decision=MediationDecision.HIDE
    )
    cast(threading.Thread, first["thread"]).join(1)


def test_host_view_unknown_denial_and_remote_cancel(tmp_path: Path) -> None:
    root = tmp_path / "home"
    root.mkdir()
    mediator = UnknownPathMediator(timeout=1)
    with HostReadonlyView(root, _profile(), mediator=mediator, session_id="session") as view:
        result: dict[str, object] = {}

        def lookup_unknown() -> None:
            with pytest.raises(HostAccessError) as error:
                view.lookup(".secret")
            assert error.value.errno == errno.EACCES
            result["done"] = True

        thread = threading.Thread(target=lookup_unknown)
        thread.start()
        for _ in range(100):
            if mediator.pending():
                break
            time.sleep(0.001)
        request = mediator.pending()[0]
        mediator.decide(
            session_id=request.session_id,
            request_number=request.request_number,
            decision=MediationDecision.DENY,
        )
        thread.join(1)
        assert result["done"] is True
    with HostReadonlyView(
        root,
        _profile(),
        mediator=RemoteUnknownPathMediator("/tmp/missing.sock"),
        session_id="session",
    ) as view:
        assert view.cancel_pending() == 0
        assert view._unknown_sensitivity(".opaque") is Sensitivity.OTHER


def test_host_view_hide_preserves_not_found_semantics(tmp_path: Path) -> None:
    root = tmp_path / "home"
    root.mkdir()
    (root / ".hidden").write_text("hidden", encoding="utf-8")
    mediator = UnknownPathMediator(timeout=1)
    with HostReadonlyView(root, _profile(), mediator=mediator, session_id="session") as view:
        result: dict[str, object] = {}

        def read_hidden() -> None:
            try:
                view.read(".hidden")
            except BaseException as error:
                result["error"] = error

        thread = threading.Thread(target=read_hidden)
        thread.start()
        for _ in range(100):
            if mediator.pending():
                break
            time.sleep(0.001)
        request = mediator.pending()[0]
        assert mediator.decide(
            session_id=request.session_id,
            request_number=request.request_number,
            decision=MediationDecision.HIDE,
        )
        thread.join(1)
        error = result.get("error")
        assert isinstance(error, HostAccessError)
        assert error.errno == errno.ENOENT


def test_host_view_prompts_opaque_lookup_but_never_opaque_listing(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".opaque").mkdir(parents=True)
    (root / ".opaque/child").write_text("child", encoding="utf-8")
    mediator = UnknownPathMediator(timeout=1)
    with HostReadonlyView(root, _profile(), mediator=mediator, session_id="session") as view:
        result: dict[str, object] = {}

        def lookup_opaque() -> None:
            try:
                result["value"] = view.lookup(".opaque")
            except BaseException as error:
                result["error"] = error

        thread = threading.Thread(target=lookup_opaque)
        thread.start()
        for _ in range(100):
            if mediator.pending():
                break
            time.sleep(0.001)
        request = mediator.pending()[0]
        assert request.opaque_ancestor
        assert request.path_component == ".opaque"
        assert mediator.decide(
            session_id=request.session_id,
            request_number=request.request_number,
            decision=MediationDecision.ALLOW_ONCE,
        )
        thread.join(1)
        assert "error" not in result
        with pytest.raises(HostAccessError) as error:
            view.listdir(".opaque")
        assert error.value.errno == errno.EACCES


def test_host_view_prompts_unknown_but_never_prompts_opaque_listing(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".opaque").mkdir(parents=True)
    (root / ".opaque/child").write_text("child", encoding="utf-8")
    (root / ".secret").write_text("secret", encoding="utf-8")
    mediator = UnknownPathMediator(timeout=1)
    with HostReadonlyView(root, _profile(), mediator=mediator, session_id="session") as view:
        result: dict[str, object] = {}

        def read_unknown() -> None:
            result["value"] = view.read(".secret")

        thread = threading.Thread(target=read_unknown)
        thread.start()
        for _ in range(100):
            if mediator.pending():
                break
            time.sleep(0.001)
        request = mediator.pending()[0]
        assert request.operation is Operation.READ
        mediator.decide(
            session_id="session",
            request_number=request.request_number,
            decision=MediationDecision.ALLOW_ONCE,
        )
        thread.join(1)
        assert result["value"] == b"secret"
        with pytest.raises(HostAccessError) as error:
            view.listdir(".opaque")
        assert error.value.errno == errno.EACCES


def test_host_view_identity_and_cancel_without_mediator(tmp_path: Path) -> None:
    root = tmp_path / "home"
    root.mkdir()
    with pytest.raises(ValueError):
        HostReadonlyView(root, _profile(), session_id="")
    with HostReadonlyView(root, _profile()) as view:
        assert view.cancel_pending() == 0


def test_mediation_authoritative_callback_failure_cancels_request() -> None:
    def fail(*_args: object) -> None:
        raise RuntimeError("persist failed")

    mediator = UnknownPathMediator(decision_observer=fail)
    result: list[object] = []
    thread = threading.Thread(
        target=lambda: result.append(
            mediator.request(
                session_id="s",
                path="x",
                path_component="x",
                operation=Operation.READ,
                sensitivity=Sensitivity.OTHER,
            )
        )
    )
    thread.start()
    while not mediator.pending():
        pass
    assert not mediator.decide(
        session_id="s", request_number=1, decision=MediationDecision.ALLOW_ONCE
    )
    thread.join(timeout=1)
    assert result and isinstance(result[0], MediationResult)
    assert result[0].decision is MediationDecision.CANCELLED


def test_sealed_profile_and_invalid_bounds_fail_closed() -> None:
    with pytest.raises(ValueError):
        UnknownPathMediator(timeout=0)
    mediator = UnknownPathMediator(timeout=1)
    assert mediator.cancel_session("none") == 0
    root = Path("/tmp")
    with HostReadonlyView(root, _profile(sealed=True)) as view, pytest.raises(HostAccessError):
        view.lookup("astral-project-path-does-not-exist")
