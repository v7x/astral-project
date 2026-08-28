"""Integrated profile-learning workflow over sandbox and projected-home enforcement."""

from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable, Sequence
from pathlib import Path

from astral_project.homed.mediation import MediationDecision, PendingRequest, UnknownPathMediator
from astral_project.profile import (
    ApprovalProvenance,
    Operation,
    Rule,
    RuleMode,
    RuleScope,
)
from astral_project.profile_lifecycle import ProfileStore
from astral_project.sandbox.command import DaemonRequest, run_sandbox
from astral_project.sandbox.environment import EnvironmentPolicy


def _empty_daemon_request(
    _operation: str, _payload: dict[str, object] | None = None
) -> dict[str, object]:
    return {}


class LearnerError(RuntimeError):
    """Learning cannot start or cannot preserve its profile transaction."""


class ProfileLearner:
    """Join profile persistence, mediation, projected home, and sandbox lifecycle."""

    def __init__(
        self,
        store: ProfileStore,
        *,
        state_root: Path,
        home_root: Path | None = None,
        sandbox_runner: Callable[..., int] = run_sandbox,
    ) -> None:
        self.store = store
        self.state_root = state_root
        self.home_root = Path.home() if home_root is None else home_root
        self.sandbox_runner = sandbox_runner

    def run(
        self,
        profile_id: str,
        command: Sequence[str],
        *,
        runtime: Path,
        approval_socket: Path | None = None,
        observer: Callable[[PendingRequest], None] | None = None,
        external_only: bool = False,
        session_id: str | None = None,
        grant_id: str | None = None,
        remotes: Sequence[str] = (),
        daemon_request: DaemonRequest | None = None,
    ) -> int:
        if not command or any(not item or "\x00" in item for item in command):
            raise LearnerError("learner command is empty or contains NUL")
        if (grant_id is None) != (not remotes):
            raise LearnerError("remote learner bindings require --grant and at least one --remote")
        if grant_id is not None and daemon_request is None:
            raise LearnerError("remote learner bindings require daemon authority")
        profile = self.store.load(profile_id)
        if profile.sealed:
            raise LearnerError("sealed profile cannot start learning")
        writable = {
            rule.mode
            for rule in profile.rules
            if rule.mode in {RuleMode.PRIVATE_RW, RuleMode.OVERLAY_RW}
        }
        draft: list[tuple[Rule, ApprovalProvenance]] = []
        decision_observer = self._decision_observer(profile_id, draft)
        mediator = UnknownPathMediator(observer=observer, decision_observer=decision_observer)
        arguments = ["sandbox", "--network", "none"]
        if grant_id is not None:
            arguments.extend(["--grant", grant_id])
            for remote in remotes:
                arguments.extend(["--remote", remote])
        arguments.extend(
            [
                "--profile",
                str(self.store.path(profile_id)),
                "--home-root",
                str(self.home_root),
            ]
        )
        if approval_socket is not None:
            arguments.extend(["--approval-socket", str(approval_socket)])
        if external_only and approval_socket is None:
            arguments.extend(["--approval-socket", str(runtime / "approval" / "approval.sock")])
        if RuleMode.PRIVATE_RW in writable:
            arguments.extend(
                ["--private-root", str(self.state_root / "profiles" / profile_id / "private")]
            )
        if RuleMode.OVERLAY_RW in writable:
            arguments.extend(
                ["--overlay-root", str(self.state_root / "profiles" / profile_id / "overlay")]
            )
        arguments.extend(["--", *command])
        try:
            result = self.sandbox_runner(
                arguments,
                daemon_request=daemon_request or _empty_daemon_request,
                runtime=runtime,
                approval_observer=observer,
                approval_input_fd=-1 if external_only else None,
                approval_mediator=mediator,
                audit_sink=self.store.audit_sink,
                session_id=session_id,
            )
            if result == 0 and draft:
                self.store.commit_learning_batch(profile_id, tuple(draft))
            return result
        finally:
            draft.clear()

    def _decision_observer(
        self, profile_id: str, draft: list[tuple[Rule, ApprovalProvenance]]
    ) -> Callable[[PendingRequest, str, MediationDecision], None]:
        def persist(request: PendingRequest, path: str, decision: MediationDecision) -> None:
            if decision is not MediationDecision.ALLOW_ONCE:
                return
            mode = RuleMode.HOST_RX if request.operation is Operation.EXECUTE else RuleMode.HOST_RO
            digest = hashlib.sha256(
                f"{request.session_id}:{request.request_number}:{request.operation.value}:{path}".encode()
            ).hexdigest()
            provenance = ApprovalProvenance(
                "trusted-approval", request.session_id, digest, int(time.time())
            )
            draft.append((Rule(path, RuleScope.EXACT, mode, request.sensitivity), provenance))

        return persist


def learner_environment() -> dict[str, str]:
    """Expose same environment boundary used by sandbox launcher."""
    return EnvironmentPolicy().sanitize(os.environ).values
