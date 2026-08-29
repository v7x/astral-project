"""Execute fixed local sandbox plans and enforce remote-loss policy."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.sandbox.environment import EnvironmentPolicy
from astral_project.sandbox.hardening import (
    HardeningPolicy,
    RootRole,
    enforce,
    require_available,
)
from astral_project.sandbox.plan import LocalSandboxPlan

HealthCheck = Callable[[], bool]


def run_plan(
    plan: LocalSandboxPlan,
    *,
    health_check: HealthCheck | None = None,
    poll_seconds: float = 0.2,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    approval: object | None = None,
    environment_policy: EnvironmentPolicy | None = None,
    hardening: HardeningPolicy | None = None,
    audit_sink: Callable[[str, str, str, dict[str, object]], None] | None = None,
) -> int:
    """Run one plan; terminate child when any daemon-owned remote view is lost."""
    if poll_seconds <= 0:
        raise _error("sandbox health interval must be positive")
    if hardening is not None:
        try:
            require_available(hardening)
        except AstralError as error:
            _audit_hardening_failure(audit_sink, plan, error.code.string)
            raise
    if audit_sink is not None:
        audit_sink(
            "sandbox.launch",
            "sandbox",
            plan.session_id or "local",
            {
                "path": plan.command[0],
                "network": plan.network.value,
                "remote_count": len(plan.remotes),
            },
        )
    if approval is not None:
        from astral_project.approval.terminal import ApprovalController, TerminalControllerError

        if not isinstance(approval, ApprovalController):
            raise _error("sandbox approval controller has invalid type")
        try:
            result = approval.run(
                plan.launcher_argv(),
                env=_sandbox_environment(environment_policy, visible_paths=_visible_paths(plan)),
                preface=plan.plan_bytes(),
                health_check=health_check,
                preexec_fn=None,
            )
            if result == 70:
                _audit_hardening_failure(audit_sink, plan, ErrorCode.HARDENING_APPLY.string)
            return result
        except TerminalControllerError as error:
            raise _error(str(error), ErrorCode.DAEMON_UNAVAILABLE) from error
    try:
        process_kwargs: dict[str, object] = {
            "stdin": subprocess.PIPE,
            "stdout": None,
            "stderr": None,
            "env": _sandbox_environment(environment_policy, visible_paths=_visible_paths(plan)),
            "close_fds": True,
            "start_new_session": True,
        }
        process = popen(plan.launcher_argv(), **process_kwargs)
        if process.stdin is None:
            raise _error("fixed sandbox launcher stdin is unavailable")
        try:
            process.stdin.write(plan.plan_bytes())
            process.stdin.close()
        except OSError as error:
            _terminate(process)
            raise _error(
                "fixed sandbox launcher rejected plan", ErrorCode.DAEMON_UNAVAILABLE
            ) from error
    except OSError as error:
        raise _error(
            f"bubblewrap could not start: {error}", ErrorCode.DAEMON_UNAVAILABLE
        ) from error
    while process.poll() is None:
        if health_check is not None and not health_check():
            _terminate(process)
            raise _error(
                "daemon remote view was lost; sandbox terminated", ErrorCode.DAEMON_UNAVAILABLE
            )
        time.sleep(poll_seconds)
    result = int(process.returncode or 0)
    if result == 70:
        _audit_hardening_failure(audit_sink, plan, ErrorCode.HARDENING_APPLY.string)
    return result


def _enforce_policy(policy: HardeningPolicy) -> None:
    """Apply hardening for callers that own the final child process."""
    enforce(policy)


def _sandbox_environment(
    policy: EnvironmentPolicy | None = None, *, visible_paths: tuple[Path, ...] = ()
) -> dict[str, str]:
    """Return allowlisted, secret-free environment for both launcher paths."""
    return (policy or EnvironmentPolicy()).sanitize(os.environ, visible_paths=visible_paths).values


def hardening_policy(plan: LocalSandboxPlan) -> HardeningPolicy:
    """Derive second-wall roots from fixed namespace and exact plan bindings."""
    roots: list[tuple[Path, RootRole | bool]] = [(path, False) for path in _visible_paths(plan)]
    roots.extend((binding.host_path, binding.mode.value == "rw") for binding in plan.remotes)
    if plan.projected_home is not None:
        roots.append((plan.projected_home, plan.projected_home_writable))
    if plan.host_rx_manifest is not None:
        roots.append((plan.host_rx_manifest, False))
    if plan.session_socket is not None:
        roots.append((plan.session_socket.parent, RootRole.SOCKET_RUNTIME))
    return HardeningPolicy.for_plan(roots)


def _visible_paths(plan: LocalSandboxPlan) -> tuple[Path, ...]:
    """Mirror fixed system binds and plan-owned roots for PATH containment."""
    roots = [Path("/usr"), Path("/bin"), Path("/sbin"), Path("/lib"), Path("/lib64")]
    if plan.projected_home is not None:
        roots.append(plan.projected_home)
    roots.extend(binding.host_path for binding in plan.remotes)
    return tuple(roots)


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=2.0)


def _audit_hardening_failure(
    audit_sink: Callable[[str, str, str, dict[str, object]], None] | None,
    plan: LocalSandboxPlan,
    error_code: str,
) -> None:
    if audit_sink is not None:
        audit_sink(
            "hardening.failure",
            "process",
            plan.session_id or "local",
            {"error_code": error_code},
        )


def _error(message: str, code: ErrorCode = ErrorCode.DAEMON_PROTOCOL) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="sandbox was not started or was terminated",
        unsafe_reason="sandbox child must not outlive daemon-owned remote authority",
        next_action="repair bubblewrap or remote mount and retry",
    )
