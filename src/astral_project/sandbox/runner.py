"""Execute fixed local sandbox plans and enforce remote-loss policy."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Callable

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.sandbox.plan import LocalSandboxPlan

HealthCheck = Callable[[], bool]


def run_plan(
    plan: LocalSandboxPlan,
    *,
    health_check: HealthCheck | None = None,
    poll_seconds: float = 0.2,
    popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
) -> int:
    """Run one plan; terminate child when any daemon-owned remote view is lost."""
    if poll_seconds <= 0:
        raise _error("sandbox health interval must be positive")
    try:
        process = popen(
            plan.launcher_argv(),
            stdin=subprocess.PIPE,
            stdout=None,
            stderr=None,
            env=_sandbox_environment(),
            close_fds=True,
            start_new_session=True,
        )
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
    return int(process.returncode or 0)


def _sandbox_environment() -> dict[str, str]:
    allowed = {"LANG", "LC_ALL", "LC_CTYPE", "TERM"}
    return {key: value for key, value in os.environ.items() if key in allowed}


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


def _error(message: str, code: ErrorCode = ErrorCode.DAEMON_PROTOCOL) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="sandbox was not started or was terminated",
        unsafe_reason="sandbox child must not outlive daemon-owned remote authority",
        next_action="repair bubblewrap or remote mount and retry",
    )
