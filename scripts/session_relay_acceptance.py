#!/usr/bin/env python3
"""Exercise the installed namespace session relay without remote mount authority."""

from __future__ import annotations

import base64
import tempfile
from pathlib import Path

from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode
from astral_project.sandbox.runner import hardening_policy, run_plan
from astral_project.sandbox.session_api import SessionApiServer

SESSION_ID = "installed-relay-acceptance"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="aspr-relay-") as temporary:
        socket_path = Path(temporary) / "session.sock"
        api = SessionApiServer(
            socket_path,
            session_id=SESSION_ID,
            describe=lambda: {"session_id": SESSION_ID},
            mounts=lambda: [],
            expiry=lambda: 2_000_000_000,
            close=lambda: {"closed": True},
            run_ls=lambda _payload: {
                "stdout_b64": base64.b64encode(b"relay-ok\n").decode("ascii"),
                "stderr_b64": "",
                "version": 1,
            },
        )
        api.start()
        try:
            plan = LocalSandboxPlan(
                ("/usr/bin/aspr", "ls", "/", "--json"),
                NetworkMode.NONE,
                session_socket=socket_path,
                session_id=SESSION_ID,
            )
            result = run_plan(plan, hardening=hardening_policy(plan))
        finally:
            api.close()
    if result != 0:
        raise SystemExit(f"installed session relay failed with exit {result}")
    print("session_relay=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
