#!/usr/bin/env python3
"""Run every Packet 39 installed adversarial probe against the installed package."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

_PROBES = (
    ("landlock.read-only", ("landlock_acceptance.py", "--role", "read-only")),
    ("landlock.regular-writable", ("landlock_acceptance.py", "--role", "regular-writable")),
    ("landlock.socket-runtime", ("landlock_acceptance.py", "--role", "socket-runtime")),
    ("landlock.device-runtime", ("landlock_acceptance.py", "--role", "device-runtime")),
    ("audit.protocol-retention-rotation", ("audit_retention_acceptance.py",)),
    ("remote.nested-mount-pinning", ("nested_mount_installed_acceptance.py",)),
    ("remote.revoked-mount-operation", ("revoked_mount_installed_acceptance.py",)),
    ("remote.audit-export", ("remote_audit_installed_acceptance.py",)),
    ("remote.hardening-failure", ("remote_hardening_failure_installed_acceptance.py",)),
    ("local.sandbox-boundary", ("sandbox_adversarial_installed_acceptance.py",)),
)


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("run Packet 39 installed acceptance as root")
    directory = Path(__file__).parent
    environment = os.environ.copy()
    environment.setdefault("SUDO_USER", "aspr-admin")
    environment.setdefault("PYTHONPATH", "/usr/lib/astral-project/python")
    for name, arguments in _PROBES:
        command = [sys.executable, str(directory / arguments[0]), *arguments[1:]]
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            env=environment,
            timeout=240,
        )
        print(f"=== {name} ===")
        print(completed.stdout, end="")
        print(completed.stderr, end="")
        if completed.returncode != 0:
            return completed.returncode
    print("PASS installed Packet 39-40 full adversarial acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
