#!/usr/bin/env python3
"""Installed Packet 23 enforcement acceptance without remote credentials."""

from __future__ import annotations

import json
import os
import struct
import subprocess
import tempfile
from pathlib import Path

LAUNCHER = Path("/usr/libexec/astral-project/aspr-bwrap-launch")
ENTRY = Path("/usr/libexec/astral-project/aspr-sandbox-entry")
ASPR = "/usr/bin/aspr"


def run(command: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, env=env, capture_output=True, text=True, check=False, timeout=90)


def require(result: subprocess.CompletedProcess[str], name: str) -> None:
    if result.returncode != 0:
        raise RuntimeError(f"{name} failed: {result.stdout}{result.stderr}")


def main() -> int:
    if os.geteuid() == 0:
        raise RuntimeError("enforcement acceptance must run as the unprivileged test user")
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    if not runtime.startswith("/run/user/"):
        raise RuntimeError("XDG_RUNTIME_DIR must be the normal /run/user/<uid> runtime")
    with tempfile.TemporaryDirectory(prefix="aspr-enforce-state-") as state:
        env = os.environ.copy()
        env["XDG_STATE_HOME"] = state
        inherit = run(
            [
                ASPR,
                "sandbox",
                "--network",
                "inherit",
                "--",
                "/bin/sh",
                "-c",
                "grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status",
            ],
            env,
        )
        require(inherit, "network=inherit")
        none = run(
            [
                ASPR,
                "sandbox",
                "--network",
                "none",
                "--",
                "/bin/sh",
                "-c",
                (
                    "set -e; grep -q aspr-sandbox-payload /proc/self/attr/current; "
                    "! grep -Eq '^Cap(Inh|Prm|Eff|Bnd|Amb):[[:space:]]*"
                    "[0]*[1-9a-f][0-9a-f]*$' /proc/self/status; "
                    "grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status; "
                    "test -z \"$(grep -E '^[[:space:]]*[A-Za-z0-9_.-]+:' /proc/net/dev | "
                    "grep -v 'lo:')\"; "
                    'test "$(cat /proc/net/route | tail -n +2 | wc -l)" -eq 0; '
                    "test ! -e /etc/resolv.conf; test ! -e /etc/hosts; "
                    "test ! -S /run/astral-project/daemon.sock; "
                    "test ! -S /run/astral-project/transport.sock; "
                    'test "$(tail -n +2 /proc/net/tcp | wc -l)" -eq 0; '
                    'test "$(tail -n +2 /proc/net/tcp6 | wc -l)" -eq 0; '
                    'test "$(tail -n +2 /proc/net/udp | wc -l)" -eq 0; '
                    'test "$(tail -n +2 /proc/net/udp6 | wc -l)" -eq 0; '
                    'test "$(tail -n +2 /proc/net/unix | wc -l)" -eq 0; '
                    "test ! -e /root/.ssh; test ! -e /home/testuser/.ssh; "
                    "mkdir /tmp/blocked; ! mount -t tmpfs tmpfs /tmp/blocked"
                ),
            ],
            env,
        )
        require(none, "network=none")
    invalid = subprocess.run([str(LAUNCHER)], input=b"BADPLAN!", capture_output=True, check=False)
    if invalid.returncode != 70:
        raise RuntimeError("invalid native plan was accepted")
    valid_plan = (
        b"ASPRSB01"
        + struct.pack("!BI", 0, 1)
        + struct.pack("!I", 9)
        + b"/bin/true"
        + struct.pack("!I", 0)
        + b"\x00\x00"
    )
    for raw_args in (
        ("--unshare-net",),
        ("/tmp/alternate-helper",),
        ("/usr/bin/alternate-entrypoint",),
    ):
        raw = subprocess.run(
            [str(LAUNCHER), *raw_args], input=valid_plan, capture_output=True, check=False
        )
        if raw.returncode != 70:
            raise RuntimeError(f"raw launcher arguments were accepted: {raw_args!r}")
    direct = subprocess.run([str(ENTRY), "/bin/true"], capture_output=True, check=False)
    if direct.returncode != 70:
        raise RuntimeError("direct native entrypoint was accepted")
    details = {
        "launcher": str(LAUNCHER),
        "entrypoint": str(ENTRY),
        "network_inherit": "passed",
        "network_none": "passed",
        "all_capability_sets_zero": "passed",
        "all_non_loopback_interfaces_absent": "passed",
        "all_network_socket_tables_empty": "passed",
        "dns_absent": "passed",
        "credentials_and_sockets_absent": "passed",
        "native_negative_controls": "passed",
        "runtime": runtime,
    }
    print(json.dumps(details, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
