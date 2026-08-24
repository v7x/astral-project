#!/usr/bin/env python3
"""Run and record the packaged daemon-backed listing matrix on certified VMs."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shlex
import subprocess
import time
from pathlib import Path

HOST_ID = "33a29bae-80a6-485e-a5a0-8af304e21d4a"
FINGERPRINT = "SHA256:vm-gate"
IDENTITY = "/home/testuser/.ssh/aspr-transport"
ISSUER_KEY = "/home/testuser/.local/state/astral-project-test/issuer.key"
RCLONE_SHA256 = {
    "1.73.3": "41bd63149d3bd281f9d8fb02fd8c0406234634a59cd0f591b86ad3f1e2f6abb7",
    "1.74.4": "9f56ca5edfac24a3ed37226c2ba1de69f1ec9e05fa2526cddee5cd97e202be6b",
}
ROWS = (
    ("Ubuntu 26.04 amd64", "aspr-test-admin", "/tmp/astral-real2"),
    ("Ubuntu 24.04 amd64", "aspr-test-admin-24", "/tmp/astral-real2"),
)
CHECKS = {
    "table",
    "json",
    "raw",
    "recursive",
    "timeout",
    "after_timeout",
    "alternate_grant",
    "traversal",
    "ungranted",
}


def _remote(host: str, command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", host, command],
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )


def _as_testuser(command: str) -> str:
    return f"sudo -u testuser sh -c {shlex.quote(command)}"


def _acceptance_command(source_dir: str, rclone: str) -> str:
    arguments = " ".join(
        shlex.quote(value) for value in (rclone, IDENTITY, ISSUER_KEY, HOST_ID, FINGERPRINT)
    )
    return (
        f"cd {shlex.quote(source_dir)} && "
        f"timeout 240 /usr/bin/python3 -I -S scripts/daemon_ls_acceptance.py {arguments}"
    )


def _preflight_commands() -> tuple[str, ...]:
    return (
        "dpkg-query -W -f='${Package} ${Version}\\n' astral-project",
        "sudo /usr/libexec/astral-project/packet15f-gate",
        "/usr/bin/rclone --version",
        "sha256sum /usr/bin/rclone",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records: list[dict[str, object]] = []
    for target, host, source_dir in ROWS:
        preflight_result: dict[str, dict[str, dict[str, object]]] = {}
        for version in ("1.73.3", "1.74.4"):
            rclone = f"/tmp/rclone-pins/rclone-{version}"
            install = _remote(
                host,
                f"sudo install -o root -g root -m 0755 {shlex.quote(rclone)} /usr/bin/rclone",
            )
            if install.returncode != 0:
                raise RuntimeError(f"{target} rclone {version}: pinned binary install failed")
            names = ("package", "packet15f_gate", "version", "sha256")
            preflight_records: dict[str, dict[str, object]] = {}
            for name, command in zip(names, _preflight_commands(), strict=True):
                result = _remote(host, command)
                preflight_records[name] = {
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            preflight_result[version] = preflight_records
            if (
                preflight_records["package"]["returncode"] != 0
                or preflight_records["packet15f_gate"]["returncode"] != 0
                or preflight_records["version"]["returncode"] != 0
                or preflight_records["sha256"]["returncode"] != 0
                or "astral-project 0.1.0" not in str(preflight_records["package"]["stdout"])
                or RCLONE_SHA256[version] not in str(preflight_records["sha256"]["stdout"])
            ):
                raise RuntimeError(f"{target} rclone {version}: package preflight failed")
            rclone = f"/tmp/rclone-pins/rclone-{version}"
            result = _remote(host, _as_testuser(_acceptance_command(source_dir, rclone)))
            try:
                parsed = json.loads(result.stdout)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"{target} rclone {version}: invalid acceptance JSON; "
                    f"returncode={result.returncode} stdout={result.stdout!r} "
                    f"stderr={result.stderr!r}"
                ) from error
            if (
                result.returncode != 0
                or set(parsed.get("checks", {})) != CHECKS
                or parsed.get("grant_signature_verified") is not True
                or parsed.get("state_active_verified") is not True
            ):
                raise RuntimeError(f"{target} rclone {version}: acceptance command failed")
            for check in parsed["checks"].values():
                if not isinstance(check, dict):
                    raise RuntimeError(f"{target} rclone {version}: malformed check record")
                encoded = check.get("stdout_b64")
                digest = check.get("stdout_sha256")
                if not isinstance(encoded, str) or not isinstance(digest, str):
                    raise RuntimeError(f"{target} rclone {version}: missing raw output record")
                raw = base64.b64decode(encoded, validate=True)
                if hashlib.sha256(raw).hexdigest() != digest:
                    raise RuntimeError(f"{target} rclone {version}: output digest mismatch")
            records.append(
                {
                    "target": target,
                    "ssh_host": host,
                    "source_dir": source_dir,
                    "package_preflight": preflight_result[version],
                    "rclone": version,
                    "rclone_sha256": RCLONE_SHA256[version],
                    "command": _as_testuser(_acceptance_command(source_dir, rclone)),
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "result": parsed,
                }
            )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {"generated_at": int(time.time()), "schema_version": 1, "rows": records},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
