#!/usr/bin/env python3
"""Build, install, and rerun the Ubuntu Packet 23-24 sandbox acceptance."""

from __future__ import annotations

import json
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = Path("/usr/libexec/astral-project/aspr-bwrap-launch")
ENTRY = Path("/usr/libexec/astral-project/aspr-sandbox-entry")
PROFILE = Path("/etc/apparmor.d/usr.libexec.astral-project.aspr-bwrap-launch")


def run(command: list[str], *, sudo: bool = False, user: str | None = None) -> str:
    full = command
    if sudo and os.geteuid() != 0:
        full = ["sudo", *full]
    if user is not None and os.geteuid() == 0:
        full = ["sudo", "-u", user, *full]
    print("$ " + " ".join(full), flush=True)
    result = subprocess.run(full, cwd=ROOT, check=False, text=True, capture_output=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")
    if result.returncode:
        raise SystemExit(f"command failed with exit {result.returncode}: {' '.join(full)}")
    return result.stdout


def _capture_root(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=True)
    return result.stdout


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("run installed acceptance as root: sudo SUDO_USER=testuser python3 ...")
    if shutil.which("sudo") is None or shutil.which("dpkg") is None:
        raise SystemExit("Ubuntu acceptance requires sudo and dpkg")
    acceptance_user = os.environ.get("SUDO_USER", "testuser")
    acceptance_uid = pwd.getpwnam(acceptance_user).pw_uid
    with tempfile.TemporaryDirectory(prefix="aspr-package-") as output:
        package_dir = Path(output)
        run(["./packaging/debian/build-deb.sh", str(package_dir)])
        package = next(package_dir.glob("*.deb"))
        run(["dpkg", "-i", str(package)], sudo=True)
        for path in (LAUNCHER, ENTRY):
            run(["stat", "-c", "%n %U:%G %a %A", str(path)])
            details = os.stat(path)
            if details.st_uid != 0 or details.st_gid != 0 or details.st_mode & 0o777 != 0o555:
                raise SystemExit(f"installed security entrypoint has unsafe ownership/mode: {path}")
            if details.st_mode & 0o6000:
                raise SystemExit(f"installed security entrypoint has setuid/setgid bits: {path}")
        capabilities = run(["getcap", str(LAUNCHER), str(ENTRY)])
        if capabilities.strip():
            raise SystemExit(
                f"installed security entrypoint has file capabilities: {capabilities.strip()}"
            )
        run(["apparmor_parser", "--replace", str(PROFILE)], sudo=True)
        run(["aa-status"], sudo=True)
        audit_before = _capture_root(["journalctl", "-k", "--no-pager", "-o", "cat"])
        serials_before = [
            int(match.group(1)) for match in re.finditer(r"audit\([^:]+:(\d+)\)", audit_before)
        ]
        baseline_serial = max(serials_before, default=0)
        run(
            [
                "unshare",
                "-m",
                "--propagation",
                "private",
                "aa-exec",
                "-p",
                "aspr-bwrap-setup",
                "--",
                "mount",
                "-t",
                "tmpfs",
                "-o",
                "nosuid,nodev",
                "tmpfs",
                "/tmp",
            ]
        )
        run(
            [
                "unshare",
                "-U",
                "-r",
                "aa-exec",
                "-p",
                "aspr-bwrap-setup",
                "--",
                "unshare",
                "-U",
                "-r",
                "true",
            ]
        )
        env = os.environ | {"XDG_RUNTIME_DIR": f"/run/user/{acceptance_uid}"}
        command = [
            "env",
            f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
            "python3",
            str(ROOT / "scripts/sandbox_enforce_acceptance.py"),
        ]
        run(command, user=acceptance_user)
        run(
            [
                "sudo",
                "unshare",
                "-n",
                "aa-exec",
                "-p",
                "aspr-bwrap-setup",
                "--",
                "/usr/bin/python3",
                "-c",
                "import fcntl, socket, struct; "
                "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); "
                "x=struct.pack('16sH', b'lo', 1); "
                "f=struct.unpack('16sH', fcntl.ioctl(s, 0x8913, x))[1]; "
                "fcntl.ioctl(s, 0x8914, struct.pack('16sH', b'lo', f|1))",
            ]
        )
        audit_lines: list[str] = []
        for _ in range(600):
            time.sleep(0.5)
            audit_after = _capture_root(["journalctl", "-k", "--no-pager", "-o", "cat"])
            audit_lines = [
                line
                for line in audit_after.splitlines()
                if (match := re.search(r"audit\([^:]+:(\d+)\)", line))
                and int(match.group(1)) > baseline_serial
            ]
            if any('capname="net_admin"' in line for line in audit_lines):
                break
        apparmor_audit = [
            line
            for line in audit_lines
            if 'profile="aspr-bwrap-setup"' in line and 'apparmor="AUDIT"' in line
        ]
        capabilities = {
            match.group(1)
            for line in apparmor_audit
            if 'operation="capable"' in line and (match := re.search(r'capname="([^"]+)"', line))
        }
        required = {"sys_admin", "net_admin", "setpcap"}
        if capabilities != required:
            raise SystemExit(f"runtime setup capability audit mismatch: {capabilities!r}")
        operations = {
            match.group(1)
            for line in apparmor_audit
            if (match := re.search(r'operation="([^"]+)"', line))
        }
        if "mount" not in operations:
            raise SystemExit(f"runtime setup mount audit missing: {operations!r}")
        selected_audit: list[str] = []
        for capability in sorted(required):
            line = next(
                (entry for entry in reversed(apparmor_audit) if f'capname="{capability}"' in entry),
                None,
            )
            if line is not None:
                selected_audit.append(line)
        mount_line = next(
            (entry for entry in reversed(apparmor_audit) if 'operation="mount"' in entry),
            None,
        )
        if mount_line is not None:
            selected_audit.append(mount_line)
        for line in selected_audit:
            print(line)
        print(
            json.dumps(
                {
                    "audit_serial_baseline": baseline_serial,
                    "audit_records": len(apparmor_audit),
                },
                sort_keys=True,
            )
        )
        print(
            json.dumps(
                {
                    "setup_audit_capabilities": sorted(capabilities),
                    "setup_audit_operations": sorted(operations),
                    "setup_userns_probe": "passed",
                    "setup_mount_probe": "passed",
                },
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
