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
PROBE = Path("/usr/libexec/astral-project/aspr-apparmor-net-admin-probe")
ASPR = "/usr/bin/aspr"


def _full_command(command: list[str], *, sudo: bool, user: str | None) -> list[str]:
    full = command
    if sudo and os.geteuid() != 0:
        full = ["sudo", *full]
    if user is not None and os.geteuid() == 0:
        full = ["sudo", "-u", user, *full]
    return full


def run_result(
    command: list[str], *, sudo: bool = False, user: str | None = None
) -> subprocess.CompletedProcess[str]:
    full = _full_command(command, sudo=sudo, user=user)
    print("$ " + " ".join(full), flush=True)
    result = subprocess.run(
        full, cwd=ROOT, check=False, text=True, capture_output=True, timeout=90
    )
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="")
    return result


def run(command: list[str], *, sudo: bool = False, user: str | None = None) -> str:
    result = run_result(command, sudo=sudo, user=user)
    if result.returncode:
        full = _full_command(command, sudo=sudo, user=user)
        raise SystemExit(f"command failed with exit {result.returncode}: {' '.join(full)}")
    return result.stdout


def _capture_root(command: list[str]) -> str:
    result = subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=True)
    return result.stdout


def _audit_baseline() -> int:
    text = _capture_root(["journalctl", "-k", "--no-pager", "-o", "cat"])
    serials = [int(match.group(1)) for match in re.finditer(r"audit\([^:]+:(\d+)\)", text)]
    return max(serials, default=0)


def _reload_profile(profile: Path) -> None:
    run(["apparmor_parser", "--remove", str(profile)], sudo=True)
    run(["apparmor_parser", "--replace", str(profile)], sudo=True)


def _audit_lines_after(baseline: int) -> list[str]:
    text = _capture_root(["journalctl", "-k", "--no-pager", "-o", "cat"])
    return [
        line
        for line in text.splitlines()
        if (match := re.search(r"audit\([^:]+:(\d+)\)", line))
        and int(match.group(1)) > baseline
    ]


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("run installed acceptance as root: sudo SUDO_USER=testuser python3 ...")
    if shutil.which("sudo") is None or shutil.which("dpkg") is None:
        raise SystemExit("Ubuntu acceptance requires sudo and dpkg")
    acceptance_user = os.environ.get("SUDO_USER", "testuser")
    acceptance_uid = pwd.getpwnam(acceptance_user).pw_uid
    package_override = os.environ.get("ASPR_PACKAGE")
    with tempfile.TemporaryDirectory(prefix="aspr-package-") as output:
        if package_override is None:
            package_dir = Path(output)
            run(["./packaging/debian/build-deb.sh", str(package_dir)])
            package = next(package_dir.glob("*.deb"))
        else:
            package = Path(package_override)
            if not package.is_absolute() or not package.is_file():
                raise SystemExit("ASPR_PACKAGE must name an existing absolute package path")
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
        status = run(["aa-status"], sudo=True)
        if "aspr-bwrap-setup" not in status or "aspr-sandbox-payload" not in status:
            raise SystemExit("installed AppArmor profiles are not loaded")
        baseline_serial = _audit_baseline()
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
        normal_audit: list[str] = []
        for _ in range(20):
            time.sleep(0.5)
            normal_audit = [
                line
                for line in _audit_lines_after(baseline_serial)
                if 'profile="aspr-bwrap-setup"' in line and 'apparmor="AUDIT"' in line
            ]
            if "sys_admin" in {
                match.group(1)
                for line in normal_audit
                if 'operation="capable"' in line
                and (match := re.search(r'capname="([^"]+)"', line))
            } and any('operation="mount"' in line for line in normal_audit):
                break
        normal_capabilities = {
            match.group(1)
            for line in normal_audit
            if 'operation="capable"' in line and (match := re.search(r'capname="([^"]+)"', line))
        }
        normal_operations = {
            match.group(1)
            for line in normal_audit
            if (match := re.search(r'operation="([^"]+)"', line))
        }
        if "mount" not in normal_operations:
            raise SystemExit(f"normal setup mount audit missing: {normal_operations!r}")

        source = PROFILE.read_text(encoding="utf-8")
        needle = "  audit capability net_admin,\n"
        if source.count(needle) != 1:
            raise SystemExit("installed profile net_admin rule count is not exactly one")
        no_net_admin = Path("/tmp/aspr-bwrap-no-net-admin")
        no_net_admin.write_text(source.replace(needle, ""), encoding="utf-8")
        cpu = min(os.sched_getaffinity(0))
        probe_command = [
            "taskset",
            "-c",
            str(cpu),
            "unshare",
            "-n",
            "aa-exec",
            "-p",
            "aspr-bwrap-setup",
            "--",
            str(PROBE),
        ]
        run(
            [
                "cc",
                "-std=c11",
                "-O2",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "scripts/apparmor_net_admin_probe.c"),
                "-o",
                str(PROBE),
            ]
        )
        try:
            time.sleep(10)
            _reload_profile(PROFILE)
            time.sleep(5)
            positive_baseline = _audit_baseline()
            positive = run_result(probe_command, sudo=True)
            positive_audit: list[str] = []
            positive_line: str | None = None
            for _ in range(20):
                time.sleep(0.5)
                positive_audit = _audit_lines_after(positive_baseline)
                positive_line = next(
                    (
                        line
                        for line in positive_audit
                        if 'apparmor="AUDIT"' in line
                        and 'operation="capable"' in line
                        and 'profile="aspr-bwrap-setup"' in line
                        and 'capname="net_admin"' in line
                    ),
                    None,
                )
                if positive_line is not None:
                    break
            if positive.returncode != 0 or positive_line is None:
                raise SystemExit(
                    "production net_admin probe did not produce allowed audit evidence"
                )
            print("setup_net_admin_probe_audit=passed")
            print(positive_line)

            _reload_profile(PROFILE)
            time.sleep(5)
            runtime_baseline = _audit_baseline()
            runtime_probe = run_result(
                [
                    "env",
                    f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
                    ASPR,
                    "sandbox",
                    "--network",
                    "none",
                    "--",
                    "/bin/true",
                ],
                user=acceptance_user,
            )
            runtime_audit: list[str] = []
            runtime_capabilities: set[str] = set()
            for _ in range(20):
                time.sleep(0.5)
                runtime_audit = [
                    line
                    for line in _audit_lines_after(runtime_baseline)
                    if 'profile="aspr-bwrap-setup"' in line
                    and 'apparmor="AUDIT"' in line
                ]
                runtime_capabilities = {
                    match.group(1)
                    for line in runtime_audit
                    if 'operation="capable"' in line
                    and (match := re.search(r'capname="([^"]+)"', line))
                }
                if {"sys_admin", "setpcap"}.issubset(runtime_capabilities):
                    break
            if runtime_probe.returncode != 0 or not {"sys_admin", "setpcap"}.issubset(
                runtime_capabilities
            ):
                raise SystemExit(
                    f"installed runtime capability audit mismatch: {runtime_capabilities!r}"
                )
            print("setup_runtime_capabilities=passed")
            for line in runtime_audit:
                if 'operation="capable"' in line:
                    print(line)

            time.sleep(15)
            run(["apparmor_parser", "--remove", str(PROFILE)], sudo=True)
            run(["apparmor_parser", "--replace", str(no_net_admin)], sudo=True)
            time.sleep(5)
            negative_baseline = _audit_baseline()
            negative = run_result(probe_command, sudo=True)
            negative_audit: list[str] = []
            negative_line: str | None = None
            for _ in range(20):
                time.sleep(0.5)
                negative_audit = _audit_lines_after(negative_baseline)
                negative_line = next(
                    (
                        line
                        for line in negative_audit
                        if 'apparmor="DENIED"' in line
                        and 'operation="capable"' in line
                        and 'profile="aspr-bwrap-setup"' in line
                        and 'capname="net_admin"' in line
                    ),
                    None,
                )
                if negative_line is not None:
                    break
            if negative.returncode == 0 or negative_line is None:
                raise SystemExit("tightened net_admin probe was not denied with audit evidence")
            print("setup_net_admin_negative_probe=passed")
            print(negative_line)
            tightened_runtime = run_result(
                [
                    "env",
                    f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
                    ASPR,
                    "sandbox",
                    "--network",
                    "none",
                    "--",
                    "/bin/true",
                ],
                user=acceptance_user,
            )
            if tightened_runtime.returncode == 0:
                raise SystemExit("tightened profile still permits installed network=none")
            print("setup_net_admin_runtime_dependency=passed")
        finally:
            run(["apparmor_parser", "--remove", str(no_net_admin)], sudo=True)
            run(["apparmor_parser", "--replace", str(PROFILE)], sudo=True)

        restored_runtime = run_result(
            [
                "env",
                f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
                ASPR,
                "sandbox",
                "--network",
                "none",
                "--",
                "/bin/true",
            ],
            user=acceptance_user,
        )
        if restored_runtime.returncode != 0:
            raise SystemExit("restored production profile rejected installed network=none")
        restored_status = run(["aa-status"], sudo=True)
        enforce_body = re.search(
            r"profiles are in enforce mode\.\s*(.*?)(?:\n\d+ profiles are|\Z)",
            restored_status,
            re.DOTALL,
        )
        if enforce_body is None or "aspr-bwrap-setup" not in enforce_body.group(1):
            raise SystemExit("restored aspr-bwrap-setup profile is not enforcing")
        print("setup_profile_restored=passed")
        for line in normal_audit:
            if 'operation="capable"' in line or 'operation="mount"' in line:
                print(line)
        print(
            json.dumps(
                {
                    "audit_serial_baseline": baseline_serial,
                    "normal_audit_records": len(normal_audit),
                    "normal_setup_capabilities": sorted(normal_capabilities),
                    "normal_setup_operations": sorted(normal_operations),
                    "setup_mount_probe": "passed",
                    "setup_userns_probe": "passed",
                    "setup_net_admin_probe": "passed",
                    "setup_net_admin_negative_probe": "passed",
                    "setup_runtime_capabilities": sorted(runtime_capabilities),
                    "setup_net_admin_runtime_dependency": "passed",
                    "setup_profile_restored": "passed",
                },
                sort_keys=True,
            )
        )
        PROBE.unlink(missing_ok=True)
        no_net_admin.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
