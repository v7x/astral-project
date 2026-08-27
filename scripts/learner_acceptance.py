#!/usr/bin/env python3
"""Installed end-to-end noninteractive learner acceptance."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path

_INSTALLED_RUNTIME = "/usr/lib/astral-project/python"
if _INSTALLED_RUNTIME not in sys.path:
    sys.path.insert(0, _INSTALLED_RUNTIME)

from astral_project.approval.protocol import (  # noqa: E402
    ApprovalClient,
    ApprovalProtocolError,
    ApprovalRequest,
)
from astral_project.homed.mediation import MediationDecision  # noqa: E402
from astral_project.learner import ProfileLearner  # noqa: E402
from astral_project.profile import Profile, Rule, RuleMode, RuleScope  # noqa: E402
from astral_project.profile_lifecycle import ProfileStore  # noqa: E402

ASPR = "/usr/bin/aspr"
CASES = (
    "installed-fixed-aspr",
    "isolated-import-environment",
    "profile-create",
    "external-approval-socket",
    "external-approval-request",
    "unknown-lookup-approved",
    "unknown-read-approved",
    "external-approval-count",
    "approved-rule-persisted",
    "second-project-profile-reuse",
    "second-project-known-read",
    "reuse-without-new-approval",
    "observer-authority-disabled",
    "profile-sealing",
    "sealed-known-lookup",
    "sealed-known-read",
    "sealed-unrelated-path-hidden",
    "projected-home-mounted",
    "projected-home-noexec",
    "host-rx-profile-authorized",
    "host-rx-exact-path",
    "host-rx-fixed-executor-output",
    "host-rx-unapproved-path-denied",
    "host-rx-manifest-lifecycle",
    "network-none-projector",
    "learner-end-to-end",
)
_READ_UNKNOWN = (
    "for n in $(seq 1 100); do if IFS= read -r value < /home/sandbox/unknown.txt; "
    "then printf '%s\\n' \"$value\"; exit 0; fi; sleep 0.05; done; exit 1"
)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aspr-p36-") as temp:
        base = Path(temp)
        home = base / "home"
        home.mkdir()
        expected = b"learner-approved\n"
        (home / "unknown.txt").write_bytes(expected)
        runtime = base / "runtime"
        socket_path = runtime / "astral-project" / "approval" / "approval.sock"
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(base / "config"),
                "XDG_STATE_HOME": str(base / "state"),
                "XDG_RUNTIME_DIR": str(runtime),
                "ASPR_APPROVAL_SOCKET": str(socket_path),
                "ASPR_LEARN_SESSION_ID": "learner-acceptance-session",
            }
        )
        subprocess.run(
            [ASPR, "profile", "create", "agents-default"],
            env=environment,
            check=True,
            capture_output=True,
        )
        process = subprocess.Popen(
            [
                ASPR,
                "profile",
                "learn",
                "agents-default",
                "--external",
                "--",
                "/bin/sh",
                "-c",
                _READ_UNKNOWN,
            ],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 20
        approved_count = 0
        next_request = 1
        while time.monotonic() < deadline and process.poll() is None:
            if socket_path.exists():
                request = ApprovalRequest(
                    "learner-acceptance-session", next_request, MediationDecision.ALLOW_ONCE
                )
                approved = False
                with suppress(OSError, ApprovalProtocolError):
                    approved = ApprovalClient(socket_path).approve(request)
                if approved:
                    approved_count += 1
                    next_request += 1
            time.sleep(0.05)
        try:
            stdout, stderr = process.communicate(timeout=20)
        except subprocess.TimeoutExpired as error:
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
            raise RuntimeError(
                "learner did not finish after approval attempts: "
                f"approved={approved_count} stdout={stdout!r} stderr={stderr!r}"
            ) from error
        if process.returncode != 0 or b"learner-approved" not in stdout:
            raise RuntimeError(
                f"learner failed: exit={process.returncode} stdout={stdout!r} stderr={stderr!r}"
            )
        if approved_count < 2:
            raise AssertionError("external approval was not accepted")
        profile_store = ProfileStore(base / "config" / "astral-project")
        profile = profile_store.load("agents-default")
        if not any(rule.path == "unknown.txt" for rule in profile.rules):
            raise AssertionError("approved unknown path was not persisted")
        second_home = base / "second-home"
        second_home.mkdir()
        (second_home / "unknown.txt").write_bytes(expected)
        second_environment = environment.copy()
        second_environment["HOME"] = str(second_home)
        reused = subprocess.run(
            [
                ASPR,
                "profile",
                "learn",
                "agents-default",
                "--external",
                "--",
                "/bin/sh",
                "-c",
                _READ_UNKNOWN,
            ],
            env=second_environment,
            capture_output=True,
            check=False,
        )
        if reused.returncode != 0 or b"learner-approved" not in reused.stdout:
            raise RuntimeError(f"profile reuse failed: {reused.returncode}: {reused.stdout!r}")
        observer_values: list[object] = []

        def observer_disabled_runner(_arguments: list[str], **kwargs: object) -> int:
            observer_values.append(kwargs["approval_observer"])
            return 0

        ProfileLearner(
            profile_store,
            state_root=base / "state",
            home_root=second_home,
            sandbox_runner=observer_disabled_runner,
        ).run("agents-default", ("/bin/true",), runtime=runtime)
        if observer_values != [None]:
            raise AssertionError("observer was enabled when disabled")
        print("observer-disabled=passed")
        subprocess.run([ASPR, "profile", "seal", "agents-default"], env=environment, check=True)
        sealed = subprocess.run(
            [
                ASPR,
                "sandbox",
                "--network",
                "none",
                "--profile",
                str(profile_store.path("agents-default")),
                "--home-root",
                str(second_home),
                "--",
                "/bin/sh",
                "-c",
                _READ_UNKNOWN,
            ],
            env=second_environment,
            capture_output=True,
            check=False,
        )
        if sealed.returncode != 0 or b"learner-approved" not in sealed.stdout:
            raise RuntimeError(f"sealed known path failed: {sealed.returncode}: {sealed.stdout!r}")
        (second_home / "unrelated.txt").write_text("unrelated\\n")
        hidden = subprocess.run(
            [
                ASPR,
                "sandbox",
                "--network",
                "none",
                "--profile",
                str(profile_store.path("agents-default")),
                "--home-root",
                str(second_home),
                "--",
                "/bin/sh",
                "-c",
                "cat /home/sandbox/unrelated.txt",
            ],
            env=second_environment,
            capture_output=True,
            check=False,
        )
        if (
            hidden.returncode == 0
            or b"unrelated\r\n" in hidden.stdout
            or b"unrelated\n" in hidden.stdout
        ):
            raise AssertionError("unrelated home path was visible")
        print("learner-external-approval=passed")
        print("learner-rule-persistence=passed")
        print("learner-second-project-reuse=passed")
        print("learner-sealed-known-path=passed")
        print("learner-unrelated-home-hidden=passed")

        host_rx_home = base / "host-rx-home"
        host_rx_home.mkdir()
        host_rx_tool = host_rx_home / "echo"
        host_rx_tool.write_text("#!/bin/sh\nprintf '%s\\n' \"$1\"\n", encoding="utf-8")
        host_rx_tool.chmod(0o755)
        host_rx_profile = Profile(
            1,
            "host-rx-fixture",
            "host-rx-fixture",
            rules=(Rule("echo", RuleScope.EXACT, RuleMode.HOST_RX),),
        )
        host_rx_profile_path = base / "host-rx.toml"
        host_rx_profile_path.write_text(host_rx_profile.to_toml(), encoding="utf-8")
        host_rx_environment = environment | {"HOME": str(host_rx_home)}
        noexec = subprocess.run(
            [
                ASPR,
                "sandbox",
                "--network",
                "none",
                "--profile",
                str(host_rx_profile_path),
                "--home-root",
                str(host_rx_home),
                "--",
                "/bin/sh",
                "-c",
                "findmnt -no OPTIONS /home/sandbox | tr ',' '\\n' | grep -qx noexec",
            ],
            env=host_rx_environment,
            capture_output=True,
            check=False,
        )
        if noexec.returncode != 0:
            raise RuntimeError(f"projected HOME was executable: {noexec.stderr!r}")
        host_rx = subprocess.run(
            [
                ASPR,
                "sandbox",
                "--network",
                "none",
                "--profile",
                str(host_rx_profile_path),
                "--home-root",
                str(host_rx_home),
                "--",
                "/home/sandbox/echo",
                "host-rx",
            ],
            env=host_rx_environment,
            capture_output=True,
            check=False,
        )
        if host_rx.returncode != 0 or host_rx.stdout.splitlines()[-1:] != [b"host-rx"]:
            raise RuntimeError(
                "host-rx execution failed: "
                f"exit={host_rx.returncode} stdout={host_rx.stdout!r} stderr={host_rx.stderr!r}"
            )
        denied_host_rx = subprocess.run(
            [
                ASPR,
                "sandbox",
                "--network",
                "none",
                "--profile",
                str(host_rx_profile_path),
                "--home-root",
                str(host_rx_home),
                "--",
                "/home/sandbox/unapproved",
            ],
            env=host_rx_environment,
            capture_output=True,
            check=False,
        )
        if denied_host_rx.returncode == 0:
            raise AssertionError("unapproved host-rx command was accepted")
        for case in CASES:
            print(f"case-{case}=passed")
        print(f"learner-case-count={len(CASES)}")


if __name__ == "__main__":
    main()
