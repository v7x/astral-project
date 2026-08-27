#!/usr/bin/env python3
"""Installed end-to-end noninteractive learner acceptance."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
from contextlib import suppress
from pathlib import Path

from astral_project.approval.protocol import ApprovalClient, ApprovalProtocolError, ApprovalRequest
from astral_project.homed.mediation import MediationDecision
from astral_project.learner import ProfileLearner
from astral_project.profile_lifecycle import ProfileStore


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aspr-p36-") as temp:
        base = Path(temp)
        home = base / "home"
        home.mkdir()
        expected = b"learner-approved\n"
        (home / "unknown.txt").write_bytes(expected)
        runtime = base / "runtime"
        socket_path = runtime / "approval" / "approval.sock"
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
            ["aspr", "profile", "create", "agents-default"],
            env=environment,
            check=True,
            capture_output=True,
        )
        process = subprocess.Popen(
            [
                "aspr",
                "profile",
                "learn",
                "agents-default",
                "--external",
                "--",
                "/bin/sh",
                "-c",
                "IFS= read -r value < /home/sandbox/unknown.txt; printf '%s\\n' \"$value\"",
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
        stdout, stderr = process.communicate(timeout=20)
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
                "aspr",
                "profile",
                "learn",
                "agents-default",
                "--external",
                "--",
                "/bin/sh",
                "-c",
                "IFS= read -r value < /home/sandbox/unknown.txt; printf '%s\\n' \"$value\"",
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
        subprocess.run(["aspr", "profile", "seal", "agents-default"], env=environment, check=True)
        sealed = subprocess.run(
            [
                "aspr",
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
                "IFS= read -r value < /home/sandbox/unknown.txt; printf '%s\\n' \"$value\"",
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
                "aspr",
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
        print("learner-end-to-end=passed")


if __name__ == "__main__":
    main()
