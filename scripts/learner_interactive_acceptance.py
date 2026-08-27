#!/usr/bin/env python3
"""Installed end-to-end trusted-terminal learner acceptance."""

from __future__ import annotations

import os
import pty
import select
import subprocess
import tempfile
import time
from pathlib import Path

from astral_project.profile_lifecycle import ProfileStore


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aspr-p36-ui-") as temp:
        base = Path(temp)
        home = base / "home"
        home.mkdir()
        (home / "unknown.txt").write_text("interactive-approved\n")
        environment = os.environ.copy()
        environment.update(
            {
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(base / "config"),
                "XDG_STATE_HOME": str(base / "state"),
                "XDG_RUNTIME_DIR": str(base / "runtime"),
            }
        )
        subprocess.run(
            ["aspr", "profile", "create", "agents-default"],
            env=environment,
            check=True,
            capture_output=True,
        )
        pid, master = pty.fork()
        if pid == 0:
            os.execvpe(
                "aspr",
                [
                    "aspr",
                    "profile",
                    "learn",
                    "agents-default",
                    "--",
                    "/bin/sh",
                    "-c",
                    "IFS= read -r value < /home/sandbox/unknown.txt; printf '%s\\n' \"$value\"",
                ],
                environment,
            )
        output = bytearray()
        pending_announcements = 0
        approval_prompts = 0
        deadline = time.monotonic() + 30
        try:
            while time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        output.extend(os.read(master, 65536))
                    except OSError:
                        break
                announcements = output.count(b"approval pending; press Ctrl-")
                if announcements > pending_announcements:
                    os.write(master, b"\x1d")
                    pending_announcements = announcements
                prompts = output.count(b"[y] allow once")
                if prompts > approval_prompts:
                    os.write(master, b"y")
                    approval_prompts = prompts
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    break
            _, status = os.waitpid(pid, 0)
        finally:
            os.close(master)
        exit_code = os.waitstatus_to_exitcode(status)
        if exit_code != 0 or b"interactive-approved" not in output:
            raise RuntimeError(f"interactive learner failed: exit={exit_code} output={output!r}")
        profile = ProfileStore(base / "config" / "astral-project").load("agents-default")
        if not any(rule.path == "unknown.txt" for rule in profile.rules):
            raise AssertionError("interactive approval was not persisted")
        print("learner-trusted-interactive-approval=passed")
        print("learner-trusted-rule-persistence=passed")
        print("learner-interactive-end-to-end=passed")


if __name__ == "__main__":
    main()
