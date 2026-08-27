#!/usr/bin/env python3
"""Installed Packet 25-27 acceptance using only a disposable host-home fixture."""

from __future__ import annotations

import errno
import os
import signal
import subprocess
import tempfile
import time
from multiprocessing import Process
from pathlib import Path

from astral_project.homed.fuse import (
    cleanup_stale_mount,
    mount_empty,
    mount_host_readonly,
)
from astral_project.profile import Profile
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode

PROFILE = """
version = 1
id = "packet-27-fixture"
name = "packet-27-fixture"

[[home.rules]]
path = ".codex/config.toml"
scope = "exact"
mode = "host-ro"
sensitivity = "configuration"

[[home.rules]]
path = ".codex"
scope = "subtree"
mode = "host-ro"
sensitivity = "configuration"
list = true
"""


def wait_mount(path: Path, process: Process) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if path.is_mount():
            return
        if not process.is_alive():
            raise RuntimeError(f"FUSE child exited with code {process.exitcode}")
        time.sleep(0.05)
    raise TimeoutError(f"mount did not appear: {path}")


def stop(process: Process, mountpoint: Path) -> None:
    if mountpoint.is_mount():
        subprocess.run(
            ["fusermount3", "-u", "-z", os.fspath(mountpoint)],
            check=False,
            timeout=5,
        )
    if process.is_alive():
        os.kill(process.pid, signal.SIGTERM)
        process.join(5)
    if mountpoint.is_mount():
        subprocess.run(
            ["fusermount3", "-u", "-z", os.fspath(mountpoint)],
            check=False,
            timeout=5,
        )
    process.join(5)
    if process.is_alive():
        process.kill()
        process.join(5)
    if mountpoint.is_mount():
        raise AssertionError(f"mount cleanup failed: {mountpoint}")


def run_empty(mountpoint: Path) -> None:
    mount_empty(mountpoint)


def run_host(mountpoint: Path, root: Path) -> None:
    mount_host_readonly(mountpoint, root, Profile.from_toml(PROFILE))


def run_sandbox_home(mountpoint: Path) -> None:
    stat_result = os.stat(mountpoint)
    statfs_result = os.statvfs(mountpoint)
    fs_magic = subprocess.check_output(
        ["stat", "-f", "-c", "%t", os.fspath(mountpoint)], text=True
    ).strip()
    print(
        f"projected-st_uid={stat_result.st_uid} process-uid={os.getuid()} "
        f"f_bsize={statfs_result.f_bsize} fs_magic={fs_magic}"
    )
    plan = LocalSandboxPlan(
        ("/bin/sh", "-c", 'test "$HOME" = /home/sandbox && test -d /home/sandbox'),
        NetworkMode.INHERIT,
        projected_home=mountpoint,
    )
    result = subprocess.run(plan.argv(), capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            f"projected HOME sandbox failed: {result.returncode}: "
            f"{result.stderr.decode('utf-8', 'replace')}"
        )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aspr-p27-") as temporary:
        base = Path(temporary)
        root = base / "home"
        mountpoint = base / "projected"
        (root / ".codex").mkdir(parents=True)
        config = root / ".codex/config.toml"
        config.write_text("one", encoding="utf-8")
        (root / ".codex/sibling.txt").write_text("sibling", encoding="utf-8")
        (root / "secret.txt").write_text("secret", encoding="utf-8")
        os.symlink(root / "secret.txt", root / ".codex/link")

        empty = Process(target=run_empty, args=(mountpoint,))
        empty.start()
        try:
            wait_mount(mountpoint, empty)
            run_sandbox_home(mountpoint)
            print("sandbox-home=passed")
            if list(mountpoint.iterdir()):
                raise AssertionError("empty projected home exposed an entry")
        finally:
            stop(empty, mountpoint)

        crashed = Process(target=run_empty, args=(mountpoint,))
        crashed.start()
        wait_mount(mountpoint, crashed)
        os.kill(crashed.pid, signal.SIGKILL)
        crashed.join(5)
        if not cleanup_stale_mount(mountpoint) or mountpoint.is_mount():
            raise AssertionError("crashed or stale projected mount was not cleaned")
        print("crash-stale-cleanup=passed")

        host = Process(target=run_host, args=(mountpoint, root))
        host.start()
        try:
            wait_mount(mountpoint, host)
            if (mountpoint / ".codex/config.toml").read_text(encoding="utf-8") != "one":
                raise AssertionError("exact host-ro read failed")
            try:
                tuple(mountpoint.iterdir())
            except OSError:
                pass
            else:
                raise AssertionError("unapproved host root listing succeeded")
            if sorted(path.name for path in (mountpoint / ".codex").iterdir()) != [
                "config.toml",
                "sibling.txt",
            ]:
                raise AssertionError("subtree listing failed")
            try:
                sibling_visible = (mountpoint / "secret.txt").exists()
            except OSError:
                sibling_visible = False
            if sibling_visible:
                raise AssertionError("sibling host path leaked")
            try:
                (mountpoint / ".codex/config.toml").write_text("no", encoding="utf-8")
            except OSError as error:
                if error.errno not in {errno.EROFS, errno.EACCES, errno.EPERM}:
                    raise
            else:
                raise AssertionError("host-backed write succeeded")
            for mutate in (
                lambda: os.chmod(mountpoint / ".codex/config.toml", 0o600),
                lambda: os.truncate(mountpoint / ".codex/config.toml", 0),
            ):
                try:
                    mutate()
                except OSError as error:
                    if error.errno not in {errno.EROFS, errno.EACCES, errno.EPERM}:
                        raise
                else:
                    raise AssertionError("host-backed metadata mutation succeeded")
            try:
                (mountpoint / ".codex/link").read_text(encoding="utf-8")
            except OSError:
                pass
            else:
                raise AssertionError("host symlink escaped")
            config.write_text("two", encoding="utf-8")
            if (mountpoint / ".codex/config.toml").read_text(encoding="utf-8") != "two":
                raise AssertionError("live host change was hidden")
        finally:
            stop(host, mountpoint)

    print("packet-25-empty=passed")
    print("packet-27-host-fixture=passed")
    print("host-write-and-symlink-negatives=passed")
    print("live-change=passed")


if __name__ == "__main__":
    main()
