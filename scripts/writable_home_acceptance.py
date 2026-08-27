#!/usr/bin/env python3
"""Installed writable projected-home FUSE acceptance on a disposable fixture."""

from __future__ import annotations

import multiprocessing
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

from astral_project.homed.fuse import mount_overlay, mount_private
from astral_project.profile import Profile

_PRIVATE_PROFILE = Profile.from_toml(
    """
version = 1
id = "packet-30-private"
name = "packet-30-private"
[[home.rules]]
path = "data"
scope = "subtree"
mode = "private-rw"
list = true
"""
)
_OVERLAY_PROFILE = Profile.from_toml(
    """
version = 1
id = "packet-32-overlay"
name = "packet-32-overlay"
[[home.rules]]
path = "data"
scope = "subtree"
mode = "overlay-rw"
list = true
"""
)


def _wait_mount(path: Path, process: multiprocessing.Process) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.is_mount():
            return
        if not process.is_alive():
            raise RuntimeError(f"FUSE child exited with code {process.exitcode}")
        time.sleep(0.05)
    raise TimeoutError(f"mount did not appear: {path}")


def _stop(process: multiprocessing.Process, path: Path) -> None:
    if path.is_mount():
        subprocess.run(["fusermount3", "-u", "-z", os.fspath(path)], check=False, timeout=5)
    process.join(10)
    if process.is_alive():
        os.kill(process.pid, signal.SIGKILL)
        process.join(5)
    if path.is_mount():
        raise AssertionError(f"mount cleanup failed: {path}")


def _private_target(mountpoint: Path, storage: Path) -> None:
    mount_private(mountpoint, storage, _PRIVATE_PROFILE)


def _overlay_target(mountpoint: Path, lower: Path, upper: Path) -> None:
    mount_overlay(mountpoint, lower, upper, profile=_OVERLAY_PROFILE)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aspr-p30-32-") as temp:
        base = Path(temp)
        private_mount = base / "private-mount"
        private_storage = base / "private-storage"
        private = multiprocessing.Process(
            target=_private_target, args=(private_mount, private_storage)
        )
        private.start()
        try:
            _wait_mount(private_mount, private)
            (private_mount / "data").mkdir()
            (private_mount / "data/file").write_bytes(b"private")
            assert (private_mount / "data/file").read_bytes() == b"private"
            print("private-fuse-write-read=passed")
        finally:
            _stop(private, private_mount)

        private_again = multiprocessing.Process(
            target=_private_target, args=(private_mount, private_storage)
        )
        private_again.start()
        try:
            _wait_mount(private_mount, private_again)
            assert (private_mount / "data/file").read_bytes() == b"private"
            print("private-fuse-persistence=passed")
        finally:
            _stop(private_again, private_mount)

        lower = base / "lower"
        upper = base / "upper"
        (lower / "data").mkdir(parents=True)
        (lower / "data/lower").write_bytes(b"lower")
        overlay_mount = base / "overlay-mount"
        overlay = multiprocessing.Process(
            target=_overlay_target, args=(overlay_mount, lower, upper)
        )
        overlay.start()
        try:
            _wait_mount(overlay_mount, overlay)
            assert (overlay_mount / "data/lower").read_bytes() == b"lower"
            (overlay_mount / "data/lower").write_bytes(b"upper")
            assert (overlay_mount / "data/lower").read_bytes() == b"upper"
            assert (lower / "data/lower").read_bytes() == b"lower"
            (overlay_mount / "data/new").write_bytes(b"new")
            (overlay_mount / "data/lower").unlink()
            assert not (overlay_mount / "data/lower").exists()
            print("overlay-fuse-copyup-whiteout-lower-immutable=passed")
        finally:
            _stop(overlay, overlay_mount)

    print("installed-writable-fuse-acceptance=passed")


if __name__ == "__main__":
    main()
