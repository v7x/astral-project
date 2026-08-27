#!/usr/bin/env python3
"""Installed composite projected-home synthetic-ancestor acceptance."""

from __future__ import annotations

import errno
import multiprocessing
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_INSTALLED_RUNTIME = "/usr/lib/astral-project/python"
sys.path[:] = [
    path for path in sys.path if not path.startswith("/usr/local/") and "site-packages" not in path
]
if _INSTALLED_RUNTIME not in sys.path:
    sys.path.insert(0, _INSTALLED_RUNTIME)

from astral_project.homed.fuse import mount_composite  # noqa: E402
from astral_project.profile import Profile  # noqa: E402

_PROFILE = Profile.from_toml(
    """
version = 1
id = "packet-36b-composite"
name = "packet-36b-composite"

[[home.rules]]
path = ".config/tool/config.toml"
scope = "exact"
mode = "host-ro"

[[home.rules]]
path = "private/deep"
scope = "subtree"
mode = "private-rw"

[[home.rules]]
path = "overlay/deep"
scope = "subtree"
mode = "overlay-rw"
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
        assert process.pid is not None
        os.kill(process.pid, signal.SIGKILL)
        process.join(5)
    if path.is_mount():
        raise AssertionError(f"mount cleanup failed: {path}")


def _target(mountpoint: Path, root: Path, private: Path, overlay: Path) -> None:
    mount_composite(
        mountpoint,
        root,
        _PROFILE,
        storage_root=private,
        overlay_root=overlay,
    )


def _denied_listing(path: Path) -> None:
    try:
        list(path.iterdir())
    except OSError as error:
        if error.errno == errno.EACCES:
            return
        raise AssertionError(
            f"listing failed with unexpected errno {error.errno}: {path}"
        ) from error
    raise AssertionError(f"listing unexpectedly succeeded: {path}")


def _write_read(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        assert os.write(descriptor, value) == len(value)
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, len(value)) == value
    finally:
        os.close(descriptor)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="aspr-p36b-") as temporary:
        base = Path(temporary)
        root = base / "host"
        (root / ".config" / "tool").mkdir(parents=True)
        (root / ".config" / "tool" / "config.toml").write_bytes(b"host-config")
        (root / ".config" / "tool" / "sibling.txt").write_bytes(b"sibling")
        (root / ".config" / "other.txt").write_bytes(b"other")
        private = base / "private"
        overlay = base / "overlay"
        mountpoint = base / "mount"
        context = multiprocessing.get_context("fork")
        process = context.Process(target=_target, args=(mountpoint, root, private, overlay))
        process.start()
        try:
            _wait_mount(mountpoint, process)
            assert (mountpoint / ".config/tool/config.toml").read_bytes() == b"host-config"
            print("mounted-nested-host-read=passed")
            _denied_listing(mountpoint)
            print("mounted-root-listing-denied=passed")
            _denied_listing(mountpoint / ".config")
            _denied_listing(mountpoint / ".config/tool")
            print("mounted-opaque-listing-denied=passed")
            sibling = subprocess.run(
                ["cat", os.fspath(mountpoint / ".config/other.txt")],
                capture_output=True,
                check=False,
            )
            if sibling.returncode == 0 or sibling.stdout:
                raise AssertionError("unapproved sibling content was observable")
            print("mounted-sibling-hidden=passed")

            _write_read(mountpoint / "private/deep/file", b"private")
            _denied_listing(mountpoint / "private")
            if (root / "private").exists():
                raise AssertionError("private synthetic ancestor touched host lower")
            print("mounted-absent-private-parent=passed")

            _write_read(mountpoint / "overlay/deep/file", b"overlay")
            _denied_listing(mountpoint / "overlay")
            if (root / "overlay").exists():
                raise AssertionError("overlay synthetic ancestor touched host lower")
            if (root / ".config/tool/config.toml").read_bytes() != b"host-config":
                raise AssertionError("overlay mutation changed host lower")
            print("mounted-absent-overlay-parent=passed")
            print("mounted-overlay-lower-immutable=passed")
        finally:
            _stop(process, mountpoint)
    print("installed-composite-synthetic-ancestor-acceptance=passed")


if __name__ == "__main__":
    main()
