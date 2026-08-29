#!/usr/bin/env python3
"""Real mount-topology attack against descriptor-pinned source resolution."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from astral_project.server.path_resolver import TrustedRoot, resolve_source


def _mount(source: Path, target: Path) -> None:
    result = subprocess.run(
        ["mount", "--bind", str(source), str(target)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nested bind mount failed: {result.stderr.strip() or 'unknown error'}")


def _unmount(target: Path) -> None:
    result = subprocess.run(
        ["umount", "--lazy", str(target)],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"nested bind unmount failed: {result.stderr.strip() or 'unknown error'}"
        )


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("run nested mount acceptance as root")
    with tempfile.TemporaryDirectory(prefix="aspr-nested-mount-") as directory:
        root = Path(directory) / "root"
        source = root / "source"
        nested = source / "nested"
        mounted_tree = Path(directory) / "mounted-tree"
        root.mkdir(mode=0o700)
        source.mkdir(mode=0o700)
        nested.mkdir(mode=0o700)
        mounted_tree.mkdir(mode=0o700)
        marker = mounted_tree / "marker"
        marker.write_text("pinned", encoding="utf-8")
        _mount(mounted_tree, nested)
        try:
            requested = nested / "marker"
            with TrustedRoot.open(str(root)) as trusted:
                with resolve_source(trusted, str(source)) as source_resolved:
                    nested_paths = [item.mount_point for item in source_resolved.nested_mounts]
                with resolve_source(trusted, str(requested)) as resolved:
                    pinned_descriptor = os.open(f"/proc/self/fd/{resolved.descriptor}", os.O_RDONLY)
                    try:
                        pinned_content = os.read(pinned_descriptor, 4096).decode("utf-8")
                    except OSError:
                        os.close(pinned_descriptor)
                        raise
                assert str(nested) in nested_paths
                assert pinned_content == "pinned"
                _unmount(nested)
                nested_unmounted = not os.path.ismount(nested)
                try:
                    os.lseek(pinned_descriptor, 0, os.SEEK_SET)
                    content_after_unmount = os.read(pinned_descriptor, 4096).decode("utf-8")
                finally:
                    os.close(pinned_descriptor)
        finally:
            if os.path.ismount(nested):
                _unmount(nested)
        result = {
            "nested_mount_observed": str(nested) in nested_paths,
            "descriptor_content_before_unmount": pinned_content,
            "descriptor_content_after_unmount": content_after_unmount,
            "descriptor_remained_pinned": content_after_unmount == "pinned",
            "nested_mount_unmounted": nested_unmounted,
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if all(result.values()) else 70


if __name__ == "__main__":
    raise SystemExit(main())
