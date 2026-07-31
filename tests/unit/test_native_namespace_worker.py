"""Packet 15A fixed native worker contract tests."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from astral_project.broker.mapping import MappingWorker
from astral_project.core.errors import AstralError

PROJECT_ROOT = Path(__file__).parents[2]
SOURCE = PROJECT_ROOT / "packaging" / "native" / "aspr-namespace-worker.c"


def test_native_mapping_worker_compiles_and_has_no_argument_interface(tmp_path: Path) -> None:
    executable = tmp_path / "aspr-namespace-worker"
    subprocess.run(
        [
            "cc",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            str(SOURCE),
            "-o",
            str(executable),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    result = subprocess.run(
        [str(executable), "caller-controlled"], check=False, capture_output=True
    )

    assert result.returncode == 64
    assert b"accepts no arguments" in result.stderr


def test_mapping_worker_rejects_non_root_or_writable_executable(tmp_path: Path) -> None:
    executable = tmp_path / "worker"
    executable.write_text("not native", encoding="ascii")
    executable.chmod(0o755)

    with pytest.raises(AstralError, match="unsafe ownership"):
        MappingWorker(executable)


def test_native_worker_source_has_mapping_only_authority() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    assert "CLONE_NEWUSER | CLONE_NEWNS" in source
    assert "MAP_READY_FD" in source
    assert "MAP_CONTINUE_FD" in source
    assert "open_tree" not in source
    assert "mount_setattr" not in source
    assert "move_mount" not in source
    assert "execve" not in source
