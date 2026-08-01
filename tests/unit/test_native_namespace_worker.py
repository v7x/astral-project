"""Packet 15A fixed native worker contract tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from astral_project.broker.mapping import MappingWorker, _install_worker_sync_fds
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


@pytest.mark.parametrize("occupied", [(), (3,), (4,), (3, 4)])
def test_sync_fd_relocation_preserves_both_channels(occupied: tuple[int, ...]) -> None:
    ready_read, ready_write = os.pipe()
    continue_read, continue_write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            if 3 in occupied:
                if ready_write != 3:
                    os.dup2(ready_write, 3)
                    os.close(ready_write)
                ready_write = 3
            if 4 in occupied:
                if continue_read != 4:
                    os.dup2(continue_read, 4)
                    os.close(continue_read)
                continue_read = 4
            _install_worker_sync_fds(ready_write, continue_read)
            os.write(3, b"R")
            os._exit(0 if os.read(4, 1) == b"C" else 1)
        except OSError:
            os._exit(2)
    os.close(ready_write)
    os.close(continue_read)
    assert os.read(ready_read, 1) == b"R"
    assert os.write(continue_write, b"C") == 1
    _, status = os.waitpid(child, 0)
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    os.close(ready_read)
    os.close(continue_write)


def test_native_worker_source_has_mapping_only_authority() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    assert "CLONE_NEWUSER | CLONE_NEWNS" in source
    assert "MAP_READY_FD" in source
    assert "MAP_CONTINUE_FD" in source
    assert "open_tree" not in source
    assert "mount_setattr" not in source
    assert "move_mount" not in source
    assert "execve" not in source
