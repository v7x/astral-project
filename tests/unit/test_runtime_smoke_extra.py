"""Fixed SFTP smoke boundary tests."""

from __future__ import annotations

import struct
import subprocess
from io import BytesIO

import pytest

from astral_project.core.errors import AstralError
from astral_project.runtime import smoke


class _Output(BytesIO):
    def fileno(self) -> int:
        return 1


class _Process:
    def __init__(self) -> None:
        self.stdin = _Output()
        self.stdout = _Output()
        self.stderr = BytesIO()

    def terminate(self) -> None:
        return None

    def communicate(self, **_kwargs: object) -> tuple[bytes, bytes]:
        return b"", b""

    def kill(self) -> None:
        return None


def test_smoke_rejects_nonpositive_timeout() -> None:
    with pytest.raises(AstralError):
        smoke._run_handshake(["true"], 0)


def test_smoke_accepts_version_and_always_terminates(monkeypatch: pytest.MonkeyPatch) -> None:
    process = _Process()
    monkeypatch.setattr(
        "astral_project.runtime.smoke.subprocess.Popen", lambda *_args, **_kwargs: process
    )
    responses = iter([struct.pack(">I", 5), bytes([2]) + struct.pack(">I", 3)])
    monkeypatch.setattr(smoke, "_read_exact", lambda *_args: next(responses))
    assert smoke._run_handshake(["sftp"], 1) == 3


@pytest.mark.parametrize(
    "responses",
    [
        [struct.pack(">I", 4)],
        [struct.pack(">I", 5), bytes([1]) + struct.pack(">I", 3)],
    ],
)
def test_smoke_rejects_bad_workload_response(
    monkeypatch: pytest.MonkeyPatch, responses: list[bytes]
) -> None:
    process = _Process()
    monkeypatch.setattr(
        "astral_project.runtime.smoke.subprocess.Popen", lambda *_args, **_kwargs: process
    )
    values = iter(responses)
    monkeypatch.setattr(smoke, "_read_exact", lambda *_args: next(values))
    with pytest.raises(AstralError):
        smoke._run_handshake(["sftp"], 1)


def test_smoke_translates_process_start_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "astral_project.runtime.smoke.subprocess.Popen",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("missing")),
    )
    with pytest.raises(AstralError):
        smoke._run_handshake(["sftp"], 1)


def test_smoke_kills_process_when_termination_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    class Stuck(_Process):
        calls = 0

        def communicate(self, **_kwargs: object) -> tuple[bytes, bytes]:
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired("sftp", 1)
            return b"", b""

    process = Stuck()
    monkeypatch.setattr(
        "astral_project.runtime.smoke.subprocess.Popen", lambda *_args, **_kwargs: process
    )
    monkeypatch.setattr(smoke, "_read_exact", lambda *_args: struct.pack(">I", 5))
    with pytest.raises(AstralError):
        smoke._run_handshake(["sftp"], 1)


def test_smoke_read_exact_reports_timeout_and_eof(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.runtime.smoke.time.monotonic", lambda: 10.0)
    monkeypatch.setattr("astral_project.runtime.smoke.select.select", lambda *_args: ([], [], []))
    with pytest.raises(AstralError):
        smoke._read_exact(1, 1, 1)
    monkeypatch.setattr("astral_project.runtime.smoke.select.select", lambda *_args: ([1], [], []))
    monkeypatch.setattr("astral_project.runtime.smoke.os.read", lambda *_args: b"")
    with pytest.raises(AstralError):
        smoke._read_exact(1, 1, 1)
