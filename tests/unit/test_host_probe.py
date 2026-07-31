from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.host.probe import (
    REMOTE_PROBE_SCRIPT,
    CommandResult,
    run_ssh_probe,
    subprocess_runner,
)
from astral_project.host.records import HostRecord, ProbeReport

FIXTURE = Path(__file__).parents[1] / "fixtures" / "hosts" / "supported.toml"


def _result(
    *,
    returncode: int = 0,
    stdout: str | None = None,
    stderr: str = "debug1: Server host key: ssh-ed25519 SHA256:verified\n",
) -> CommandResult:
    report = HostRecord.load(FIXTURE).probe.to_dict()
    return CommandResult(returncode, json.dumps(report) if stdout is None else stdout, stderr)


def test_read_only_ssh_probe_uses_existing_config_and_parses_every_field() -> None:
    seen: list[tuple[tuple[str, ...], str]] = []

    def runner(arguments: object, script: str) -> CommandResult:
        seen.append((tuple(arguments), script))  # type: ignore[arg-type]
        return _result()

    report, fingerprint = run_ssh_probe("alice@cluster", runner)
    assert report == HostRecord.load(FIXTURE).probe
    assert fingerprint == "SHA256:verified"
    assert seen[0][0] == ("ssh", "-v", "-o", "BatchMode=yes", "alice@cluster", "sh", "-s")
    assert seen[0][1] == REMOTE_PROBE_SCRIPT


@pytest.mark.parametrize(
    ("target", "result", "code"),
    [
        ("-bad", _result(), ErrorCode.HOST_PROBE),
        ("host", _result(returncode=1, stderr="token=topsecret failed"), ErrorCode.HOST_PROBE),
        ("host", _result(stderr="no fingerprint"), ErrorCode.HOST_PROBE),
        ("host", _result(stdout="not json"), ErrorCode.HOST_PROBE),
        ("host", _result(stdout="[]"), ErrorCode.HOST_PROBE),
    ],
)
def test_probe_rejects_bad_target_or_remote_evidence(
    target: str, result: CommandResult, code: ErrorCode
) -> None:
    with pytest.raises(AstralError) as error:
        run_ssh_probe(target, lambda arguments, script: result)
    assert error.value.code is code
    assert "topsecret" not in (error.value.dependency_error or "")


def test_static_shell_probe_emits_complete_contract() -> None:
    completed = subprocess.run(
        ["/bin/sh", "-s"], input=REMOTE_PROBE_SCRIPT, capture_output=True, check=True, text=True
    )
    payload = json.loads(completed.stdout)
    assert ProbeReport.from_dict(payload).remote_user


def test_subprocess_runner_timeout_and_result(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0, "out", "err")
    )
    assert subprocess_runner(("ssh", "host"), "script") == CommandResult(0, "out", "err")
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired("ssh", 1)),
    )
    with pytest.raises(AstralError) as error:
        subprocess_runner(("ssh", "host"), "script")
    assert error.value.code is ErrorCode.HOST_PROBE
