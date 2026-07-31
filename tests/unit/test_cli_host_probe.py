from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

import pytest

from astral_project import cli
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.host.records import HostRecord

FIXTURE = Path(__file__).parents[1] / "fixtures" / "hosts" / "supported.toml"


def test_host_probe_and_probe_file_doctor(monkeypatch: pytest.MonkeyPatch) -> None:
    record = HostRecord.load(FIXTURE)
    monkeypatch.setattr(
        cli, "run_ssh_probe", lambda target, runner: (record.probe, record.ssh_host_fingerprint)
    )
    stdout = StringIO()
    assert cli.run(["host", "probe", "alice@cluster"], stdout=stdout, stderr=StringIO()) == 0
    assert json.loads(stdout.getvalue())["ssh_host_fingerprint"] == record.ssh_host_fingerprint
    stdout = StringIO()
    assert (
        cli.run(["host", "doctor", "--probe-file", str(FIXTURE)], stdout=stdout, stderr=StringIO())
        == 0
    )
    assert json.loads(stdout.getvalue()) == record.probe.to_dict()


def test_host_probe_cli_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    error = AstralError(ErrorCode.HOST_PROBE, "bad", "rejected", "unsafe", "fix")
    monkeypatch.setattr(cli, "run_ssh_probe", lambda target, runner: (_ for _ in ()).throw(error))
    assert cli.run(["host", "probe", "bad"], stdout=StringIO(), stderr=StringIO()) == 70
    assert cli.run(["host", "doctor", "--probe-file"], stdout=StringIO(), stderr=StringIO()) == 2
    assert (
        cli.run(
            ["host", "doctor", "--probe-file", "/missing/record.toml"],
            stdout=StringIO(),
            stderr=StringIO(),
        )
        == 70
    )
    assert cli.run(["host", "update-server"], stdout=StringIO(), stderr=StringIO()) == 70
    assert cli.run(["host", "remove"], stdout=StringIO(), stderr=StringIO()) == 70
