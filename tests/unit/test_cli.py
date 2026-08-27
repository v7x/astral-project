"""Public command identity tests."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from io import StringIO
from pathlib import Path
from typing import NoReturn

import pytest

from astral_project import PROTOCOL_VERSION, TARGET_PLATFORM, __version__, cli

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_DIRECTORY = Path(sys.executable).parent


def run_launcher(name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(LAUNCHER_DIRECTORY / name), *arguments],
        capture_output=True,
        check=False,
        cwd=PROJECT_ROOT,
        text=True,
    )


@pytest.mark.parametrize("arguments", [("version",), ("version", "--json")])
def test_public_launchers_match(arguments: tuple[str, ...]) -> None:
    astral_project = run_launcher("astral-project", *arguments)
    aspr = run_launcher("aspr", *arguments)

    assert astral_project.returncode == 0
    assert aspr.returncode == 0
    assert astral_project.stderr == aspr.stderr == ""
    assert astral_project.stdout == aspr.stdout


def test_version_json_schema() -> None:
    result = run_launcher("aspr", "version", "--json")

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["package_version"] == __version__
    assert payload["protocol_version"] == PROTOCOL_VERSION
    assert payload["python_version"] == sys.version.split()[0]
    assert payload["target_platform"] == TARGET_PLATFORM
    assert isinstance(payload["git_revision"], str)
    assert payload["git_revision"]


def test_unknown_command_has_stable_error() -> None:
    result = run_launcher("aspr", "unknown")

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == (
        "ASPR_CLI_UNKNOWN_COMMAND [1001]: unknown command 'unknown'\n"
        "Security result: command was not run\n"
        "Why: public command surface is fixed\n"
        "Fix: run `aspr version` for available command\n"
    )


def test_only_two_public_console_scripts_exist() -> None:
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["scripts"] == {
        "astral-project": "astral_project.cli:main",
        "aspr": "astral_project.cli:main",
    }


def test_run_supports_text_and_both_json_positions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "_git_revision", lambda: "deadbeef")

    text_stdout = StringIO()
    assert cli.run(["version"], stdout=text_stdout, stderr=StringIO()) == 0
    assert "git_revision: deadbeef\n" in text_stdout.getvalue()

    for arguments in (["version", "--json"], ["--json", "version"]):
        json_stdout = StringIO()
        assert cli.run(arguments, stdout=json_stdout, stderr=StringIO()) == 0
        assert json.loads(json_stdout.getvalue())["git_revision"] == "deadbeef"


def test_run_dispatches_transport_key_ssh_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    called: dict[str, object] = {}

    def fake_entry(key: str, **kwargs: object) -> int:
        called["key"] = key
        called.update(kwargs)
        return 17

    monkeypatch.setattr(cli, "run_ssh_entry", fake_entry)
    assert (
        cli.run(
            ["server", "ssh-entry", "--transport-key", "key-id"],
            stdout=StringIO(),
            stderr=StringIO(),
        )
        == 17
    )
    assert called["key"] == "key-id"
    assert called["stderr"] is not None


def test_run_rejects_unknown_and_reserves_internal_modes() -> None:
    stderr = StringIO()
    assert cli.run([], stdout=StringIO(), stderr=stderr) == 2
    assert stderr.getvalue() == (
        "ASPR_CLI_UNKNOWN_COMMAND [1001]: unknown command ''\n"
        "Security result: command was not run\n"
        "Why: public command surface is fixed\n"
        "Fix: run `aspr version` for available command\n"
    )

    stderr = StringIO()
    assert cli.run(["__internal", "homed"], stdout=StringIO(), stderr=stderr) == 70
    assert stderr.getvalue() == "ASPR_HOMED_MOUNTPOINT is required for internal homed mode\n"

    stderr = StringIO()
    assert cli._run_internal("unknown", stderr) == 70
    assert "internal mode 'unknown' is unavailable" in stderr.getvalue()

    stderr = StringIO()
    assert cli.run(["__internal", "unknown"], stdout=StringIO(), stderr=stderr) == 2
    assert stderr.getvalue() == (
        "ASPR_CLI_UNKNOWN_COMMAND [1001]: unknown command '__internal'\n"
        "Security result: command was not run\n"
        "Why: public command surface is fixed\n"
        "Fix: run `aspr version` for available command\n"
    )


def test_homed_internal_mode_reports_start_and_runtime_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, bool]] = []

    def started(path: str, *, debug: bool = False) -> None:
        calls.append((path, debug))

    monkeypatch.setenv("ASPR_HOMED_MOUNTPOINT", "/tmp/projected")
    monkeypatch.setenv("ASPR_HOMED_DEBUG", "1")
    monkeypatch.setattr("astral_project.homed.fuse.mount_empty", started)
    assert cli.run(["__internal", "homed"], stdout=StringIO(), stderr=StringIO()) == 0
    assert calls == [("/tmp/projected", True)]

    def failed(_path: str, *, debug: bool = False) -> None:
        del debug
        raise OSError("boom")

    monkeypatch.setattr("astral_project.homed.fuse.mount_empty", failed)
    stderr = StringIO()
    assert cli.run(["__internal", "homed"], stdout=StringIO(), stderr=stderr) == 70
    assert "aspr-homed could not start: boom" in stderr.getvalue()


def test_main_uses_process_streams(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "_git_revision", lambda: "deadbeef")
    monkeypatch.setattr(sys, "argv", ["aspr", "version"])

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 0
    assert "git_revision: deadbeef\n" in capsys.readouterr().out


def test_git_revision_reads_successful_command(monkeypatch: pytest.MonkeyPatch) -> None:
    def successful_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["git"], returncode=0, stdout="deadbeef\n", stderr=""
        )

    monkeypatch.setattr(subprocess, "run", successful_run)

    assert cli._git_revision() == "deadbeef"


@pytest.mark.parametrize(("returncode", "stdout"), [(1, "deadbeef\n"), (0, "")])
def test_git_revision_rejects_missing_revision(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str
) -> None:
    def failed_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=["git"], returncode=returncode, stdout=stdout, stderr=""
        )

    monkeypatch.setattr(subprocess, "run", failed_run)

    assert cli._git_revision() == "unavailable"


@pytest.mark.parametrize("error", [OSError("missing git"), subprocess.TimeoutExpired("git", 1.0)])
def test_git_revision_handles_execution_failure(
    monkeypatch: pytest.MonkeyPatch, error: OSError | subprocess.TimeoutExpired
) -> None:
    def unavailable_run(*args: object, **kwargs: object) -> NoReturn:
        raise error

    monkeypatch.setattr(subprocess, "run", unavailable_run)

    assert cli._git_revision() == "unavailable"
