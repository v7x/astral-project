from __future__ import annotations

import base64
from io import BytesIO, StringIO
from pathlib import Path
from typing import TextIO, cast

import pytest

from astral_project import cli
from astral_project.core.errors import AstralError
from astral_project.daemon.server import DaemonPaths


def test_cli_ls_decodes_daemon_byte_channels(monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        def __init__(self, _path: Path) -> None:
            pass

        def request(self, **_kwargs: object) -> dict[str, object]:
            return {
                "stderr_b64": base64.b64encode(b"diag\n").decode(),
                "stdout_b64": base64.b64encode(b"listing\n").decode(),
                "version": 1,
            }

    monkeypatch.setattr(cli, "DaemonClient", Client)
    monkeypatch.setattr(
        cli, "_daemon_paths", lambda: DaemonPaths(Path("/tmp/runtime"), Path("/tmp/state"))
    )
    stdout, stderr = StringIO(), StringIO()
    assert cli.run(["ls", "grant:/", "--recursive"], stdout=stdout, stderr=stderr) == 0
    assert stdout.getvalue() == "listing\n"
    assert stderr.getvalue() == "diag\n"


def test_cli_ls_parser_covers_options_and_failures() -> None:
    payload = cli._ls_payload(
        [
            "ls",
            "grant:/",
            "-R",
            "--stat",
            "--json",
            "--raw",
            "--no-header",
            "--reverse",
            "--sort",
            "name",
            "--max-depth",
            "2",
            "--timeout",
            "1.5",
            "--filter",
            "*.py",
        ]
    )
    assert payload["recursive"] is True and payload["stat"] is True
    assert payload["no_header"] is True and payload["reverse"] is True
    with pytest.raises(AstralError):
        cli._ls_payload(["ls"])
    cases = (
        ["ls", "grant:/", "--filter"],
        ["ls", "grant:/", "--max-depth", "x"],
        ["ls", "grant:/", "--timeout", "x"],
        ["ls", "grant:/", "--unknown"],
    )
    for arguments in cases:
        with pytest.raises(AstralError):
            cli._ls_payload(arguments)


def test_cli_ls_rejects_bad_daemon_results(monkeypatch: pytest.MonkeyPatch) -> None:
    class Client:
        def __init__(self, _path: Path) -> None:
            pass

        def request(self, **_kwargs: object) -> dict[str, object]:
            return {"bad": True}

    monkeypatch.setattr(cli, "DaemonClient", Client)
    monkeypatch.setattr(
        cli, "_daemon_paths", lambda: DaemonPaths(Path("/tmp/runtime"), Path("/tmp/state"))
    )
    stderr = StringIO()
    assert cli.run(["ls", "grant:/"], stdout=StringIO(), stderr=stderr) == 70
    assert "daemon listing response is invalid" in stderr.getvalue()

    class BadEncodingClient(Client):
        def request(self, **_kwargs: object) -> dict[str, object]:
            return {"stderr_b64": "!", "stdout_b64": "!", "version": 1}

    monkeypatch.setattr(cli, "DaemonClient", BadEncodingClient)
    stderr = StringIO()
    assert cli.run(["ls", "grant:/"], stdout=StringIO(), stderr=stderr) == 70
    assert "encoding is invalid" in stderr.getvalue()

    class BadFieldsClient(Client):
        def request(self, **_kwargs: object) -> dict[str, object]:
            return {"stderr_b64": 1, "stdout_b64": "", "version": 1}

    monkeypatch.setattr(cli, "DaemonClient", BadFieldsClient)
    stderr = StringIO()
    assert cli.run(["ls", "grant:/"], stdout=StringIO(), stderr=stderr) == 70
    assert "fields are invalid" in stderr.getvalue()


def test_cli_write_bytes_supports_binary_stream() -> None:
    class TextWithBuffer:
        def __init__(self) -> None:
            self.buffer = BytesIO()

        def write(self, value: str) -> int:
            return len(value)

        def flush(self) -> None:
            return None

    stream = TextWithBuffer()
    cli._write_bytes(cast(TextIO, stream), b"raw")
    assert stream.buffer.getvalue() == b"raw"


def test_cli_transport_dispatch_is_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake_transport(*args: object, **kwargs: object) -> int:
        observed["args"] = args
        observed["kwargs"] = kwargs
        return 23

    monkeypatch.setattr(cli, "run_transport", fake_transport)
    assert cli.run(["transport", "-s", "sftp"], stdout=StringIO(), stderr=StringIO()) == 23
    assert observed["args"] == (["-s", "sftp"],)
