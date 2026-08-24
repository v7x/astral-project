"""Public lifecycle command parsing tests."""

from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest

from astral_project import cli
from astral_project.core.errors import AstralError, ErrorCode


def invoke(
    arguments: list[str],
    monkeypatch: pytest.MonkeyPatch,
    result: dict[str, object] | None = None,
) -> tuple[int, str, str]:
    output = StringIO()
    diagnostic = StringIO()
    monkeypatch.setattr(cli, "_daemon_request", lambda _op, _payload=None: result or {"ok": True})
    code = cli.run(arguments, stdout=output, stderr=diagnostic)
    return code, output.getvalue(), diagnostic.getvalue()


def test_grant_commands(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for arguments in (
        ["grant", "list"],
        ["grant", "list", "--all"],
        ["grant", "show", "g"],
        ["grant", "validate", "g"],
        ["grant", "revoke", "g"],
        ["grant", "revoke", "g", "--reason", "done"],
    ):
        assert invoke(arguments, monkeypatch)[0] == 0
    envelope = tmp_path / "grant.cbor"
    envelope.write_bytes(b"signed")
    public_key = tmp_path / "issuer.pub"
    public_key.write_bytes(b"p" * 32)
    assert invoke(["grant", "import", str(envelope)], monkeypatch)[0] == 0
    assert invoke(["grant", "import", str(envelope), str(public_key)], monkeypatch)[0] == 0
    assert invoke(["grant", "create", str(envelope)], monkeypatch)[0] == 0


def test_session_and_mount_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    for arguments in (
        ["session", "list"],
        ["session", "open", "g"],
        ["session", "show", "s"],
        ["session", "close", "s"],
        ["mount", "list"],
        ["mount", "show", "m"],
        ["mount", "close", "m"],
        ["mount", "open", "/tmp/m", "/project", "ro"],
        ["mount", "open", "/tmp/m", "/project", "rw", "--read-write"],
    ):
        assert invoke(arguments, monkeypatch)[0] == 0


def test_lifecycle_daemon_errors_and_unknown_shapes(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(_op: str, _payload: object = None) -> dict[str, object]:
        raise AstralError(ErrorCode.DAEMON_UNAVAILABLE, "offline", "none", "none", "retry")

    original_request = cli._daemon_request
    monkeypatch.setattr(cli, "_daemon_request", fail)
    output = StringIO()
    diagnostic = StringIO()
    assert cli._run_json_operation("session.list", None, output, diagnostic) == 70
    assert "offline" in diagnostic.getvalue()
    monkeypatch.setattr(
        cli,
        "DaemonClient",
        lambda _socket: SimpleNamespace(request=lambda **_kwargs: "bad"),
    )
    with pytest.raises(AstralError, match="invalid result"):
        original_request("session.list")
    monkeypatch.setattr(
        cli,
        "DaemonClient",
        lambda _socket: SimpleNamespace(request=lambda **_kwargs: {"ok": True}),
    )
    assert original_request("session.list") == {"ok": True}
    assert invoke(["grant", "revoke", "g", "bad"], monkeypatch)[0] == 2
    assert invoke(["session", "close"], monkeypatch)[0] == 2
    assert invoke(["mount", "bogus"], monkeypatch)[0] == 2


def test_lifecycle_errors_stay_stable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    code, _output, diagnostic = invoke(
        ["mount", "open", "/tmp/m", "/project", "ro", "bad"], monkeypatch
    )
    assert code == 70
    assert "mount open accepts only" in diagnostic
    missing = tmp_path / "missing"
    code, _output, diagnostic = invoke(["grant", "import", str(missing)], monkeypatch)
    assert code == 70
    assert "could not be read" in diagnostic
