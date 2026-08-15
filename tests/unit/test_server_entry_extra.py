"""Forced-entry trust and command validation edge cases."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import HostId, IssuerKeyId
from astral_project.server import entry


def _trust() -> entry.ServerTrust:
    key = Ed25519PrivateKey.generate().public_key()
    issuer = IssuerKeyId("00000000-0000-4000-8000-000000000001")
    return entry.ServerTrust(
        HostId("00000000-0000-4000-8000-000000000002"),
        "SHA256:test",
        "remote",
        {issuer: key},
        frozenset({"transport"}),
    )


def test_command_and_transport_checks() -> None:
    with pytest.raises(AstralError) as command:
        entry._require_exact_command({})
    assert command.value.code is ErrorCode.PROTOCOL_COMMAND
    entry._require_exact_command({"SSH_ORIGINAL_COMMAND": entry.SSH_ORIGINAL_COMMAND})
    with pytest.raises(AstralError) as transport:
        entry._require_transport_key(_trust(), "other")
    assert transport.value.code is ErrorCode.PROTOCOL_COMMAND
    entry._require_transport_key(_trust(), "transport")


def test_issuer_keys_reject_bad_entries() -> None:
    with pytest.raises(AstralError):
        entry._issuer_keys({})
    with pytest.raises(AstralError):
        entry._issuer_keys({"bad": 1})
    with pytest.raises(AstralError):
        entry._issuer_keys({1: "encoded"})  # type: ignore[dict-item]
    with pytest.raises(AstralError):
        entry._issuer_keys({"00000000-0000-4000-8000-000000000001": "%%%"})


def test_text_helpers_and_transport_config_errors() -> None:
    with pytest.raises(TypeError):
        entry._text({}, "x")
    with pytest.raises(TypeError):
        entry._text_list({"x": [1]}, "x")
    with pytest.raises(AstralError):
        entry.load_server_trust("bad key", home=Path("/tmp"))
    with pytest.raises(AstralError):
        entry.load_server_trust("transport", home=Path("/tmp"))


def test_load_server_trust_validates_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / ".config/astral-project/server.toml"
    path.parent.mkdir(parents=True)
    path.write_text("config", encoding="ascii")
    key = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    raw = {
        "version": 1,
        "host_id": "00000000-0000-4000-8000-000000000002",
        "issuer_keys": {"00000000-0000-4000-8000-000000000001": key},
        "remote_user": "remote",
        "ssh_host_key_fingerprint": "SHA256:test",
        "transport_key_ids": ["transport"],
    }
    monkeypatch.setattr(entry, "check_private_path", lambda _path: None)
    monkeypatch.setattr(entry, "load_toml_config", lambda *_args, **_kwargs: raw)
    trust = entry.load_server_trust("transport", home=tmp_path)
    assert trust.remote_user == "remote"


def test_load_server_trust_rejects_typed_and_incomplete_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    key = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    base = {
        "version": 1,
        "host_id": "00000000-0000-4000-8000-000000000002",
        "issuer_keys": {"00000000-0000-4000-8000-000000000001": key},
        "remote_user": "remote",
        "ssh_host_key_fingerprint": "SHA256:test",
        "transport_key_ids": ["transport"],
    }
    monkeypatch.setattr(entry, "check_private_path", lambda _path: None)
    for raw in ({**base, "host_id": 1}, {**base, "remote_user": ""}):
        monkeypatch.setattr(entry, "load_toml_config", lambda *_args, raw=raw, **_kwargs: raw)
        with pytest.raises(AstralError):
            entry.load_server_trust("transport", home=tmp_path)


def test_main_dispatches_valid_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "astral_project.server.entry.sys.argv", ["aspr-server", "--transport-key", "id"]
    )
    monkeypatch.setattr("astral_project.server.entry.run_ssh_entry", lambda *_args, **_kwargs: 3)
    with pytest.raises(SystemExit) as error:
        entry.main()
    assert error.value.code == 3


def test_main_rejects_invalid_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("astral_project.server.entry.sys.argv", ["aspr-server", "bad"])
    with pytest.raises(SystemExit) as error:
        entry.main()
    assert error.value.code == 70


@pytest.mark.parametrize(
    "raw",
    [
        {"version": 2},
        {"version": 1, "host_id": "bad"},
        {
            "version": 1,
            "host_id": "00000000-0000-4000-8000-000000000002",
            "ssh_host_key_fingerprint": "",
            "remote_user": "remote",
            "transport_key_ids": ["transport"],
            "issuer_keys": {"bad": "%%%"},
        },
    ],
)
def test_load_server_trust_rejects_invalid_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw: dict[str, object]
) -> None:
    monkeypatch.setattr(entry, "check_private_path", lambda _path: None)
    monkeypatch.setattr(entry, "load_toml_config", lambda *_args, **_kwargs: raw)
    with pytest.raises(AstralError):
        entry.load_server_trust("transport", home=tmp_path)
