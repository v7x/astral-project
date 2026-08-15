"""Broker installation and authority configuration validation."""

from __future__ import annotations

import base64
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from astral_project.broker import config
from astral_project.core.errors import AstralError, ErrorCode


def _raw_paths() -> dict[str, object]:
    return {
        "socket_path": "/run/astral-project/broker.sock",
        "runtime_root": "/var/lib/astral-project/runtime/sftp_v1",
        "runtime_manifest_digest": "a" * 64,
        "mount_worker": "/usr/libexec/astral-project/aspr-mount-worker",
        "namespace_worker": "/usr/libexec/astral-project/aspr-namespace-worker",
        "authority_path": "/etc/astral-project/authority.toml",
        "workload": "sftp_v1",
        "backend_id": "admin_bootstrapped_broker_v1",
        "version": 1,
    }


def test_load_install_config_validates_fixed_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "_require_root_owned_regular_file", Mock())
    monkeypatch.setattr(config, "_require_root_owned_path", Mock())
    monkeypatch.setattr(config, "load_toml_config", lambda *_args, **_kwargs: _raw_paths())

    result = config.load_broker_install_config(Path("/config"))

    assert result.socket_path == Path("/run/astral-project/broker.sock")
    assert result.version == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [("socket_path", "relative"), ("runtime_manifest_digest", "bad"), ("version", True)],
)
def test_load_install_config_rejects_invalid_fields(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    raw = _raw_paths()
    raw[field] = value
    monkeypatch.setattr(config, "_require_root_owned_regular_file", Mock())
    monkeypatch.setattr(config, "_require_root_owned_path", Mock())
    monkeypatch.setattr(config, "load_toml_config", lambda *_args, **_kwargs: raw)

    with pytest.raises(AstralError) as error:
        config.load_broker_install_config(Path("/config"))
    assert error.value.code is ErrorCode.CONFIG_PARSE


def test_load_install_config_rejects_version_and_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "_require_root_owned_regular_file", Mock())
    monkeypatch.setattr(config, "_require_root_owned_path", Mock())
    for field, value in (("version", 2), ("backend_id", "other")):
        raw = _raw_paths()
        raw[field] = value
        monkeypatch.setattr(config, "load_toml_config", lambda *_args, raw=raw, **_kwargs: raw)
        with pytest.raises(AstralError):
            config.load_broker_install_config(Path("/config"))


def test_load_install_config_rejects_unsupported_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = _raw_paths()
    raw["workload"] = "other"
    monkeypatch.setattr(config, "_require_root_owned_regular_file", Mock())
    monkeypatch.setattr(config, "_require_root_owned_path", Mock())
    monkeypatch.setattr(config, "load_toml_config", lambda *_args, **_kwargs: raw)

    with pytest.raises(AstralError) as error:
        config.load_broker_install_config(Path("/config"))
    assert error.value.code is ErrorCode.CONFIG_PARSE


def test_root_path_validation_rejects_missing_unsafe_and_nonregular(tmp_path: Path) -> None:
    with pytest.raises(AstralError):
        config._require_root_owned_path(tmp_path / "missing")
    path = tmp_path / "file"
    path.write_text("x", encoding="ascii")
    with pytest.raises(AstralError):
        config._require_root_owned_regular_file(path)
    directory = tmp_path / "directory"
    directory.mkdir()
    with pytest.raises(AstralError):
        config._require_root_owned_regular_file(directory)


def test_root_path_validation_rejects_unsafe_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    cases = [
        SimpleNamespace(st_uid=1, st_mode=0o644),
        SimpleNamespace(st_uid=0, st_mode=0o666),
        SimpleNamespace(st_uid=0, st_mode=0o120777),
    ]
    for details in cases:
        monkeypatch.setattr(
            "astral_project.broker.config.Path.lstat", lambda _path, details=details: details
        )
        with pytest.raises(AstralError):
            config._require_root_owned_path(Path("/config"))

    safe_file = SimpleNamespace(st_uid=0, st_mode=0o100644)
    monkeypatch.setattr("astral_project.broker.config.Path.lstat", lambda _path: safe_file)
    config._require_root_owned_path(Path("/config"))
    directory = SimpleNamespace(st_uid=0, st_mode=0o040755)
    monkeypatch.setattr("astral_project.broker.config.Path.lstat", lambda _path: directory)
    with pytest.raises(AstralError):
        config._require_root_owned_regular_file(Path("/directory"))


def test_private_field_helpers() -> None:
    assert config._absolute({"x": "/tmp/x"}, "x") == Path("/tmp/x")
    assert config._digest({"x": "a" * 64}, "x") == "a" * 64
    assert config._string({"x": "v"}, "x") == "v"
    assert config._integer({"x": 1}, "x") == 1
    for helper, value in (
        (config._absolute, "relative"),
        (config._digest, "g" * 64),
        (config._string, 1),
        (config._integer, True),
    ):
        with pytest.raises(ValueError):
            helper({"x": value}, "x")


def test_load_authority_validates_typed_inputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ceiling = Mock()
    ceiling_path = tmp_path / "ceiling.cbor"
    ceiling_path.write_bytes(b"ceiling")
    monkeypatch.setattr(config, "_require_root_owned_regular_file", Mock())
    monkeypatch.setattr(
        config,
        "load_toml_config",
        lambda *_args, **_kwargs: {
            "ceiling_path": str(ceiling_path),
            "expected_peer_uid": 1000,
            "expected_peer_gid": 1000,
            "host_id": "00000000-0000-4000-8000-000000000001",
            "issuer_keys": {
                "00000000-0000-4000-8000-000000000002": base64.b64encode(b"k" * 32).decode()
            },
            "remote_user": "user",
            "ssh_host_key_fingerprint": "SHA256:test",
            "transport_key_ids": ["transport"],
            "version": 1,
        },
    )
    monkeypatch.setattr(
        "astral_project.broker.config.ServerCeilingV1.from_cbor", lambda _value: ceiling
    )
    monkeypatch.setattr(config, "public_key_from_bytes", lambda _value: Mock())
    authority = config.load_broker_authority(Path("/authority.toml"))
    assert authority.expected_peer_uid == 1000
    assert authority.server_ceiling is ceiling


def _authority_raw(**updates: object) -> dict[str, object]:
    raw: dict[str, object] = {
        "ceiling_path": "/ceiling",
        "expected_peer_uid": 1000,
        "expected_peer_gid": 1000,
        "host_id": "00000000-0000-4000-8000-000000000001",
        "issuer_keys": {},
        "remote_user": "user",
        "ssh_host_key_fingerprint": "SHA256:test",
        "transport_key_ids": ["transport"],
        "version": 1,
    }
    raw.update(updates)
    return raw


@pytest.mark.parametrize(
    "updates",
    [
        {"issuer_keys": "bad"},
        {"transport_key_ids": "bad"},
        {"transport_key_ids": [1]},
        {"version": 2},
    ],
)
def test_load_authority_rejects_malformed_collections_and_version(
    monkeypatch: pytest.MonkeyPatch, updates: dict[str, object]
) -> None:
    monkeypatch.setattr(config, "_require_root_owned_regular_file", Mock())
    monkeypatch.setattr("astral_project.broker.config.Path.read_bytes", lambda _path: b"ceiling")
    monkeypatch.setattr(
        config,
        "load_toml_config",
        lambda *_args, **_kwargs: _authority_raw(**updates),
    )
    monkeypatch.setattr(
        "astral_project.broker.config.ServerCeilingV1.from_cbor", lambda _value: Mock()
    )
    with pytest.raises(AstralError) as error:
        config.load_broker_authority(Path("/authority.toml"))
    assert error.value.code is ErrorCode.CONFIG_PARSE


def test_load_authority_rejects_non_string_issuer_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(config, "_require_root_owned_regular_file", Mock())
    monkeypatch.setattr("astral_project.broker.config.Path.read_bytes", lambda _path: b"ceiling")
    monkeypatch.setattr(
        config,
        "load_toml_config",
        lambda *_args, **_kwargs: _authority_raw(issuer_keys={1: "bad", "key": 1}),
    )
    monkeypatch.setattr(
        "astral_project.broker.config.ServerCeilingV1.from_cbor", lambda _value: Mock()
    )
    with pytest.raises(AstralError):
        config.load_broker_authority(Path("/authority.toml"))


def test_load_authority_rejects_bad_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "_require_root_owned_regular_file", Mock())
    monkeypatch.setattr("astral_project.broker.config.Path.read_bytes", lambda _path: b"ceiling")
    monkeypatch.setattr(
        config,
        "load_toml_config",
        lambda *_args, **_kwargs: _authority_raw(transport_key_ids="bad"),
    )
    monkeypatch.setattr(
        "astral_project.broker.config.ServerCeilingV1.from_cbor", lambda _value: Mock()
    )
    with pytest.raises(AstralError) as error:
        config.load_broker_authority(Path("/authority.toml"))
    assert error.value.code is ErrorCode.CONFIG_PARSE
