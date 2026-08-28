from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from astral_project.core.errors import AstralError
from astral_project.core.ids import GrantId, HostId, IssuerKeyId, SessionId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    SignedGrant,
    SourceIdentity,
)
from astral_project.rclone.listing import (
    ListingOptions,
    RcloneOutput,
    SftpRemoteConfig,
    build_lsjson_argv,
    daemon_bound_listing_handler,
    listing_options_from_payload,
    parse_lsjson,
    render_listing,
    render_sftp_config,
    run_listing,
    run_rclone,
    write_sftp_config,
)


def payload() -> bytes:
    return json.dumps(
        [
            {
                "Path": "b\n.txt",
                "Name": "b\n.txt",
                "Size": 2048,
                "ModTime": "2026-01-01T00:00:00Z",
                "IsDir": False,
            },
            {"Path": "dir", "Name": "dir", "Size": -1, "ModTime": None, "IsDir": True},
        ]
    ).encode()


def test_parse_and_render_listing_safely() -> None:
    entries = parse_lsjson(payload())
    assert entries[0].size == 2048
    table = render_listing(entries)
    assert b"TYPE" in table
    assert b"\\x0a" in table
    normalized = render_listing(entries, options=ListingOptions(json_output=True, sort="name"))
    assert json.loads(normalized)["version"] == 1
    assert b"b\\n.txt" in normalized
    assert b"dir" in render_listing(
        entries, options=ListingOptions(no_header=True, sort="type", reverse=True)
    )


def test_listing_option_and_remote_validation() -> None:
    for kwargs in (
        {"max_depth": -1},
        {"max_depth": 1025},
        {"timeout_seconds": 0},
        {"timeout_seconds": 86401},
        {"sort": "bad"},
        {"filters": ("",)},
        {"filters": ("bad\x00",)},
    ):
        with pytest.raises(AstralError):
            ListingOptions(**kwargs)
    with pytest.raises(AstralError):
        SftpRemoteConfig("", "u", Path("/tmp/key"), Path("/tmp/aspr"))
    with pytest.raises(AstralError):
        SftpRemoteConfig("host name", "u", Path("/tmp/key"), Path("/tmp/aspr"))
    with pytest.raises(AstralError):
        SftpRemoteConfig("host", "u", Path("/tmp/key"), Path("/tmp/aspr"), port=0)
    with pytest.raises(AstralError):
        SftpRemoteConfig("host", "u", Path("relative"), Path("/tmp/aspr"))
    with pytest.raises(AstralError):
        write_sftp_config(
            Path("relative"),
            SftpRemoteConfig("h", "u", Path("/tmp/k"), Path("/tmp/a")),
        )


def test_parse_rejects_malformed_or_unsafe_entries() -> None:
    for raw in (b"{}", b"not-json", b"[1]", b'[{"Path":"","Name":"x","Size":0,"IsDir":false}]'):
        with pytest.raises(AstralError):
            parse_lsjson(raw)
    with pytest.raises(AstralError):
        parse_lsjson(b'[{"Path":"x","Name":"x","Size":-2,"IsDir":false}]')
    with pytest.raises(AstralError):
        parse_lsjson(b'[{"Path":"x","Name":"x","Size":0,"IsDir":"no"}]')
    with pytest.raises(AstralError):
        parse_lsjson(b'[{"Path":"x","Name":"x","Size":0,"IsDir":false,"Hashes":[]} ]')
    with pytest.raises(AstralError):
        parse_lsjson(b'[{"Path":"x","Name":"x\\u0000","Size":0,"IsDir":false}]')
    with pytest.raises(AstralError):
        parse_lsjson(b"[]", max_bytes=0)
    with pytest.raises(AstralError):
        parse_lsjson(b"{}")
    with pytest.raises(AstralError):
        parse_lsjson(b"[{}]")
    with pytest.raises(AstralError):
        parse_lsjson(b'[{"Path":"x","Name":"x","Size":0,"IsDir":false,"ModTime":3}]')


def test_ephemeral_sftp_config_has_fixed_transport_and_no_token(tmp_path: Path) -> None:
    remote = SftpRemoteConfig(
        host="remote.example",
        remote_user="alice",
        identity_file=tmp_path / "id_ed25519",
        transport_program=Path("/usr/bin/aspr"),
    )
    content = render_sftp_config(remote)
    assert "ssh = /usr/bin/aspr" in content
    assert "ssh = /usr/bin/aspr transport" not in content
    assert "shell_type = unix" in content
    assert "disable_hashcheck = true" in content
    assert "token" not in content
    path = write_sftp_config(tmp_path / "rclone.conf", remote)
    assert path.read_text() == content
    assert path.stat().st_mode & 0o077 == 0


def test_rclone_listing_imports_in_clean_process() -> None:
    result = subprocess.run(
        [sys.executable, "-c", "import astral_project.rclone.listing"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_run_rclone_translates_process_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    real_popen = subprocess.Popen

    class TimeoutProcess:
        pid = 123

        def wait(self, timeout: float | None = None) -> int:
            if timeout is not None:
                raise subprocess.TimeoutExpired("rclone", timeout)
            return -9

    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: TimeoutProcess())
    monkeypatch.setattr(os, "killpg", lambda *_args: None)
    with pytest.raises(AstralError):
        run_rclone(["rclone"], {}, 1.0)

    def missing(*_args: object, **_kwargs: object) -> None:
        raise OSError("missing")

    monkeypatch.setattr(subprocess, "Popen", missing)
    with pytest.raises(AstralError):
        run_rclone(["rclone"], {}, None)
    monkeypatch.setattr(subprocess, "Popen", real_popen)

    result = run_rclone(
        ["/bin/sh", "-c", "printf out; printf err >&2"],
        {"RCLONE_CONFIG": "bad", "HOME": "/tmp"},
        None,
    )
    assert result.stdout == b"out"


def test_daemon_bound_listing_owns_capability_and_remote_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import astral_project.transport.local as transport

    identity = tmp_path / "id_ed25519"
    identity.write_bytes(b"key")
    identity.chmod(0o600)
    grant = Grant(
        GrantId("00000000-0000-4000-8000-000000000001"),
        IssuerKeyId("00000000-0000-4000-8000-000000000002"),
        HostId("00000000-0000-4000-8000-000000000003"),
        "SHA256:test",
        "alice",
        1,
        1,
        2,
        b"n" * 32,
        (
            GrantExport(
                "/source",
                "/source",
                "/project",
                AccessMode.READ_ONLY,
                ExportKind.DIRECTORY,
                SourceIdentity(8, 42, "ext4", ExportKind.DIRECTORY),
            ),
        ),
    )

    class FakeServer:
        started = False
        closed = False

        def __init__(self, *_args: object) -> None:
            pass

        def start(self) -> None:
            self.started = True

        def serve_once(self) -> None:
            return None

        def serve_forever(self) -> None:
            return None

        def close(self) -> None:
            self.closed = True

    monkeypatch.setattr(transport, "PrivateTransportServer", FakeServer)
    observed: dict[str, object] = {}

    def runner(
        argv: Sequence[str], _environment: Mapping[str, str], _timeout: float | None
    ) -> RcloneOutput:
        observed["argv"] = list(argv)
        return RcloneOutput(payload(), b"diagnostic", 0)

    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    request_payload = {
        "filters": [],
        "json_output": False,
        "max_depth": None,
        "no_header": False,
        "raw_output": False,
        "recursive": False,
        "reverse": False,
        "sort": "path",
        "stat": False,
        "target": "aspr-session:/project",
        "timeout_seconds": None,
    }
    result = daemon_bound_listing_handler(
        request_payload,
        session_id=str(SessionId("00000000-0000-4000-8000-000000000004")),
        signed_grant=SignedGrant.create(grant, Ed25519PrivateKey.generate()),
        host="127.0.0.1",
        remote_user="alice",
        identity_file=identity,
        port=22,
        binary=Path("/usr/bin/rclone"),
        runtime=runtime,
        transport_program=Path("/usr/bin/aspr-transport"),
        runner=runner,
    )
    assert result["version"] == 1
    assert "aspr-session:/project" in str(observed["argv"])
    assert b"diagnostic" in __import__("base64").b64decode(result["stderr_b64"])
    with pytest.raises(AstralError):
        daemon_bound_listing_handler(
            request_payload,
            session_id=str(SessionId("00000000-0000-4000-8000-000000000004")),
            signed_grant=SignedGrant.create(grant, Ed25519PrivateKey.generate()),
            host="127.0.0.1",
            remote_user="alice",
            identity_file=Path("relative"),
            port=22,
            binary=Path("/usr/bin/rclone"),
            runtime=runtime,
            transport_program=Path("/usr/bin/aspr-transport"),
            runner=runner,
        )
    with pytest.raises(AstralError):
        daemon_bound_listing_handler(
            request_payload,
            session_id="bad-session",
            signed_grant=SignedGrant.create(grant, Ed25519PrivateKey.generate()),
            host="127.0.0.1",
            remote_user="alice",
            identity_file=identity,
            port=22,
            binary=Path("/usr/bin/rclone"),
            runtime=runtime,
            transport_program=Path("/usr/bin/aspr-transport"),
            runner=runner,
        )


def test_listing_payload_validation() -> None:
    base = {
        "filters": [],
        "json_output": False,
        "max_depth": None,
        "no_header": False,
        "raw_output": False,
        "recursive": False,
        "reverse": False,
        "sort": "path",
        "stat": False,
        "target": "grant:/",
        "timeout_seconds": None,
    }
    assert listing_options_from_payload(base)[0] == "grant:/"
    for bad in (
        {},
        {**base, "filters": "bad"},
        {**base, "max_depth": True},
        {**base, "timeout_seconds": True},
        {**base, "recursive": 1},
        {**base, "sort": 1},
    ):
        with pytest.raises(AstralError):
            listing_options_from_payload(bad)


def test_listing_argv_and_runner_security(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    options = ListingOptions(recursive=True, stat=True, max_depth=2, filters=("- *.tmp",))
    argv = build_lsjson_argv(
        binary=Path("/usr/bin/rclone"),
        config=tmp_path / "rclone.conf",
        target="remote:/x",
        options=options,
    )
    assert argv == [
        "/usr/bin/rclone",
        "--config",
        str(tmp_path / "rclone.conf"),
        "--log-level",
        "ERROR",
        "--transfers",
        "1",
        "--checkers",
        "1",
        "--sftp-connections",
        "1",
        "--sftp-concurrency",
        "1",
        "lsjson",
        "--recursive",
        "--stat",
        "--max-depth",
        "2",
        "--filter",
        "- *.tmp",
        "remote:/x",
    ]
    with pytest.raises(AstralError):
        ListingOptions(json_output=True, raw_output=True)
    with pytest.raises(AstralError):
        build_lsjson_argv(binary=Path("rclone"), config=tmp_path / "x", target="remote:/x")

    seen: list[tuple[Sequence[str], Mapping[str, str], float | None]] = []

    def runner(
        argv: Sequence[str], environment: Mapping[str, str], timeout: float | None
    ) -> RcloneOutput:
        seen.append((argv, environment, timeout))
        return RcloneOutput(payload(), b"diagnostic", 0)

    output, diagnostic = run_listing(
        binary=Path("/usr/bin/rclone"),
        config=tmp_path / "rclone.conf",
        target="remote:/x",
        options=ListingOptions(),
        environment={
            "RCLONE_CONFIG": "bad",
            "HOME": "/tmp",
            "AWS_SECRET_ACCESS_KEY": "must-not-appear",
            "ASPR_APPROVAL_SOCKET": "/tmp/approval.sock",
            "PATH": "/usr/bin:/not-visible",
        },
        runner=runner,
    )
    assert b"TYPE" in output and diagnostic == b"diagnostic"
    assert "RCLONE_CONFIG" not in seen[0][1]
    assert "AWS_SECRET_ACCESS_KEY" not in seen[0][1]
    assert "ASPR_APPROVAL_SOCKET" not in seen[0][1]
    assert seen[0][1]["PATH"] == "/usr/bin"
    entries = parse_lsjson(payload())
    assert b"SIZE" in render_listing(entries, options=ListingOptions(sort="size"))
    assert b"MODIFIED" in render_listing(entries, options=ListingOptions(sort="modified"))
    raw, _ = run_listing(
        binary=Path("/usr/bin/rclone"),
        config=tmp_path / "rclone.conf",
        target="remote:/x",
        options=ListingOptions(raw_output=True),
        runner=lambda *_args: RcloneOutput(payload(), b"", 0),
    )
    assert raw == payload()
    with pytest.raises(AstralError):
        run_listing(
            binary=Path("/usr/bin/rclone"),
            config=tmp_path / "rclone.conf",
            target="remote:/x",
            options=ListingOptions(),
            runner=lambda *_args: RcloneOutput(b"", b"failed", 1),
        )

    import astral_project.rclone.listing as listing

    monkeypatch.setattr(listing, "run_listing", lambda **_kwargs: (b"out", b"err"))
    result = listing.daemon_listing_handler(
        {
            "filters": [],
            "json_output": False,
            "max_depth": None,
            "no_header": False,
            "raw_output": False,
            "recursive": False,
            "reverse": False,
            "sort": "path",
            "stat": False,
            "target": "grant:/",
            "timeout_seconds": None,
        },
        binary=Path("/usr/bin/rclone"),
        config=tmp_path / "rclone.conf",
    )
    assert result["version"] == 1
