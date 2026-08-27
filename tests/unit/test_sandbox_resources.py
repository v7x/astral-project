from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

from astral_project.profile import CredentialRule, Profile, Sensitivity, SocketRule, WarningLevel
from astral_project.sandbox import environment
from astral_project.sandbox.environment import (
    EnvironmentPolicy,
    close_unlisted_fds,
    inherited_fd_inventory,
)
from astral_project.sandbox.resources import ResourcePolicy, socket_kind, validate_socket_path


def test_environment_policy_removes_secrets_and_invisible_path(tmp_path: Path) -> None:
    visible = tmp_path / "visible"
    visible.mkdir()
    hidden = tmp_path / "hidden"
    hidden.mkdir()
    policy = EnvironmentPolicy(
        allowed_names=frozenset({"LANG", "PATH", "AWS_SECRET_ACCESS_KEY", "TERM"}),
        unset_names=frozenset({"TERM"}),
    )
    result = policy.sanitize(
        {
            "LANG": "C",
            "PATH": os.pathsep.join((str(visible), str(hidden), "/missing")),
            "AWS_SECRET_ACCESS_KEY": "must-not-appear",
            "TERM": "xterm",
        },
        visible_paths=(visible,),
    )
    assert result.values == {"LANG": "C", "PATH": str(visible)}
    assert "AWS_SECRET_ACCESS_KEY" in result.removed_names
    assert policy.diagnostics(result)["removed_path_entries"] == ("<hidden>", "<hidden>")


def test_environment_policy_removes_reserved_control_variables() -> None:
    policy = EnvironmentPolicy(
        allowed_names=frozenset(
            {"LANG", "ASPR_APPROVAL_SOCKET", "ASPR_SESSION_ID", "ASPR_SESSION_SOCKET"}
        ),
        fixed_values=(("ASPR_APPROVAL_SOCKET", "/fixed.sock"),),
    )
    result = policy.sanitize(
        {
            "LANG": "C",
            "ASPR_APPROVAL_SOCKET": "/tmp/approval.sock",
            "ASPR_SESSION_ID": "session",
            "ASPR_SESSION_SOCKET": "/tmp/session.sock",
        }
    )
    assert result.values == {"LANG": "C"}
    assert set(result.removed_names) == {
        "ASPR_APPROVAL_SOCKET",
        "ASPR_SESSION_ID",
        "ASPR_SESSION_SOCKET",
    }


def test_environment_policy_filters_fixed_secrets_and_path(tmp_path: Path) -> None:
    visible = tmp_path / "visible"
    visible.mkdir()
    result = EnvironmentPolicy(
        allowed_names=frozenset(),
        fixed_values=(
            ("API_TOKEN", "must-not-appear"),
            ("PATH", f"{visible}{os.pathsep}/not-visible"),
        ),
    ).sanitize({}, visible_paths=(visible,))
    assert result.values == {"PATH": str(visible)}
    assert result.removed_names == ("API_TOKEN",)
    assert result.removed_path_entries == ("/not-visible",)
    empty_path = EnvironmentPolicy(fixed_values=(("PATH", "/not-visible"),)).sanitize({})
    assert empty_path.values == {}
    assert empty_path.removed_path_entries == ("/not-visible",)


def test_subprocess_environment_rejects_invalid_capabilities() -> None:
    from astral_project.sandbox.environment import sanitize_subprocess_environment

    with pytest.raises(ValueError, match="unsupported transport"):
        sanitize_subprocess_environment({}, capability_environment={"ASPR_OTHER": "x"})
    with pytest.raises(ValueError, match="transport capability"):
        sanitize_subprocess_environment({}, capability_environment={"ASPR_TRANSPORT_TOKEN": ""})


def test_environment_policy_rejects_bad_fixed_value_and_fd_inventory() -> None:
    with pytest.raises(ValueError):
        EnvironmentPolicy(fixed_values=(("X", "bad\x00"),)).sanitize({})
    descriptors = inherited_fd_inventory()
    assert all(fd not in {0, 1, 2} for fd in descriptors)
    close_unlisted_fds(allowed=(0, 1, 2, *descriptors))


def test_resource_policy_requires_exact_socket_and_strong_credentials(tmp_path: Path) -> None:
    harmless = tmp_path / "harmless.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(harmless))
    try:
        profile = Profile(
            1,
            "p",
            "p",
            sockets=(SocketRule(str(harmless), Sensitivity.OTHER, WarningLevel.INFO),),
            credentials=(CredentialRule(".config/token"),),
        )
        policy = ResourcePolicy(profile)
        assert policy.socket(harmless).allowed
        assert socket_kind(harmless) == "pathname-socket"
        assert policy.approved_sockets() == (harmless,)
        assert policy.credential(".config/token").allowed is False
        assert policy.credential(".config/token", strong_confirmation=True).allowed
        assert policy.credential(".config/other").allowed is False
        credential_socket = tmp_path / "credential.sock"
        credential_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        credential_listener.bind(str(credential_socket))
        try:
            credential_policy = ResourcePolicy(
                Profile(
                    1,
                    "credential-socket",
                    "credential-socket",
                    sockets=(SocketRule(str(credential_socket), Sensitivity.CREDENTIAL),),
                )
            )
            assert not credential_policy.socket(credential_socket).allowed
            assert credential_policy.socket(credential_socket, strong_confirmation=True).allowed
        finally:
            credential_listener.close()
    finally:
        listener.close()


def test_environment_policy_rejects_bad_visible_root_and_handles_empty_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixed = EnvironmentPolicy(fixed_values=(("FIXED", "value"),)).sanitize({})
    assert fixed.values == {"FIXED": "value"}
    with pytest.raises(ValueError):
        EnvironmentPolicy().sanitize({}, visible_paths=(Path("relative"),))
    result = EnvironmentPolicy(allowed_names=frozenset({"PATH"})).sanitize(
        {"PATH": os.pathsep.join(("", "relative", str(tmp_path / "missing")))},
        visible_paths=(tmp_path,),
    )
    assert result.values == {}
    monkeypatch.setattr(
        "astral_project.sandbox.environment.os.listdir",
        lambda _path: (_ for _ in ()).throw(OSError()),
    )
    assert inherited_fd_inventory() == ()


def test_close_unlisted_fds_ignores_close_races(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(environment, "inherited_fd_inventory", lambda **_kwargs: (99,))
    monkeypatch.setattr(
        "astral_project.sandbox.environment.os.close",
        lambda _fd: (_ for _ in ()).throw(OSError()),
    )
    close_unlisted_fds()


def test_resource_policy_denies_dangerous_abstract_and_wrong_paths(tmp_path: Path) -> None:
    profile = Profile(
        1,
        "p",
        "p",
        sockets=(SocketRule("/run/docker.sock"),),
    )
    policy = ResourcePolicy(profile)
    assert policy.socket(Path("/run/docker.sock")).allowed is False
    with pytest.raises(ValueError):
        validate_socket_path("@docker")
    with pytest.raises(ValueError):
        validate_socket_path("relative.sock")
    assert socket_kind(tmp_path / "missing") == "missing"
    regular = tmp_path / "regular"
    regular.write_text("x")
    assert socket_kind(regular) == "other"
    assert ResourcePolicy(Profile(1, "p", "p")).approved_sockets() == ()


def test_resource_policy_rejects_invalid_and_missing_approved_resources(tmp_path: Path) -> None:
    policy = ResourcePolicy(Profile(1, "p", "p", sockets=(SocketRule("/run/missing.sock"),)))
    assert policy.socket(Path("relative")).allowed is False
    assert policy.socket(Path("/run/missing.sock")).allowed is False
    assert policy.socket(tmp_path / "not-listed.sock").allowed is False
    validate_socket_path("/tmp/exact.sock")
    regular = tmp_path / "not-socket"
    regular.write_text("x")
    profile = Profile(1, "p2", "p2", sockets=(SocketRule(str(regular)),))
    assert ResourcePolicy(profile).socket(regular).allowed is False
    assert ResourcePolicy(Profile(1, "p3", "p3")).credential("x").allowed is False
    assert not ResourcePolicy(Profile(1, "default", "default")).raw_socket().allowed
    raw_policy = ResourcePolicy(Profile(1, "raw", "raw", raw_socket=True))
    assert raw_policy.raw_socket().allowed is False
    assert raw_policy.raw_socket(strong_confirmation=True).allowed
