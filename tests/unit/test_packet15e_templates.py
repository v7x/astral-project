"""Packet 15E package templates remain parseable before root installation."""

from __future__ import annotations

import shutil
import stat
import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
PACKAGING = ROOT / "packaging"


def test_broker_apparmor_allows_only_authenticated_stream_ipc() -> None:
    profile = (PACKAGING / "apparmor" / "usr.libexec.astral-project.aspr-broker").read_text(
        encoding="utf-8"
    )
    assert "  unix (accept, getattr, receive, send) type=stream," in profile
    assert "  deny network inet," in profile
    assert "  deny network," in profile


def test_final_workload_apparmor_has_explicit_device_and_mapping_rules() -> None:
    profile = (PACKAGING / "apparmor" / "usr.libexec.astral-project.aspr-broker").read_text(
        encoding="utf-8"
    )
    for rule in (
        "  /dev/null rw,",
        "  /dev/zero rw,",
        "  /dev/full rw,",
        "  /dev/random r,",
        "  /dev/urandom r,",
        "  unix (getattr, getopt, setopt, shutdown),",
        "  /** mr,",
        "  deny unix (create),",
    ):
        assert rule in profile


def test_apparmor_profile_preprocesses_without_loading() -> None:
    profile = (PACKAGING / "apparmor" / "usr.libexec.astral-project.aspr-broker").read_text(
        encoding="utf-8"
    )
    assert "abi <abi/4.0>," in profile
    parser = shutil.which("apparmor_parser")
    if parser is None:
        pytest.skip("AppArmor parser is not installed")
    subprocess.run(
        [parser, "-p", str(PACKAGING / "apparmor" / "usr.libexec.astral-project.aspr-broker")],
        check=True,
        capture_output=True,
        text=True,
    )


def test_systemd_units_verify_in_disposable_root(tmp_path: Path) -> None:
    verifier = shutil.which("systemd-analyze")
    if verifier is None:
        pytest.skip("systemd-analyze is not installed")
    unit_dir = tmp_path / "usr/lib/systemd/system"
    executable = tmp_path / "usr/libexec/astral-project/aspr-broker"
    unit_dir.mkdir(parents=True)
    executable.parent.mkdir(parents=True)
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    for unit in PACKAGING.joinpath("systemd").iterdir():
        shutil.copy2(unit, unit_dir / unit.name)
    for name in ("sysinit.target", "sockets.target", "multi-user.target", "network.target"):
        (unit_dir / name).write_text("[Unit]\nDescription=test target\n", encoding="ascii")
    subprocess.run(
        [
            verifier,
            f"--root={tmp_path}",
            "verify",
            "astral-project-broker.socket",
            "astral-project-broker.service",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_broker_launcher_uses_isolated_no_site_startup() -> None:
    launcher = (PACKAGING / "launchers" / "aspr-broker").read_text(encoding="utf-8")
    assert "/usr/bin/python3 -I -S -c" in launcher
    assert "/usr/lib/astral-project/python" in launcher
    assert "PYTHONPATH" not in launcher
    result = subprocess.run(
        [
            "/usr/bin/python3",
            "-I",
            "-S",
            "-c",
            "import sys; sys.path.insert(0, 'src'); import astral_project; print(sys.path)",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "site-packages" not in result.stdout


def test_source_root_renderer_is_packaged_and_provisioned() -> None:
    build = (PACKAGING / "debian" / "build-deb.sh").read_text(encoding="utf-8")
    postinst = (PACKAGING / "debian" / "postinst").read_text(encoding="utf-8")
    assert "render-apparmor-roots" in build
    assert "render-apparmor-roots" in postinst
    assert "apparmor_parser" not in postinst


def test_deb_builder_handles_old_and_new_dpkg_deb() -> None:
    build = (PACKAGING / "debian" / "build-deb.sh").read_text(encoding="utf-8")
    assert "dpkg-deb --help" in build
    assert "--compression=gzip" in build
    assert 'dpkg-deb --build --root-owner-group "$pkg" "$out"' in build


def test_packet15f_gate_has_fixed_paths_and_no_argument_surface() -> None:
    source = (PACKAGING / "tools" / "packet15f-gate.py").read_text(encoding="utf-8")
    assert 'EVIDENCE = Path("/var/lib/astral-project/evidence/packet15f.json")' in source
    assert 'CONFIG = Path("/etc/astral-project/broker.toml")' in source
    assert "sys.argv" not in source
    assert "subprocess.run(arguments" in source


def test_root_owned_package_configuration_is_fixed() -> None:
    with (PACKAGING / "config" / "broker.toml").open("rb") as stream:
        config = tomllib.load(stream)
    assert config == {
        "version": 1,
        "socket_path": "/run/astral-project/broker.sock",
        "runtime_root": "/var/lib/astral-project/runtime/sftp_v1",
        "runtime_manifest_digest": "",
        "mount_worker": "/usr/libexec/astral-project/aspr-mount-worker",
        "namespace_worker": "/usr/libexec/astral-project/aspr-namespace-worker",
        "authority_path": "/etc/astral-project/authority.toml",
        "workload": "sftp_v1",
        "backend_id": "admin_bootstrapped_broker_v1",
    }
