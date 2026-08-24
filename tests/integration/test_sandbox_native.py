from __future__ import annotations

import struct
import subprocess
from pathlib import Path

from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode

ROOT = Path(__file__).parents[2]
LAUNCHER_SOURCE = ROOT / "packaging/native/aspr-bwrap-launch.c"
ENTRY_SOURCE = ROOT / "packaging/native/aspr-sandbox-entry.c"
POSTINST = ROOT / "packaging/debian/postinst"


def _build(source: Path, output: Path) -> None:
    subprocess.run(
        ["cc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(output)],
        check=True,
        capture_output=True,
        text=True,
    )


def _run(launcher: Path, plan: bytes, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run([str(launcher), *arguments], input=plan, capture_output=True, check=False)


def _string(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack("!I", len(encoded)) + encoded


def _remote_plan(
    *targets: str,
    mode: int = 0,
    source: str = "/tmp/aspr-native-source",
    mount_id: str = "a" * 32,
) -> bytes:
    payload = bytearray(b"ASPRSB01")
    payload.extend(struct.pack("!BI", 0, 1))
    payload.extend(_string("/bin/true"))
    payload.extend(struct.pack("!I", len(targets)))
    for target in targets:
        payload.extend(bytes((mode,)))
        payload.extend(_string(mount_id))
        payload.extend(_string(source))
        payload.extend(_string(target))
    payload.extend(b"\x00\x00")
    return bytes(payload)


def test_native_launcher_rejects_malformed_and_alternate_authority(tmp_path: Path) -> None:
    launcher = tmp_path / "launcher"
    entry = tmp_path / "entry"
    _build(LAUNCHER_SOURCE, launcher)
    _build(ENTRY_SOURCE, entry)

    invalid = _run(launcher, b"BADPLAN!")
    assert invalid.returncode == 70
    assert b"magic or version" in invalid.stderr

    valid = LocalSandboxPlan(("/bin/true",), NetworkMode.INHERIT).plan_bytes()
    unknown_version = _run(launcher, b"ASPRSB02" + valid[8:])
    assert unknown_version.returncode == 70
    assert b"magic or version" in unknown_version.stderr
    unknown_field = _run(launcher, valid + struct.pack("!I", 0x554E4B4E))
    assert unknown_field.returncode == 70
    assert b"trailing bytes" in unknown_field.stderr
    bad_network = bytearray(valid)
    bad_network[8] = 2
    network = _run(launcher, bytes(bad_network))
    assert network.returncode == 70
    assert b"network mode" in network.stderr
    bad_count = bytearray(valid)
    bad_count[12] = 65
    count = _run(launcher, bytes(bad_count))
    assert count.returncode == 70
    assert b"command count" in count.stderr
    trailing = _run(launcher, valid + b"x")
    assert trailing.returncode == 70
    assert b"trailing bytes" in trailing.stderr

    relative = _run(launcher, LocalSandboxPlan(("relative",), NetworkMode.INHERIT).plan_bytes())
    assert relative.returncode == 70
    assert b"not absolute" in relative.stderr

    malformed_identity = _run(launcher, _remote_plan("/remote", mount_id="bad"))
    assert malformed_identity.returncode == 70
    assert b"mount identity" in malformed_identity.stderr

    malformed_mode = _run(launcher, _remote_plan("/remote", mode=2))
    assert malformed_mode.returncode == 70
    assert b"remote mode" in malformed_mode.stderr

    source = Path("/tmp/aspr-native-source")
    source.mkdir(exist_ok=True)
    marker = source.parent / (".aspr-mount-" + "a" * 32)
    marker.unlink(missing_ok=True)
    missing_marker = _run(launcher, _remote_plan("/remote"))
    assert missing_marker.returncode == 70
    assert b"lacks daemon authority marker" in missing_marker.stderr
    marker.write_text("b" * 32, encoding="ascii")
    mismatch = _run(launcher, _remote_plan("/remote"))
    assert mismatch.returncode == 70
    assert b"authority marker is invalid" in mismatch.stderr
    marker.write_text(("a" * 32) + "extra", encoding="ascii")
    trailing_marker = _run(launcher, _remote_plan("/remote"))
    assert trailing_marker.returncode == 70
    assert b"authority marker is invalid" in trailing_marker.stderr
    marker.unlink()
    marker.symlink_to("/etc/hosts")
    symlink_marker = _run(launcher, _remote_plan("/remote"))
    assert symlink_marker.returncode == 70
    assert b"lacks daemon authority marker" in symlink_marker.stderr
    marker.unlink()
    marker.write_text("a" * 32, encoding="ascii")
    try:
        malformed_bind = _run(launcher, _remote_plan("/remote"))
        assert malformed_bind.returncode == 70
        assert b"FUSE mount" in malformed_bind.stderr
    finally:
        marker.unlink(missing_ok=True)
        source.rmdir()

    collision = _run(launcher, _remote_plan("/same", "/same/child"))
    assert collision.returncode == 70
    assert b"collide or overlap" in collision.stderr

    bad_socket = _run(launcher, valid[:-2] + b"\x02\x00")
    assert bad_socket.returncode == 70
    assert b"socket flag" in bad_socket.stderr

    for raw_args in (
        ("--ro-bind", "/", "/"),
        ("--unshare-net",),
        ("--cap-drop", "ALL"),
        ("/tmp/alternate-helper",),
    ):
        raw_flags = _run(launcher, b"", *raw_args)
        assert raw_flags.returncode == 70

    for raw_args in (
        ("--unshare-net",),
        ("/tmp/alternate-helper",),
        ("/usr/bin/alternate-entrypoint",),
    ):
        valid_with_raw_args = _run(launcher, valid, *raw_args)
        assert valid_with_raw_args.returncode == 70
        assert b"no command-line arguments" in valid_with_raw_args.stderr

    direct = subprocess.run(
        ["/usr/libexec/astral-project/aspr-sandbox-entry", "/bin/true"],
        executable=str(entry),
        capture_output=True,
        check=False,
    )
    assert direct.returncode == 70
    assert b"setup profile" in direct.stderr


def test_postinst_fails_closed_when_apparmor_is_unavailable() -> None:
    postinst = POSTINST.read_text(encoding="utf-8")
    assert "if ! command -v apparmor_parser" in postinst
    assert 'echo "Astral requires AppArmor to load sandbox confinement"' in postinst
    assert "exit 1" in postinst
    assert (
        "apparmor_parser --replace /etc/apparmor.d/usr.libexec.astral-project.aspr-bwrap-launch"
        in postinst
    )


def test_native_sources_pin_all_authority_to_fixed_paths() -> None:
    launcher_source = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    entry_source = ENTRY_SOURCE.read_text(encoding="utf-8")
    assert 'BWRAP "/usr/bin/bwrap"' in launcher_source
    assert 'ENTRY "/usr/libexec/astral-project/aspr-sandbox-entry"' in launcher_source
    assert 'ENTRY "/usr/libexec/astral-project/aspr-sandbox-entry"' in entry_source
    assert "cap-drop" in launcher_source
    assert "unshare-net" in launcher_source
