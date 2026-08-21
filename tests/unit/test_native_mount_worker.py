"""Packet 15B/15D native descriptor mount and fixed-workload contract."""

from __future__ import annotations

import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]
SOURCE = PROJECT_ROOT / "packaging" / "native" / "aspr-mount-worker.c"


def test_native_mount_worker_compiles_and_rejects_arguments(tmp_path: Path) -> None:
    executable = tmp_path / "aspr-mount-worker"
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(SOURCE), "-o", str(executable)],
        check=True,
        capture_output=True,
        text=True,
    )
    result = subprocess.run([str(executable), "bad"], check=False, capture_output=True)

    assert result.returncode == 64


def test_mount_worker_uses_only_fixed_fd_abi_and_descriptor_syscalls() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    for required in (
        "PLAN 5",
        "STREAM 6",
        "LOG 7",
        "RUNTIME 74",
        '#define STAGING_BASE "/run/astral-project/staging/"',
        'snprintf(staging,sizeof(staging),"%s%ld",STAGING_BASE,(long)getpid())',
        'mount("tmpfs",staging,"tmpfs",MS_NOSUID|MS_NODEV,"mode=0700,uid=0,gid=0")',
        "getpid()",
        "SOURCE_BASE 10",
        "F_GET_SEALS",
        "SYS_statx",
        "SYS_mount_setattr",
        "SYS_move_mount",
        "F_GET_SEALS",
        "seals<0",
        "overlap_target",
        "SYS_pivot_root",
        "MOUNT_ATTR_NOSUID",
        "MOUNT_ATTR_NODEV",
        "MOUNT_ATTR_NOEXEC",
        "FD_CLOEXEC",
        "SYS_capset",
        "PR_SET_SECUREBITS",
        "PR_CAPBSET_DROP",
        "PR_CAP_AMBIENT_CLEAR_ALL",
        "PR_SET_PDEATHSIG",
        "PR_SET_NO_NEW_PRIVS",
        "SYS_close_range",
        'APPARMOR_PROFILE "aspr-sftp-v1"',
        '"/.astral-project-runtime/ld.so"',
        '"--library-path"',
        '"/.astral-project-runtime/sftp-server"',
    ):
        assert required in source
    assert "system(" not in source
    assert "execlp" not in source
    assert "dup2(STREAM,STDERR_FILENO)" not in source
    assert "dup2(LOG,STDERR_FILENO)" in source
    assert "caller-controlled" not in source
    assert "SYS_open_tree" not in source


def test_final_transition_precedes_no_new_privs_and_exec() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    assert source.index("enter_apparmor_profile(apparmor_control)") < source.index(
        "set_no_new_privs()"
    )
    assert source.index("set_no_new_privs()") < source.index("run_fixed_sftp()")
    assert "runtime mount is noexec" in source


def test_packaged_apparmor_has_no_packet15f_diagnostic_allowances() -> None:
    profile = (
        PROJECT_ROOT / "packaging" / "apparmor" / "usr.libexec.astral-project.aspr-broker"
    ).read_text(encoding="utf-8")

    assert "allow mount," not in profile
    assert "/proc/** rw," not in profile
    assert "mount -> /run/astral-project/staging/**," in profile
    assert "  capability kill," in profile
    assert "abi <abi/4.0>," in profile
    assert "  deny userns," in profile
    assert "  userns create," in profile
    assert "signal (send) set=(kill) peer=aspr-sftp-v1," in profile
    assert "signal (send) set=(kill) peer=aspr-namespace-setup," in profile
    assert "signal (receive) set=(kill) peer=aspr-broker," in profile


def test_broker_clones_pinned_mounts_before_worker_mount_namespace() -> None:
    source = (PROJECT_ROOT / "src" / "astral_project" / "broker" / "sources.py").read_text(
        encoding="utf-8"
    )

    assert "linux.clone_mount(source.descriptor)" in source
    assert "linux.statx_descriptor(descriptor)" in source


def test_worker_verifies_source_identities_before_private_mount_namespace() -> None:
    source = SOURCE.read_text(encoding="utf-8")

    assert "unshare(CLONE_NEWUSER)" in source
    assert "unshare(CLONE_NEWNS)" in source
    assert "unshare(CLONE_NEWUSER|CLONE_NEWNS)" not in source
    assert source.index("verify_fd(SOURCE_BASE+slot") < source.index("unshare(CLONE_NEWNS)")
    assert source.index("unshare(CLONE_NEWNS)") < source.index("private mounts")
