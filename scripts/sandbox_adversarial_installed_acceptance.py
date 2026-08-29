#!/usr/bin/env python3
"""Installed Packet 40 acceptance with an empty inherited capability boundary."""

from __future__ import annotations

import ctypes
import os
import pwd
import subprocess
from pathlib import Path


class _CapabilityHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapabilityData(ctypes.Structure):
    _fields_ = [
        ("effective", ctypes.c_uint32),
        ("permitted", ctypes.c_uint32),
        ("inheritable", ctypes.c_uint32),
    ]


def _set_capabilities(libc: ctypes.CDLL, mask: int) -> None:
    header = _CapabilityHeader(0x20080522, 0)
    data = (_CapabilityData * 2)()
    data[0].effective = data[0].permitted = data[0].inheritable = mask
    if libc.syscall(126, ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))


def _drop_bounding_set(libc: ctypes.CDLL) -> None:
    for capability in range(64):
        result = libc.syscall(157, 24, capability, 0, 0, 0)
        if result == 0:
            continue
        error = ctypes.get_errno()
        if error == 22:
            continue
        if error == 1 and libc.syscall(157, 23, capability, 0, 0, 0) == 0:
            continue
        raise OSError(error, os.strerror(error))


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("run installed adversarial acceptance as root")
    user = os.environ.get("SUDO_USER", "aspr-admin")
    account = pwd.getpwnam(user)
    runtime = Path(f"/run/user/{account.pw_uid}")
    details = runtime.stat()
    if (details.st_uid, details.st_gid, details.st_mode & 0o777) != (
        account.pw_uid,
        account.pw_gid,
        0o700,
    ):
        raise SystemExit("normal runtime directory has unsafe ownership or mode")
    status = subprocess.run(["aa-status"], capture_output=True, text=True, check=False)
    if "aspr-bwrap-setup" not in status.stdout or "aspr-sandbox-payload" not in status.stdout:
        raise SystemExit("installed AppArmor profiles are not loaded")
    script = Path(__file__).with_name("sandbox_enforce_acceptance.py")
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(8, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    os.setgroups([account.pw_gid])
    os.setgid(account.pw_gid)
    os.setuid(account.pw_uid)
    _set_capabilities(libc, (1 << 21) | (1 << 8))
    if libc.prctl(47, 2, 21, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), os.strerror(ctypes.get_errno()))
    _drop_bounding_set(libc)
    _set_capabilities(libc, 1 << 21)
    child_environment = os.environ | {"XDG_RUNTIME_DIR": str(runtime)}
    result = subprocess.run(
        ["python3", str(script)],
        env=child_environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    print(result.stdout, end="")
    print(result.stderr, end="")
    if result.returncode:
        raise SystemExit(result.returncode)
    print("PASS installed Packet 40 adversarial sandbox acceptance with empty CapBnd")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
