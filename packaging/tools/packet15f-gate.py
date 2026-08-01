#!/usr/bin/python3
"""Packet 15F fixed-path package preflight. No installer or mutator."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path

EVIDENCE = Path("/var/lib/astral-project/evidence/packet15f.json")
CONFIG = Path("/etc/astral-project/broker.toml")
CEILINGS = Path("/etc/astral-project/ceilings")
RUNTIME = Path("/var/lib/astral-project/runtime/sftp_v1")
SOCKET_UNIT = "astral-project-broker.socket"
PROFILES = frozenset({"aspr-broker", "aspr-namespace-setup", "aspr-sftp-v1"})
ROOT_ARTIFACTS = (
    Path("/usr/libexec/astral-project/aspr-broker"),
    Path("/usr/libexec/astral-project/aspr-namespace-worker"),
    Path("/usr/libexec/astral-project/aspr-mount-worker"),
    CONFIG,
)


def main() -> int:
    if os.geteuid() != 0:
        return _fail("gate requires root")
    try:
        evidence = {
            "apparmor": _profiles(),
            "broker_config_sha256": _digest(CONFIG),
            "ceilings_sha256": _tree_digest(CEILINGS),
            "kernel": os.uname().release,
            "os_release": _os_release(),
            "runtime": _runtime(),
            "systemd": _command(("/usr/bin/systemctl", "--version")).splitlines()[0],
            "version": 1,
        }
        _root_artifacts()
        if _command(("/usr/bin/systemctl", "is-enabled", SOCKET_UNIT)).strip() != "enabled":
            raise RuntimeError("broker socket is not enabled")
        EVIDENCE.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_evidence(evidence)
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        return _fail(str(error))
    return 0


def _root_artifacts() -> None:
    for path in ROOT_ARTIFACTS:
        details = path.lstat()
        if details.st_uid != 0 or details.st_mode & 0o022 or not stat.S_ISREG(details.st_mode):
            raise RuntimeError(f"unsafe package artifact: {path}")


def _profiles() -> dict[str, object]:
    raw = _command(("/usr/sbin/aa-status", "--json"))
    parsed = json.loads(raw)
    listed = parsed.get("profiles", ())
    profiles = (
        set(listed)
        if isinstance(listed, list)
        else set(listed)
        if isinstance(listed, Mapping)
        else set()
    )
    missing = sorted(PROFILES - profiles)
    if missing:
        raise RuntimeError("required AppArmor profiles are absent: " + ",".join(missing))
    return {
        "required_profiles": sorted(PROFILES),
        "sha256": hashlib.sha256(raw.encode()).hexdigest(),
    }


def _runtime() -> dict[str, str]:
    with CONFIG.open("rb") as stream:
        configured = tomllib.load(stream).get("runtime_manifest_digest")
    if not isinstance(configured, str) or re.fullmatch(r"[a-f0-9]{64}", configured) is None:
        raise RuntimeError("configured active runtime digest is invalid")
    closure = RUNTIME / configured
    manifest = closure / "manifest.cbor"
    if not closure.is_dir() or not manifest.is_file():
        raise RuntimeError("configured runtime closure is absent")
    return {"digest": configured, "manifest_sha256": _digest(manifest)}


def _os_release() -> str:
    values = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    return values.get("PRETTY_NAME", "unknown").strip('"')


def _command(arguments: tuple[str, ...]) -> str:
    return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(
            path.relative_to(root).as_posix().encode() + b"\0" + bytes.fromhex(_digest(path))
        )
    return digest.hexdigest()


def _write_evidence(value: dict[str, object]) -> None:
    temporary = EVIDENCE.with_suffix(".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, EVIDENCE)


def _fail(message: str) -> int:
    print(f"packet15f-gate: {message}", file=sys.stderr)
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
