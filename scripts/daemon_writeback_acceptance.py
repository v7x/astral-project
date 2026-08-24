#!/usr/bin/env python3
"""Installed RW mount writeback acceptance through the real daemon close path."""

from __future__ import annotations

import hashlib
import json
import os
import select
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, "/usr/lib/astral-project/python")

from astral_project.core.ids import GrantId, HostId, IssuerKeyId
from astral_project.crypto.grants import (
    AccessMode,
    ExportKind,
    Grant,
    GrantExport,
    SignedGrant,
    SourceIdentity,
)
from astral_project.crypto.keys import load_private_key
from astral_project.state.sqlite import StateDatabase


def _run(arguments: list[str], environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["/usr/bin/aspr", *arguments],
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )


def _require(result: subprocess.CompletedProcess[str], label: str) -> dict[str, object]:
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed: {result.stderr}")
    value = json.loads(result.stdout)
    if not isinstance(value, dict):
        raise RuntimeError(f"{label} returned a non-object response")
    return value


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: daemon_writeback_acceptance.py RCLONE IDENTITY ISSUER_KEY "
            "HOST_ID HOST_FINGERPRINT",
            file=sys.stderr,
        )
        return 64
    rclone_text, identity_text, issuer_text, host_id_text, fingerprint = sys.argv[1:]
    rclone = Path(rclone_text)
    identity = Path(identity_text)
    issuer_key = Path(issuer_text)
    now = int(time.time())
    source_root = Path.home() / "astral-gate-source"
    source_root.mkdir(mode=0o700, exist_ok=True)
    source_stat = source_root.stat()
    grant = Grant(
        GrantId.new(),
        IssuerKeyId("00000000-0000-4000-8000-000000000001"),
        HostId(host_id_text),
        fingerprint,
        "testuser",
        now,
        now,
        now + 250,
        os.urandom(32),
        (
            GrantExport(
                str(source_root),
                str(source_root),
                "/project",
                AccessMode.READ_WRITE,
                ExportKind.DIRECTORY,
                SourceIdentity(
                    source_stat.st_dev, source_stat.st_ino, "ext4", ExportKind.DIRECTORY
                ),
            ),
        ),
    )
    issuer = load_private_key(issuer_key)
    signed = SignedGrant.create(grant, issuer)
    payload = (b"packet-24a-writeback\n" * (1024 * 1024)) + b"final-byte\n"
    filename = f"writeback-{uuid.uuid4().hex}.bin"
    with tempfile.TemporaryDirectory(prefix="wa-") as temporary:
        root = Path(temporary)
        environment = os.environ.copy()
        environment["XDG_RUNTIME_DIR"] = str(root / "runtime-root")
        environment["XDG_STATE_HOME"] = str(root / "state-root")
        runtime = root / "runtime-root" / "astral-project"
        state_path = root / "state-root" / "astral-project" / "state.sqlite3"
        runtime.mkdir(parents=True, mode=0o700)
        state_path.parent.mkdir(parents=True, mode=0o700)
        state = StateDatabase.open(state_path)
        state.store_signed_grant(
            signed,
            host_key_fingerprint=fingerprint,
            remote_user="testuser",
            host_metadata={"address": "127.0.0.1", "identity_file": str(identity), "port": 22},
            stored_at=now,
            issuer_key=issuer.public_key(),
        )
        daemon = subprocess.Popen(
            ["/usr/bin/aspr", "__internal", "daemon"],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        mountpoint = root / "mount"
        readback_mountpoint = root / "readback-mount"
        mountpoint.mkdir(mode=0o700)
        readback_mountpoint.mkdir(mode=0o700)
        try:
            deadline = time.monotonic() + 15
            while not runtime.joinpath("daemon.sock").exists():
                if daemon.poll() is not None:
                    raise RuntimeError("daemon exited before readiness")
                if time.monotonic() >= deadline:
                    raise RuntimeError("daemon readiness timed out")
                time.sleep(0.05)
            session = _require(
                _run(["session", "open", str(grant.grant_id)], environment), "session open"
            )
            first_result = _run(["mount", "open", str(mountpoint), "/project", "rw"], environment)
            if first_result.returncode != 0:
                daemon_detail = ""
                if daemon.stderr is not None and select.select([daemon.stderr], [], [], 0)[0]:
                    daemon_detail = daemon.stderr.read(65536).decode("utf-8", "replace")
                raise RuntimeError(f"RW mount open failed: {first_result.stderr}{daemon_detail}")
            first_mount = _require(first_result, "RW mount open")
            if first_mount.get("state") != "ready" or not mountpoint.is_mount():
                raise RuntimeError("RW mount did not become ready")
            (mountpoint / filename).write_bytes(payload)
            first_close = _require(
                _run(["mount", "close", str(first_mount["mount_id"])], environment),
                "first mount close",
            )
            if first_close.get("state") != "closed" or mountpoint.is_mount():
                raise RuntimeError(f"first close did not detach cleanly: {first_close}")
            second_result = _run(
                ["mount", "open", str(readback_mountpoint), "/project", "ro"], environment
            )
            if second_result.returncode != 0:
                daemon_detail = ""
                if daemon.stderr is not None and select.select([daemon.stderr], [], [], 0)[0]:
                    daemon_detail = daemon.stderr.read(65536).decode("utf-8", "replace")
                raise RuntimeError(
                    f"independent readback mount open failed: {second_result.stderr}{daemon_detail}"
                )
            second_mount = _require(second_result, "independent readback mount open")
            if second_mount.get("state") != "ready":
                raise RuntimeError("independent readback mount was not ready")
            observed = (readback_mountpoint / filename).read_bytes()
            second_close = _require(
                _run(["mount", "close", str(second_mount["mount_id"])], environment),
                "readback mount close",
            )
            if second_close.get("state") != "closed" or observed != payload:
                raise RuntimeError("RW writeback bytes did not survive daemon close")
            _require(
                _run(["session", "close", str(session["session_id"])], environment), "session close"
            )
            print(
                json.dumps(
                    {
                        "rclone": str(rclone),
                        "grant_id": str(grant.grant_id),
                        "write_bytes": len(payload),
                        "write_sha256": hashlib.sha256(payload).hexdigest(),
                        "read_sha256": hashlib.sha256(observed).hexdigest(),
                        "first_close": first_close.get("state"),
                        "independent_readback": "passed",
                        "expiry_during_write": "not_run",
                        "revocation_during_write": "not_run",
                        "forced_close_unflushed": "covered_by_unit_failure_injection",
                    },
                    sort_keys=True,
                )
            )
        finally:
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait()
            source_root.joinpath(filename).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
