#!/usr/bin/env python3
"""Installed RW mount writeback acceptance through the real daemon close path."""

from __future__ import annotations

import dataclasses
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


def _mount_record(payload: dict[str, object], mount_id: object) -> dict[str, object]:
    mounts = payload.get("mounts")
    if not isinstance(mounts, list):
        raise RuntimeError("mount list returned no mounts")
    for item in mounts:
        if isinstance(item, dict) and item.get("mount_id") == mount_id:
            return item
    raise RuntimeError(f"mount {mount_id} was not returned by lifecycle refresh")


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
    if not rclone.is_file() or not os.access(rclone, os.X_OK):
        raise RuntimeError(f"rclone binary is not executable: {rclone}")
    version_result = subprocess.run(
        [str(rclone), "version"], capture_output=True, text=True, check=False, timeout=10
    )
    if version_result.returncode != 0:
        raise RuntimeError(f"rclone version failed: {version_result.stderr}")
    rclone_version = version_result.stdout.splitlines()[0] if version_result.stdout else "unknown"
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
        environment["PYTHONPATH"] = "/usr/lib/astral-project/python"
        environment["ASPR_ACCEPTANCE_RCLONE"] = str(rclone)
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
        daemon_code = (
            "import os; from pathlib import Path; "
            "from astral_project.daemon.server import DaemonPaths, DaemonServer; "
            "paths=DaemonPaths(Path(os.environ['XDG_RUNTIME_DIR']) / 'astral-project', "
            "Path(os.environ['XDG_STATE_HOME']) / 'astral-project' / 'state.sqlite3'); "
            "daemon=DaemonServer(paths, rclone_binary=Path(os.environ['ASPR_ACCEPTANCE_RCLONE'])); "
            "daemon.start(); daemon.serve_forever()"
        )
        daemon = subprocess.Popen(
            [sys.executable, "-c", daemon_code],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        mountpoint = root / "mount"
        readback_mountpoint = root / "readback-mount"
        mountpoint.mkdir(mode=0o700)
        readback_mountpoint.mkdir(mode=0o700)
        scenario_files: list[Path] = []
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

            def scenario_mount(
                scenario_grant: SignedGrant, label: str
            ) -> tuple[dict[str, object], dict[str, object], Path]:
                state.store_signed_grant(
                    scenario_grant,
                    host_key_fingerprint=fingerprint,
                    remote_user="testuser",
                    host_metadata={
                        "address": "127.0.0.1",
                        "identity_file": str(identity),
                        "port": 22,
                    },
                    stored_at=int(time.time()),
                    issuer_key=issuer.public_key(),
                )
                scenario_session = _require(
                    _run(["session", "open", str(scenario_grant.grant.grant_id)], environment),
                    f"{label} session open",
                )
                scenario_mountpoint = root / f"{label}-mount"
                scenario_mountpoint.mkdir(mode=0o700)
                opened_scenario = _require(
                    _run(
                        ["mount", "open", str(scenario_mountpoint), "/project", "rw"], environment
                    ),
                    f"{label} mount open",
                )
                if opened_scenario.get("state") != "ready" or not scenario_mountpoint.is_mount():
                    raise RuntimeError(f"{label} mount did not become ready")
                return scenario_session, opened_scenario, scenario_mountpoint

            expiry_grant = dataclasses.replace(
                grant,
                grant_id=GrantId.new(),
                issued_at=now,
                not_before=now,
                expires_at=now + 20,
            )
            expiry_signed = SignedGrant.create(expiry_grant, issuer)
            expiry_session, expiry_mount, expiry_mountpoint = scenario_mount(
                expiry_signed, "expiry"
            )
            expiry_file = source_root / f"expiry-{uuid.uuid4().hex}.bin"
            scenario_files.append(expiry_file)
            (expiry_mountpoint / expiry_file.name).write_bytes(b"expiry-during-write\\n")
            time.sleep(21)
            expiry_list = _require(_run(["mount", "list"], environment), "expiry lifecycle refresh")
            expiry_record = _mount_record(expiry_list, expiry_mount["mount_id"])
            expiry_session_close = _run(
                ["session", "close", str(expiry_session["session_id"])], environment
            )
            if expiry_session_close.returncode == 0:
                expiry_session_state = "closed"
            elif "active session was not found" in expiry_session_close.stderr:
                expiry_session_state = "retired"
            else:
                raise RuntimeError(f"expiry session close failed: {expiry_session_close.stderr}")
            expiry_outcome = {
                "state": expiry_record.get("state"),
                "mount_detached": not expiry_mountpoint.is_mount(),
                "session": expiry_session_state,
            }

            revoke_grant = dataclasses.replace(
                grant,
                grant_id=GrantId.new(),
                issued_at=now,
                not_before=now,
                expires_at=now + 250,
            )
            revoke_signed = SignedGrant.create(revoke_grant, issuer)
            revoke_session, revoke_mount, revoke_mountpoint = scenario_mount(
                revoke_signed, "revocation"
            )
            revoke_file = source_root / f"revocation-{uuid.uuid4().hex}.bin"
            scenario_files.append(revoke_file)
            (revoke_mountpoint / revoke_file.name).write_bytes(b"revocation-during-write\\n")
            _require(
                _run(
                    ["grant", "revoke", str(revoke_grant.grant_id), "--reason", "acceptance"],
                    environment,
                ),
                "grant revoke",
            )
            revoke_list = _require(
                _run(["mount", "list"], environment), "revocation lifecycle refresh"
            )
            revoke_record = _mount_record(revoke_list, revoke_mount["mount_id"])
            revoke_session_close = _run(
                ["session", "close", str(revoke_session["session_id"])], environment
            )
            if revoke_session_close.returncode == 0:
                revoke_session_state = "closed"
            elif "active session was not found" in revoke_session_close.stderr:
                revoke_session_state = "retired"
            else:
                raise RuntimeError(
                    f"revocation session close failed: {revoke_session_close.stderr}"
                )
            revoke_outcome = {
                "state": revoke_record.get("state"),
                "mount_detached": not revoke_mountpoint.is_mount(),
                "session": revoke_session_state,
            }

            forced_grant = dataclasses.replace(
                grant,
                grant_id=GrantId.new(),
                issued_at=now,
                not_before=now,
                expires_at=now + 250,
            )
            forced_signed = SignedGrant.create(forced_grant, issuer)
            forced_session, forced_mount, forced_mountpoint = scenario_mount(
                forced_signed, "forced-close"
            )
            forced_file = source_root / f"forced-{uuid.uuid4().hex}.bin"
            scenario_files.append(forced_file)
            (forced_mountpoint / forced_file.name).write_bytes(b"forced-close\\n")
            forced_close = _require(
                _run(["mount", "close", str(forced_mount["mount_id"])], environment),
                "forced close",
            )
            _require(
                _run(["session", "close", str(forced_session["session_id"])], environment),
                "forced session close",
            )
            forced_outcome = {
                "state": forced_close.get("state"),
                "mount_detached": not forced_mountpoint.is_mount(),
            }
            print(
                json.dumps(
                    {
                        "rclone": str(rclone.resolve()),
                        "rclone_version": rclone_version,
                        "grant_id": str(grant.grant_id),
                        "write_bytes": len(payload),
                        "write_sha256": hashlib.sha256(payload).hexdigest(),
                        "read_sha256": hashlib.sha256(observed).hexdigest(),
                        "first_close": first_close.get("state"),
                        "independent_readback": "passed",
                        "expiry_during_write": expiry_outcome,
                        "revocation_during_write": revoke_outcome,
                        "forced_close": forced_outcome,
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
            for scenario_file in scenario_files:
                scenario_file.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
