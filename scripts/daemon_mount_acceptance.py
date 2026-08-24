#!/usr/bin/env python3
"""Packaged daemon-backed mount lifecycle acceptance."""

from __future__ import annotations

import json
import os
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
    GrantVerificationContext,
    SignedGrant,
    SourceIdentity,
)
from astral_project.crypto.keys import load_private_key
from astral_project.state.sqlite import StateDatabase


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: daemon_mount_acceptance.py RCLONE IDENTITY ISSUER_KEY HOST_ID HOST_FINGERPRINT",
            file=sys.stderr,
        )
        return 64
    rclone_text, identity_text, issuer_key_text, host_id_text, fingerprint = sys.argv[1:]
    _rclone, identity, issuer_key = map(Path, (rclone_text, identity_text, issuer_key_text))
    host_id = HostId(str(host_id_text))
    now = int(time.time())
    source_root = Path.home() / "astral-gate-source"
    source_root.mkdir(mode=0o700, exist_ok=True)
    source = source_root
    filename = f"astral-mount-{uuid.uuid4().hex}.txt"
    (source / filename).write_text("allowed\n", encoding="utf-8")
    source_stat = source.stat()
    grant = Grant(
        GrantId.new(),
        IssuerKeyId("00000000-0000-4000-8000-000000000001"),
        host_id,
        fingerprint,
        "testuser",
        now,
        now,
        now + 300,
        os.urandom(32),
        (
            GrantExport(
                str(source),
                str(source),
                "/project",
                AccessMode.READ_ONLY,
                ExportKind.DIRECTORY,
                SourceIdentity(
                    source_stat.st_dev, source_stat.st_ino, "ext4", ExportKind.DIRECTORY
                ),
            ),
        ),
    )
    signed = SignedGrant.create(grant, load_private_key(issuer_key))
    signed.verify(
        load_private_key(issuer_key).public_key(),
        GrantVerificationContext(host_id, fingerprint, "testuser", now),
    )
    with tempfile.TemporaryDirectory(prefix="aspr-mount-acceptance-") as temporary:
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
            issuer_key=load_private_key(issuer_key).public_key(),
        )
        daemon = subprocess.Popen(
            ["/usr/bin/aspr", "__internal", "daemon"],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        mountpoint = root / "mount"
        mountpoint.mkdir(mode=0o700)
        try:
            deadline = time.monotonic() + 10
            while not runtime.joinpath("daemon.sock").exists():
                if daemon.poll() is not None:
                    raise RuntimeError("installed daemon exited before socket readiness")
                if time.monotonic() >= deadline:
                    raise RuntimeError("installed daemon socket readiness timed out")
                time.sleep(0.05)
            session_opened = subprocess.run(
                ["/usr/bin/aspr", "session", "open", str(grant.grant_id)],
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if session_opened.returncode != 0:
                raise RuntimeError(session_opened.stderr)
            session_id = json.loads(session_opened.stdout)["session_id"]
            opened = subprocess.run(
                ["/usr/bin/aspr", "mount", "open", str(mountpoint), "/project", "ro"],
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if opened.returncode != 0:
                daemon.terminate()
                daemon_output = daemon.communicate(timeout=5)[1].decode("utf-8", "replace")
                raise RuntimeError(opened.stderr + daemon_output)
            mount = json.loads(opened.stdout)
            if mount["state"] != "ready" or not mountpoint.is_mount():
                raise RuntimeError("mount did not reach ready state")
            if (mountpoint / filename).read_text(encoding="utf-8") != "allowed\n":
                raise RuntimeError("mounted read returned unexpected content")
            closed = subprocess.run(
                ["/usr/bin/aspr", "mount", "close", mount["mount_id"]],
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            if closed.returncode != 0 or json.loads(closed.stdout)["state"] != "closed":
                raise RuntimeError(f"mount close failed: {closed.stderr}")
            print(
                json.dumps(
                    {
                        "grant_id": str(grant.grant_id),
                        "session_id": session_id,
                        "mount_id": mount["mount_id"],
                        "opened": "ready",
                        "closed": "closed",
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
            (source / filename).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
