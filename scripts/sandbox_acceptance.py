#!/usr/bin/env python3
"""Installed Packet 23-24 sandbox acceptance on one certified VM."""

from __future__ import annotations

import json
import os
import shutil
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
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode
from astral_project.state.sqlite import StateDatabase


def _run(
    args: list[str], env: dict[str, str], timeout: float = 60
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )


def _native_negative_controls() -> None:
    invalid = subprocess.run(
        ["/usr/libexec/astral-project/aspr-bwrap-launch"],
        input=b"BADPLAN!",
        capture_output=True,
        check=False,
    )
    if invalid.returncode != 70 or b"magic or version" not in invalid.stderr:
        raise RuntimeError(f"invalid typed plan was not rejected: {invalid.stderr!r}")
    valid_plan = LocalSandboxPlan(("/bin/true",), NetworkMode.INHERIT).plan_bytes()
    trailing = subprocess.run(
        ["/usr/libexec/astral-project/aspr-bwrap-launch"],
        input=valid_plan + b"x",
        capture_output=True,
        check=False,
    )
    if trailing.returncode != 70 or b"trailing bytes" not in trailing.stderr:
        raise RuntimeError(f"trailing typed-plan bytes were not rejected: {trailing.stderr!r}")
    relative_plan = LocalSandboxPlan(("relative",), NetworkMode.INHERIT).plan_bytes()
    relative = subprocess.run(
        ["/usr/libexec/astral-project/aspr-bwrap-launch"],
        input=relative_plan,
        capture_output=True,
        check=False,
    )
    if relative.returncode != 70 or b"not absolute" not in relative.stderr:
        raise RuntimeError(f"relative payload was not rejected: {relative.stderr!r}")
    direct = subprocess.run(
        ["/usr/libexec/astral-project/aspr-sandbox-entry", "/bin/true"],
        capture_output=True,
        check=False,
    )
    if direct.returncode != 70 or b"setup profile" not in direct.stderr:
        raise RuntimeError(f"direct entrypoint escape was not rejected: {direct.stderr!r}")


def _mounts(env: dict[str, str]) -> list[dict[str, object]]:
    result = _run(["/usr/bin/aspr", "mount", "list"], env)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    payload = json.loads(result.stdout)
    return [item for item in payload["mounts"] if isinstance(item, dict)]


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: sandbox_acceptance.py RCLONE IDENTITY ISSUER_KEY HOST_ID HOST_FINGERPRINT",
            file=sys.stderr,
        )
        return 64
    _rclone, identity_text, issuer_text, host_id_text, fingerprint = sys.argv[1:]
    _native_negative_controls()
    identity = Path(identity_text)
    issuer = load_private_key(Path(issuer_text))
    now = int(time.time())
    source_root = Path.home() / "astral-gate-source"
    second_root = Path.home() / "astral-gate-source-2"
    source_root.mkdir(mode=0o700, exist_ok=True)
    second_root.mkdir(mode=0o700, exist_ok=True)
    filename = f"astral-sandbox-{uuid.uuid4().hex}.txt"
    second_filename = f"astral-sandbox-second-{uuid.uuid4().hex}.txt"
    source = source_root / filename
    second_source = second_root / second_filename
    descendant_one = source_root / "descendant-one"
    descendant_two = source_root / "descendant-two"
    descendant_one.mkdir(mode=0o700, exist_ok=True)
    descendant_two.mkdir(mode=0o700, exist_ok=True)
    descendant_one_file = descendant_one / "one.txt"
    descendant_two_file = descendant_two / "two.txt"
    source.write_text("sandbox-visible\n", encoding="utf-8")
    second_source.write_text("sandbox-visible-second\n", encoding="utf-8")
    descendant_one_file.write_text("descendant-one\n", encoding="utf-8")
    descendant_two_file.write_text("descendant-two\n", encoding="utf-8")
    directory = source_root
    stat = directory.stat()
    host_id = HostId(host_id_text)
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
                str(directory),
                str(directory),
                "/project",
                AccessMode.READ_ONLY,
                ExportKind.DIRECTORY,
                SourceIdentity(stat.st_dev, stat.st_ino, "ext4", ExportKind.DIRECTORY),
            ),
        ),
    )
    signed = SignedGrant.create(grant, issuer)
    with tempfile.TemporaryDirectory(prefix="sa-") as temporary:
        root = Path(temporary)
        env = os.environ.copy()
        env["XDG_RUNTIME_DIR"] = str(root / "runtime-root")
        env["XDG_STATE_HOME"] = str(root / "state-root")
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
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            deadline = time.monotonic() + 10
            while not runtime.joinpath("daemon.sock").exists():
                if daemon.poll() is not None:
                    raise RuntimeError("installed daemon exited before socket readiness")
                if time.monotonic() >= deadline:
                    raise RuntimeError("installed daemon socket readiness timed out")
                time.sleep(0.05)
            opened = _run(["/usr/bin/aspr", "session", "open", str(grant.grant_id)], env)
            if opened.returncode != 0:
                raise RuntimeError(opened.stderr)
            session_id = json.loads(opened.stdout)["session_id"]
            manual_path = root / "manual-mount"
            manual_path.mkdir(mode=0o700)
            manual = _run(
                ["/usr/bin/aspr", "mount", "open", str(manual_path), "/project", "ro"], env
            )
            if manual.returncode != 0:
                daemon.terminate()
                daemon_stdout, daemon_stderr = daemon.communicate(timeout=5)
                raise RuntimeError(
                    f"manual mount preflight failed: {manual.stderr}"
                    f" daemon={daemon_stdout.decode('utf-8', 'replace')}"
                    f"{daemon_stderr.decode('utf-8', 'replace')}"
                )
            manual_id = json.loads(manual.stdout)["mount_id"]
            manual_close = _run(["/usr/bin/aspr", "mount", "close", manual_id], env)
            if manual_close.returncode != 0:
                raise RuntimeError(f"manual mount close failed: {manual_close.stderr}")
            negative_remotes = {
                "ancestor": f"{grant.grant_id}:{directory.parent}=/bad:ro",
                "sibling": f"{grant.grant_id}:{second_root}=/bad:ro",
                "traversal": f"{grant.grant_id}:{directory}/descendant-one/../=/bad:ro",
            }
            negative_results: dict[str, str] = {}
            for label, negative_remote in negative_remotes.items():
                rejected = _run(
                    [
                        "/usr/bin/aspr",
                        "sandbox",
                        "--network",
                        "none",
                        "--grant",
                        str(grant.grant_id),
                        "--remote",
                        negative_remote,
                        "--",
                        "/bin/true",
                    ],
                    env,
                )
                if rejected.returncode == 0:
                    raise RuntimeError(f"sandbox {label} authority request was accepted")
                negative_results[label] = "rejected"
            remote = f"{grant.grant_id}:{directory}=/remote:ro"
            second_remote = f"{grant.grant_id}:{descendant_two}=/other:ro"
            positive = _run(
                [
                    "/usr/bin/aspr",
                    "sandbox",
                    "--network",
                    "none",
                    "--grant",
                    str(grant.grant_id),
                    "--remote",
                    remote,
                    "--remote",
                    second_remote,
                    "--",
                    "/bin/sh",
                    "-c",
                    (
                        f"test -f /remote/{filename} && test -f /other/two.txt "
                        '&& test "$ASPR_SESSION_SOCKET" = /run/astral-project/session.sock '
                        '&& test -n "$ASPR_SESSION_ID" '
                        f"&& ( /usr/bin/aspr ls /project --json > /tmp/session-ls.json "
                        f"|| {{ stat -c '%a %u %g %F' /run/astral-project/session.sock >&2; "
                        f"ls -ld /run/astral-project >&2; id >&2; exit 1; }} ) "
                        f"&& grep -q {filename} /tmp/session-ls.json "
                        "&& ! /usr/bin/aspr ls other:/project "
                        "&& ! /usr/bin/aspr grant list "
                        "&& test ! -e /dev/fuse "
                        "&& test ! -e /root/.ssh && test ! -e /run/astral-project/daemon.sock "
                        "&& grep -q aspr-sandbox-payload /proc/self/attr/current "
                        "&& grep -q 'CapEff:[[:space:]]*0000000000000000' /proc/self/status "
                        "&& grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status "
                        '&& test "$(cat /proc/net/route | tail -n +2 | wc -l)" -eq 0'
                    ),
                ],
                env,
                timeout=90,
            )
            if positive.returncode != 0:
                daemon_output = ""
                if daemon.poll() is not None:
                    daemon_output = (
                        daemon.stderr.read().decode("utf-8", "replace") if daemon.stderr else ""
                    )
                raise RuntimeError(f"sandbox positive failed: {positive.stderr}{daemon_output}")
            descendant = _run(
                [
                    "/usr/bin/aspr",
                    "sandbox",
                    "--network",
                    "none",
                    "--grant",
                    str(grant.grant_id),
                    "--remote",
                    f"{grant.grant_id}:{descendant_one}=/one:ro",
                    "--remote",
                    f"{grant.grant_id}:{descendant_two}=/two:ro",
                    "--",
                    "/bin/sh",
                    "-c",
                    f"test -f /one/one.txt && test -f /two/two.txt "
                    f"&& test ! -e /one/{filename} && test ! -e /one/two.txt "
                    f"&& test ! -e /two/{filename} && test ! -e /two/one.txt",
                ],
                env,
                timeout=90,
            )
            if descendant.returncode != 0:
                raise RuntimeError(f"sandbox descendant selection failed: {descendant.stderr}")
            child = subprocess.Popen(
                [
                    "/usr/bin/aspr",
                    "sandbox",
                    "--network",
                    "none",
                    "--grant",
                    str(grant.grant_id),
                    "--remote",
                    remote,
                    "--remote",
                    second_remote,
                    "--",
                    "/bin/sh",
                    "-c",
                    "sleep 30",
                ],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            lost_mount: str | None = None
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline and child.poll() is None:
                for item in _mounts(env):
                    if item.get("state") == "ready" and item.get("session_id") == session_id:
                        candidate = item.get("mount_id")
                        if isinstance(candidate, str):
                            lost_mount = candidate
                            break
                if lost_mount is not None:
                    break
                time.sleep(0.1)
            if lost_mount is None:
                child.kill()
                raise RuntimeError("sandbox mount did not become ready for loss test")
            closed = _run(["/usr/bin/aspr", "mount", "close", lost_mount], env)
            if closed.returncode != 0:
                raise RuntimeError(closed.stderr)
            child.wait(timeout=20)
            if child.returncode == 0:
                raise RuntimeError("remote-loss sandbox exited cleanly")
            session_closed = _run(["/usr/bin/aspr", "session", "close", session_id], env)
            if session_closed.returncode != 0:
                raise RuntimeError(f"session close failed: {session_closed.stderr}")
            shorthand_opened = _run(["/usr/bin/aspr", "session", "open", str(grant.grant_id)], env)
            if shorthand_opened.returncode != 0:
                raise RuntimeError(f"shorthand session open failed: {shorthand_opened.stderr}")
            shorthand_session_id = json.loads(shorthand_opened.stdout)["session_id"]
            shorthand = _run(
                [
                    "/usr/bin/aspr",
                    "sandbox",
                    "--network",
                    "none",
                    "--grant",
                    str(grant.grant_id),
                    "--",
                    "/bin/sh",
                    "-c",
                    f"test -f /workspace/remote/{filename}",
                ],
                env,
                timeout=90,
            )
            if shorthand.returncode != 0:
                raise RuntimeError(f"grant shorthand failed: {shorthand.stderr}")
            shorthand_closed = _run(
                ["/usr/bin/aspr", "session", "close", shorthand_session_id], env
            )
            if shorthand_closed.returncode != 0:
                raise RuntimeError(f"shorthand session close failed: {shorthand_closed.stderr}")
            print(
                json.dumps(
                    {
                        "target": os.environ.get("ASPR_ACCEPTANCE_TARGET", "unknown"),
                        "package": "installed",
                        "session_id": session_id,
                        "sandbox_positive": "passed",
                        "remote_loss": "terminated",
                        "network_none": "passed",
                        "hidden_fuse_and_daemon_socket": "passed",
                        "negative_source_authority": negative_results,
                        "descendant_scope_isolated": "passed",
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
            source.unlink(missing_ok=True)
            second_source.unlink(missing_ok=True)
            descendant_one_file.unlink(missing_ok=True)
            descendant_two_file.unlink(missing_ok=True)
            shutil.rmtree(descendant_one, ignore_errors=True)
            shutil.rmtree(descendant_two, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
