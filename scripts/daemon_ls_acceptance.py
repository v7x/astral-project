#!/usr/bin/env python3
"""Packaged daemon-backed `aspr ls` acceptance against one live grant."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, "/usr/lib/astral-project/python")

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import uuid

from astral_project.core.ids import GrantId, HostId, IssuerKeyId, SessionId
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


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _mtime(path: Path) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(path.stat().st_mtime))


def _expected_entries(source: Path, fixture: Path) -> list[dict[str, object]]:
    entries = [
        {
            "Path": "allowed.txt",
            "Name": "allowed.txt",
            "Size": source.joinpath("allowed.txt").stat().st_size,
            "MimeType": "text/plain; charset=utf-8",
            "ModTime": _mtime(source / "allowed.txt"),
            "IsDir": False,
        },
        {
            "Path": fixture.name,
            "Name": fixture.name,
            "Size": -1,
            "MimeType": "inode/directory",
            "ModTime": _mtime(fixture),
            "IsDir": True,
        },
    ]
    return sorted(entries, key=lambda entry: str(entry["Path"]))


def _expected_table(entries: list[dict[str, object]]) -> bytes:
    lines = ["TYPE  SIZE  MODIFIED                  PATH"]
    for entry in entries:
        is_dir = bool(entry["IsDir"])
        kind = "dir" if is_dir else "file"
        size = "-" if is_dir else f"{entry['Size']} B"
        lines.append(f"{kind:<4}  {size:<4}  {entry['ModTime']:<25} {entry['Path']}")
    return ("\n".join(lines) + "\n").encode()


def _raw_json(entries: list[dict[str, object]]) -> bytes:
    return (
        "[\n" + ",\n".join(json.dumps(entry, separators=(",", ":")) for entry in entries) + "\n]\n"
    ).encode()


def _error_text(reason: str) -> str:
    return (
        f"ASPR_DAEMON_UNAVAILABLE [8003]: daemon rejected request: {reason}\n"
        "Security result: daemon request was not sent\n"
        "Why: trusted daemon control socket is unavailable\n"
        "Fix: start trusted daemon, then retry\n"
    )


def _record(code: int, output: bytes, diagnostics: str) -> dict[str, object]:
    return {
        "exit": code,
        "stdout_b64": base64.b64encode(output).decode("ascii"),
        "stdout_sha256": hashlib.sha256(output).hexdigest(),
        "stderr": diagnostics,
    }


def _call(arguments: list[str], environment: dict[str, str]) -> tuple[int, bytes, str]:
    completed = subprocess.run(
        ["/usr/bin/aspr", *arguments],
        capture_output=True,
        check=False,
        env=environment,
        timeout=60,
    )
    return completed.returncode, completed.stdout, completed.stderr.decode("utf-8", "replace")


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: daemon_ls_acceptance.py RCLONE IDENTITY ISSUER_KEY HOST_ID HOST_FINGERPRINT",
            file=sys.stderr,
        )
        return 64
    rclone, identity, issuer_key = map(Path, sys.argv[1:4])
    host_id_text, fingerprint = sys.argv[4:6]
    if not rclone.is_absolute() or not identity.is_absolute() or not issuer_key.is_absolute():
        print("paths must be absolute", file=sys.stderr)
        return 64
    host_id = HostId(str(host_id_text))
    now = int(time.time())
    source = Path.home() / "astral-gate-source"
    fixture = source / f".aspr-acceptance-{uuid.uuid4().hex}"
    fixture.mkdir()
    (fixture / "nested.txt").write_bytes(b"nested\n")
    deeper = fixture / "deeper"
    deeper.mkdir()
    (deeper / "deep.txt").write_bytes(b"too-deep\n")
    source_stat = source.stat()
    grant = Grant(
        GrantId.new(),
        IssuerKeyId("00000000-0000-4000-8000-000000000001"),
        host_id,
        fingerprint,
        "testuser",
        now,
        now,
        now + 250,
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
    issuer_private_key = load_private_key(issuer_key)
    signed = SignedGrant.create(grant, issuer_private_key)
    signed.verify(
        issuer_private_key.public_key(),
        GrantVerificationContext(host_id, fingerprint, "testuser", now),
    )

    with tempfile.TemporaryDirectory(prefix="aspr-daemon-ls-") as temporary:
        root = Path(temporary)
        environment = os.environ.copy()
        environment["XDG_RUNTIME_DIR"] = str(root / "runtime-root")
        environment["XDG_STATE_HOME"] = str(root / "state-root")
        runtime = root / "runtime-root" / "astral-project"
        runtime.mkdir(parents=True, mode=0o700)
        state_path = root / "state-root" / "astral-project" / "state.sqlite3"
        state_path.parent.mkdir(parents=True, mode=0o700)
        state = StateDatabase.open(state_path)
        session_id = str(SessionId(str(uuid.uuid4())))
        state.activate_session(
            session_id=SessionId(session_id),
            signed_grant=signed,
            host_id=host_id,
            host_key_fingerprint=fingerprint,
            remote_user="testuser",
            host_metadata={"address": "127.0.0.1", "identity_file": str(identity), "port": 22},
            started_at=now,
            issuer_key=issuer_private_key.public_key(),
        )
        active = state.active_listing_session()
        _assert(active is not None, "live session was not recorded")
        _assert(active.session_id == session_id, "session identifier was not preserved")
        _assert(
            active.signed_grant.grant.grant_id == grant.grant_id, "grant binding was not preserved"
        )
        daemon_process = subprocess.Popen(
            ["/usr/bin/aspr", "__internal", "daemon"],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 10
        while not runtime.joinpath("daemon.sock").exists():
            if daemon_process.poll() is not None:
                diagnostic = daemon_process.stderr.read().decode("utf-8", "replace")
                raise RuntimeError(f"installed daemon exited: {diagnostic}")
            if time.monotonic() >= deadline:
                daemon_process.kill()
                raise RuntimeError("installed daemon did not create its socket")
            time.sleep(0.05)
        try:
            target = f"{grant.grant_id}:/project"
            expected = _expected_entries(source, fixture)
            expected_table = _expected_table(expected)
            expected_raw = _raw_json(expected)
            expected_json = (
                json.dumps(
                    {
                        "entries": [
                            {
                                "is_dir": bool(entry["IsDir"]),
                                "mime_type": entry["MimeType"],
                                "modified": entry["ModTime"],
                                "name": entry["Name"],
                                "path": entry["Path"],
                                "size": entry["Size"],
                            }
                            for entry in expected
                        ],
                        "version": 1,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
                + "\n"
            ).encode()
            checks: dict[str, object] = {}
            for name, arguments in (
                ("table", ["ls", target, "--timeout", "30"]),
                ("json", ["ls", target, "--json"]),
                ("raw", ["ls", target, "--raw"]),
                ("recursive", ["ls", target, "--recursive", "--max-depth", "2"]),
            ):
                code, output, diagnostics = _call(arguments, environment)
                _assert(
                    code == 0 and not diagnostics and b"ASPR_" not in output,
                    f"{name} failed: code={code} stderr={diagnostics!r} output={output!r}",
                )
                if name == "table":
                    _assert(output == expected_table, "table output is not exact")
                elif name == "json":
                    _assert(output == expected_json, "normalized JSON output is not exact")
                elif name == "raw":
                    _assert(output == expected_raw, "raw JSON output is not exact")
                else:
                    decoded = output.decode("utf-8")
                    _assert(
                        fixture.name in decoded and f"{fixture.name}/nested.txt" in decoded,
                        "recursive listing omitted nested entry",
                    )
                    _assert(
                        f"{fixture.name}/deeper/deep.txt" not in decoded,
                        "recursive depth exceeded max-depth 2",
                    )
                    _assert(
                        decoded.count("nested.txt") == 1, "recursive depth emitted duplicate entry"
                    )
                checks[name] = _record(code, output, diagnostics)
            code, output, diagnostics = _call(["ls", target, "--timeout", "0.001"], environment)
            _assert(
                code == 70
                and not output
                and diagnostics == _error_text("rclone listing timed out"),
                "timeout control did not fail closed exactly",
            )
            checks["timeout"] = _record(code, output, diagnostics)
            code, output, diagnostics = _call(["ls", target, "--timeout", "30"], environment)
            _assert(
                code == 0 and output == expected_table and not diagnostics, "timeout cleanup failed"
            )
            checks["after_timeout"] = _record(code, output, diagnostics)
            for name, bad_target, reason in (
                (
                    "alternate_grant",
                    "other-grant:/project",
                    "listing target selects another grant or host",
                ),
                (
                    "traversal",
                    f"{grant.grant_id}:/project/../secret",
                    "listing target contains traversal",
                ),
                (
                    "ungranted",
                    f"{grant.grant_id}:/hidden",
                    "listing target is outside bound export",
                ),
            ):
                code, output, diagnostics = _call(["ls", bad_target], environment)
                _assert(
                    code == 70 and not output and diagnostics == _error_text(reason),
                    f"negative control failed exactly: {name}",
                )
                checks[name] = _record(code, output, diagnostics)
            print(
                json.dumps(
                    {
                        "checks": checks,
                        "grant_id": str(grant.grant_id),
                        "session_id": session_id,
                        "grant_signature_verified": True,
                        "state_active_verified": True,
                        "rclone": str(rclone),
                        "session_state": "active",
                        "version": 1,
                    },
                    sort_keys=True,
                )
            )
            return 0
        finally:
            if daemon_process.poll() is None:
                daemon_process.terminate()
                try:
                    daemon_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon_process.kill()
                    daemon_process.wait()
            shutil.rmtree(fixture, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
