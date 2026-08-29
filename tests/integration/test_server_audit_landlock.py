"""Real-kernel regression coverage for the read-only remote audit wall."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from astral_project.audit import AuditLog
from astral_project.sandbox.hardening import detect_landlock

_REMOTE_EXPORT_PROBE = r"""
import json
import sys
from io import BytesIO, StringIO
from pathlib import Path
from astral_project.audit import AuditLog
from astral_project.core.ids import HostId
from astral_project.server.entry import (
    SSH_ORIGINAL_AUDIT_COMMAND,
    ServerTrust,
    run_audit_export_entry,
)

log = AuditLog(Path(sys.argv[1]), retention=1)
failure_log = AuditLog(Path(sys.argv[1]).with_name("failure.log"))
failure_log.append("probe.started", "process", "probe", {})
failure_recorder = failure_log.prepare_failure_recorder()
trust = ServerTrust(
    HostId("00000000-0000-4000-8000-000000000002"),
    "SHA256:test",
    "remote",
    {},
    frozenset({"transport"}),
)
stdout = BytesIO()
stderr = StringIO()
return_code = run_audit_export_entry(
    "transport",
    stdin=BytesIO(b'{"version":1,"path_mode":"redact"}'),
    stdout=stdout,
    stderr=stderr,
    environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_AUDIT_COMMAND},
    trust=trust,
    audit_log=log,
)
failure_recorder.append("hardening.failure", "process", "remote-audit", {"error_code": "probe"})
failure_recorder.close()
print(json.dumps({
    "return_code": return_code,
    "response": json.loads(stdout.getvalue()),
    "stderr": stderr.getvalue(),
    "failure_kinds": [event.kind for event in failure_log.read()],
}))
"""


@pytest.mark.skipif(sys.platform != "linux", reason="Landlock is Linux-only")
def test_remote_audit_export_survives_real_read_only_landlock_wall() -> None:
    try:
        abi = detect_landlock()
    except OSError as error:
        pytest.skip(f"Landlock probe unavailable: {error}")
    if abi is None or abi < 3:
        pytest.skip(f"Landlock ABI {abi!r} is below the required ABI")

    # /tmp is intentionally writable in the fixed policy; use the projected-home
    # class of root that the remote server actually hardens read-only.
    with tempfile.TemporaryDirectory(dir=Path.home(), prefix=".aspr-audit-landlock-") as root_name:
        root = Path(root_name)
        root.chmod(0o700)
        log_path = root / "remote.log"
        environment = os.environ.copy()
        source_root = str(Path(__file__).parents[2] / "src")
        environment["PYTHONPATH"] = source_root + os.pathsep + environment.get("PYTHONPATH", "")
        completed = subprocess.run(
            [sys.executable, "-c", _REMOTE_EXPORT_PROBE, str(log_path)],
            capture_output=True,
            check=True,
            env=environment,
            text=True,
            timeout=30,
        )

        probe = json.loads(completed.stdout)
        assert probe["return_code"] == 0
        assert probe["response"]["ok"] is True
        assert "audit.remote.export.started" in probe["response"]["export"]
        assert probe["stderr"] == ""
        assert probe["failure_kinds"] == ["probe.started", "hardening.failure"]
        assert AuditLog(log_path).chain_errors() == ()
        assert [event.kind for event in AuditLog(log_path).read()] == [
            "audit.remote.export.completed",
        ]
