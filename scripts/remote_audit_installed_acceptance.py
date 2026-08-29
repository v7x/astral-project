#!/usr/bin/env python3
"""Installed real-kernel remote audit export acceptance."""

from __future__ import annotations

import json
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import mkdtemp

from astral_project.audit import AuditLog
from astral_project.core.ids import HostId
from astral_project.server.entry import (
    SSH_ORIGINAL_AUDIT_COMMAND,
    ServerTrust,
    run_audit_export_entry,
)


def main() -> int:
    root = Path(mkdtemp(dir=Path.home(), prefix=".aspr-remote-audit-"))
    root.chmod(0o700)
    log = AuditLog(root / "remote.log", retention=2)
    log.append("probe.started", "process", "probe", {"path": "/secret"})
    failure = AuditLog(root / "failure.log")
    failure.append("probe.started", "process", "probe", {})
    recorder = failure.prepare_failure_recorder()
    trust = ServerTrust(
        HostId("00000000-0000-4000-8000-000000000002"),
        "SHA256:test",
        "remote",
        {},
        frozenset({"transport"}),
    )
    output = BytesIO()
    error = StringIO()
    abuse_log = AuditLog(root / "command-abuse.log")
    command_abuse_output = BytesIO()
    command_abuse = run_audit_export_entry(
        "transport",
        stdin=BytesIO(b"{}"),
        stdout=command_abuse_output,
        stderr=StringIO(),
        environment={"SSH_ORIGINAL_COMMAND": "sh -c id"},
        trust=trust,
        audit_log=abuse_log,
    )
    result = run_audit_export_entry(
        "transport",
        stdin=BytesIO(json.dumps({"version": 1, "path_mode": "redact"}).encode()),
        stdout=output,
        stderr=error,
        environment={"SSH_ORIGINAL_COMMAND": SSH_ORIGINAL_AUDIT_COMMAND},
        trust=trust,
        audit_log=log,
    )
    recorder.append("hardening.failure", "process", "remote-audit", {"error_code": "probe"})
    recorder.close()
    response = json.loads(output.getvalue())
    exported = response["export"]
    exported_events = [json.loads(line) for line in exported.splitlines()]
    assert command_abuse == 70
    assert result == 0 and response["ok"] is True
    path_event = next(
        event for event in exported_events if event["payload"].get("path") == "<redacted>"
    )
    assert log.chain_errors() == ()
    assert [event.kind for event in failure.read()] == ["probe.started", "hardening.failure"]
    print(
        json.dumps(
            {
                "chain_errors": list(log.chain_errors()),
                "command_abuse": {"result": "denied" if command_abuse == 70 else "succeeded"},
                "export_ok": response["ok"],
                "exported_path": path_event["payload"]["path"],
                "exported_records": [
                    {
                        "event_id": event["event_id"],
                        "kind": event["kind"],
                        "payload": event["payload"],
                        "previous_event_id": event["previous_event_id"],
                    }
                    for event in exported_events
                ],
                "failure_order": [event.kind for event in failure.read()],
                "retained_remote_events": [event.kind for event in log.read()],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
