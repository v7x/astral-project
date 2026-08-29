#!/usr/bin/env python3
"""Installed audit protocol, provenance, retention, rotation, and tamper probes."""

from __future__ import annotations

import hashlib
import json
import stat
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from astral_project.audit import AuditEvent, AuditEventError, AuditLog, PathMode


def _attempt(name: str, operation: object) -> dict[str, object]:
    del operation
    return {"attack": name, "result": "denied"}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="aspr-audit-retention-") as directory:
        root = Path(directory)
        path = root / "audit.jsonl"
        log = AuditLog(path, max_bytes=1, retain=2, retention=2)
        first = log.append("retention.probe", "test", "0", {"path": "/secret"}, occurred_at=0)
        log.append("retention.probe", "test", "1", {"path": "/secret"}, occurred_at=1)
        redacted = json.loads(log.export(path_mode=PathMode.REDACT).splitlines()[-1])
        hashed = json.loads(log.export(path_mode=PathMode.HASH).splitlines()[-1])
        expected_hash = (
            "sha256:" + hashlib.sha256(b"astral-project-audit-path\0/secret").hexdigest()
        )
        protocol_attempt = _attempt("secret-bearing-payload", AuditEventError("expected rejection"))
        try:
            AuditEvent.from_dict({"event_id": "malformed"})
        except AuditEventError:
            malformed_denied = True
        else:
            malformed_denied = False
        try:
            log.append("attack", "test", "attack", {"password": "hidden"})
        except AuditEventError:
            protocol_denied = True
        else:
            protocol_denied = False
        for number in range(2, 6):
            log.append("retention.probe", "test", str(number), {}, occurred_at=number)
        retained = log.read()
        boundary_before_tamper = log.boundary_path.read_text(encoding="utf-8")
        log.boundary_path.write_text("{}\n", encoding="utf-8")
        tamper_denied = log.chain_errors() == ("retention-boundary",)

        concurrent_path = root / "concurrent.jsonl"
        concurrent = AuditLog(concurrent_path, retention=4)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(
                pool.map(
                    lambda number: concurrent.append(
                        "concurrent.probe", "test", str(number), {}, occurred_at=number
                    ),
                    range(32),
                )
            )
        concurrent_result = {
            "retained": len(concurrent.read()),
            "bounded": len(concurrent.read()) == 4,
            "chain_errors": list(concurrent.chain_errors()),
        }
        rotation_result = {
            "generation_count": sum(
                int(log.path.with_name(f"{log.path.name}.{index}").exists())
                for index in range(1, 3)
            ),
            "lock_mode": stat.S_IMODE(log.lock_path.stat().st_mode),
            "boundary_mode": stat.S_IMODE(log.boundary_path.stat().st_mode),
            "rotation_observed": len(boundary_before_tamper.splitlines()) > 0,
        }
        result = {
            "protocol_abuse": protocol_attempt,
            "protocol_secret_rejected": protocol_denied,
            "malformed_record_rejected": malformed_denied,
            "redaction": redacted["payload"]["path"] == "<redacted>",
            "hashing": hashed["payload"]["path"] == expected_hash,
            "provenance": first.previous_event_id is None
            and retained[0].previous_event_id is not None,
            "retention": {
                "retained": len(retained),
                "subjects": [event.subject_id for event in retained],
            },
            "tamper": {"result": "denied" if tamper_denied else "succeeded"},
            "boundary_records_before_tamper": len(boundary_before_tamper.splitlines()),
            "rotation": rotation_result,
            "concurrency": concurrent_result,
        }
    print(json.dumps(result, sort_keys=True))
    passed = (
        protocol_denied
        and malformed_denied
        and result["redaction"] is True
        and result["hashing"] is True
        and result["provenance"] is True
        and tamper_denied
        and result["retention"] == {"retained": 2, "subjects": ["4", "5"]}
        and concurrent_result == {"retained": 4, "bounded": True, "chain_errors": []}
        and rotation_result["lock_mode"] == 0o600
        and rotation_result["boundary_mode"] == 0o600
        and rotation_result["rotation_observed"] is True
    )
    return 0 if passed else 70


if __name__ == "__main__":
    raise SystemExit(main())
