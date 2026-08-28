#!/usr/bin/env python3
"""Run the bounded JSONL audit retention acceptance probe."""

from __future__ import annotations

import stat
import tempfile
from pathlib import Path

from astral_project.audit import AuditLog


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="aspr-audit-retention-") as directory:
        path = Path(directory) / "audit.jsonl"
        log = AuditLog(path, max_bytes=1, retain=5, retention=2)
        for number in range(6):
            log.append("retention.probe", "test", str(number), {}, occurred_at=number)
        events = log.read()
        result = {
            "retained": len(events),
            "subjects": [event.subject_id for event in events],
            "chain_errors": list(log.chain_errors()),
            "lock_mode": stat.S_IMODE(log.lock_path.stat().st_mode),
            "boundary_mode": stat.S_IMODE(log.boundary_path.stat().st_mode),
            "boundary_records": len(log.boundary_path.read_text(encoding="utf-8").splitlines()),
        }
        print(result)
        if result != {
            "retained": 2,
            "subjects": ["4", "5"],
            "chain_errors": [],
            "lock_mode": 0o600,
            "boundary_mode": 0o600,
            "boundary_records": 4,
        }:
            return 1
    print("PASS audit retention byte-and-count probe")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
