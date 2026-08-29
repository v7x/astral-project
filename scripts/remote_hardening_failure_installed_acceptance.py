#!/usr/bin/env python3
"""Installed production remote hardening-failure ordering acceptance."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import mkdtemp

from astral_project.audit import AuditLog
from astral_project.sandbox import hardening
from astral_project.sandbox.hardening import HardeningError, HardeningPolicy, RootRole
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode
from astral_project.sandbox.runner import run_plan


def main() -> int:
    root = Path(mkdtemp(prefix="aspr-hardening-failure-"))
    root.chmod(0o700)
    log = AuditLog(root / "failure.jsonl")
    original_probe = hardening.detect_landlock
    events: list[str] = []

    def audit_sink(
        kind: str, subject_type: str, subject_id: str, payload: dict[str, object]
    ) -> None:
        del subject_type, subject_id, payload
        events.append(kind)
        log.append(kind, "process", "sandbox", {"error_code": "ASPR_HARDENING_UNAVAILABLE"})

    hardening.detect_landlock = lambda *_args: None
    try:
        try:
            run_plan(
                LocalSandboxPlan(("/bin/true",), NetworkMode.INHERIT),
                hardening=HardeningPolicy(allowed_roots=((root, RootRole.REGULAR_WRITABLE),)),
                audit_sink=audit_sink,
            )
        except HardeningError as error:
            error_code = error.code.string
        else:
            raise AssertionError("unavailable hardening was accepted")
    finally:
        hardening.detect_landlock = original_probe
    kinds = [event.kind for event in log.read()]
    assert error_code == "ASPR_HARDENING_UNAVAILABLE"
    assert events == ["hardening.failure"]
    assert kinds == ["hardening.failure"]
    print(json.dumps({"error_code": error_code, "event_order": kinds, "workload_started": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
