#!/usr/bin/env python3
"""Installed fail-closed hardening failure acceptance probe."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

from astral_project.audit import AuditLog
from astral_project.sandbox import hardening
from astral_project.sandbox.hardening import HardeningError, HardeningPolicy, RootRole
from astral_project.sandbox.plan import LocalSandboxPlan, NetworkMode
from astral_project.sandbox.runner import run_plan


def main() -> int:
    root = Path.home() / ".local" / "state" / "astral-project" / "hardening-acceptance"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    allowed = root / "allowed"
    allowed.mkdir(mode=0o700, exist_ok=True)
    marker = allowed / "workload-executed"
    marker.unlink(missing_ok=True)
    log = AuditLog(root / "failure.jsonl")
    original_probe = hardening.detect_landlock
    error_code: str | None = None
    events: list[str] = []

    def audit_sink(
        kind: str, subject_type: str, subject_id: str, payload: dict[str, object]
    ) -> None:
        events.append(kind)
        log.append(kind, subject_type, subject_id, payload)

    try:
        hardening.detect_landlock = cast(Callable[..., int | None], lambda *_args: None)
        try:
            run_plan(
                LocalSandboxPlan(("/bin/sh", "-c", f"touch {marker}"), NetworkMode.INHERIT),
                hardening=HardeningPolicy(allowed_roots=((allowed, RootRole.REGULAR_WRITABLE),)),
                audit_sink=audit_sink,
            )
        except HardeningError as error:
            error_code = error.code.string
    finally:
        hardening.detect_landlock = original_probe
    output = {
        "error_code": error_code,
        "marker_present": marker.exists(),
        "audit_events": [event.kind for event in log.read()],
        "sink_events": events,
    }
    print(json.dumps(output, sort_keys=True))
    return (
        0
        if error_code == "ASPR_HARDENING_UNAVAILABLE"
        and not marker.exists()
        and events == ["hardening.failure"]
        else 70
    )


if __name__ == "__main__":
    raise SystemExit(main())
