"""Ubuntu release records are explicit pending gates, never inferred support."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

ROOT = Path(__file__).parents[2]


def _record(release: str) -> dict[str, object]:
    value = json.loads(
        (ROOT / "packaging" / "matrix" / f"ubuntu-{release}-amd64.json").read_text(encoding="utf-8")
    )
    return cast(dict[str, object], value)


def test_supported_ubuntu_releases_have_explicit_amd64_gate_records() -> None:
    for release in ("24.04", "26.04"):
        record = _record(release)
        assert record["release"] == release
        assert record["architecture"] == "amd64"
        assert record["gate"] == "packet15f"
        required = cast(list[str], record["required"])
        assert set(required) >= {
            "systemd-fd3",
            "descriptor-pinned-mount",
            "expiry-cancellation-cleanup",
        }


def test_ubuntu_2604_acceptance_references_passed_evidence() -> None:
    record = _record("26.04")
    assert record["result"] == "passed"
    evidence = ROOT / str(record["evidence"])
    assert evidence.is_file()
    assert "Status: **passed**" in evidence.read_text(encoding="utf-8")


def test_ubuntu_2404_remains_uncertified() -> None:
    record = _record("24.04")
    assert record["result"] == "failed"
    evidence = ROOT / str(record["evidence"])
    assert evidence.is_file()
    assert "uncertified" in evidence.read_text(encoding="utf-8")
