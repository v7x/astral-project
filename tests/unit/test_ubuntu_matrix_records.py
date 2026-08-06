"""Ubuntu release records are explicit pending gates, never inferred support."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[2]


def test_supported_ubuntu_releases_have_non_accepting_amd64_gate_records() -> None:
    for release in ("24.04", "26.04"):
        record = json.loads(
            (ROOT / "packaging" / "matrix" / f"ubuntu-{release}-amd64.json").read_text(
                encoding="utf-8"
            )
        )
        assert record["release"] == release
        assert record["architecture"] == "amd64"
        assert record["gate"] == "packet15f"
        assert record["result"] == "pending"
        assert set(record["required"]) >= {
            "systemd-fd3",
            "descriptor-pinned-mount",
            "expiry-cancellation-cleanup",
        }
