"""Packet 10 candidate pin manifest tests."""

from __future__ import annotations

import tomllib
from pathlib import Path

MANIFEST = Path(__file__).parents[1] / "fixtures" / "rclone" / "candidates.toml"


def test_rclone_spike_candidates_are_exact_linux_amd64_pins() -> None:
    with MANIFEST.open("rb") as stream:
        candidates = tomllib.load(stream)

    assert set(candidates) == {"1.73.3", "1.74.4"}
    for version, candidate in candidates.items():
        assert set(candidate) == {"archive_sha256", "archive_url", "binary_sha256"}
        assert candidate["archive_url"] == (
            f"https://downloads.rclone.org/v{version}/rclone-v{version}-linux-amd64.zip"
        )
        assert all(len(candidate[field]) == 64 for field in ("archive_sha256", "binary_sha256"))
        assert all(candidate[field].isalnum() for field in ("archive_sha256", "binary_sha256"))
