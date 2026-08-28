from __future__ import annotations

from pathlib import Path

import pytest

from astral_project.sandbox.hardening import HardeningStatus


@pytest.fixture(autouse=True)
def isolate_process_hardening(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep unit tests from permanently Landlocking the pytest process."""
    monkeypatch.setattr(
        "astral_project.daemon.server.enforce",
        lambda _policy: HardeningStatus(True, 1, True, True, "test hardening enforced"),
    )
    monkeypatch.setattr(
        "astral_project.server.entry.enforce",
        lambda _policy: HardeningStatus(True, 1, True, True, "test hardening enforced"),
    )
    monkeypatch.setattr(
        "astral_project.server.entry.BROKER_SOCKET", Path("/tmp/aspr-unit-broker.sock")
    )
