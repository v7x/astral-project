from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from astral_project.core.errors import AstralError
from astral_project.daemon.protocol import parse_request
from astral_project.rclone.listing import (
    RcloneOutput,
    daemon_listing_handler,
    listing_options_from_payload,
)


def listing_payload() -> dict[str, object]:
    return {
        "filters": [],
        "json_output": False,
        "max_depth": None,
        "no_header": False,
        "raw_output": False,
        "recursive": False,
        "reverse": False,
        "sort": "path",
        "stat": False,
        "target": "grant:/",
        "timeout_seconds": None,
    }


def test_daemon_listing_handler_returns_bounded_encoded_output(tmp_path: Path) -> None:
    def runner(_argv: object, _environment: object, _timeout: object) -> RcloneOutput:
        return RcloneOutput(
            json.dumps(
                [{"Path": "file", "Name": "file", "Size": 1, "ModTime": None, "IsDir": False}]
            ).encode(),
            b"",
            0,
        )

    # The handler uses production runner; malformed fixed binary is rejected before execution.
    with pytest.raises(AstralError):
        daemon_listing_handler(listing_payload(), binary=tmp_path / "rclone", config=tmp_path / "c")


def test_daemon_protocol_allows_only_ls_payload() -> None:
    payload = listing_payload()
    payload = {
        "cancellation_id": "c",
        "kind": "request",
        "operation": "ls",
        "payload": payload,
        "request_id": "r",
        "version": 1,
    }
    request = parse_request(payload)
    assert request.operation == "ls"
    assert request.payload is not None

    payload["payload"] = {"target": "other"}
    with pytest.raises(AstralError):
        listing_options_from_payload(cast(Mapping[str, object], payload["payload"]))
