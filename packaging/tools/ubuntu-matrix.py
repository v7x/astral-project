#!/usr/bin/python3
"""Read-only Ubuntu 24.04/26.04 package compatibility preflight."""

from __future__ import annotations

import json
import platform
from pathlib import Path

SUPPORTED = frozenset({"24.04", "26.04"})


def main() -> int:
    values = dict(
        line.split("=", 1)
        for line in Path("/etc/os-release").read_text().splitlines()
        if "=" in line
    )
    version = values.get("VERSION_ID", "").strip('"')
    result = {
        "ubuntu_version": version,
        "kernel": platform.release(),
        "result": "passed"
        if values.get("ID") == "ubuntu" and version in SUPPORTED
        else "unsupported",
    }
    print(json.dumps(result, sort_keys=True))
    return 0 if result["result"] == "passed" else 70


if __name__ == "__main__":
    raise SystemExit(main())
