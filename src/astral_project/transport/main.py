"""Installed external rclone transport entry point."""

from __future__ import annotations

import os
import sys

from astral_project.transport.local import run_transport


def main() -> None:
    raise SystemExit(
        run_transport(
            sys.argv[1:],
            environment=os.environ,
            stdin=getattr(sys.stdin.buffer, "raw", sys.stdin.buffer),
            stdout=getattr(sys.stdout.buffer, "raw", sys.stdout.buffer),
            stderr=sys.stderr.buffer,
        )
    )


if __name__ == "__main__":  # pragma: no cover
    main()
