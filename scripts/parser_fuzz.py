#!/usr/bin/env python3
"""Run bounded parser fuzz corpus for installed protocol parsers."""

from __future__ import annotations

import sys
from pathlib import Path

from astral_project.server.protocol import fuzz_outer_request

_MAX_CASE_BYTES = 1 << 20
_DEFAULT_CORPUS = Path(__file__).parents[1] / "tests" / "fixtures" / "fuzz"


def run(corpus: Path = _DEFAULT_CORPUS) -> int:
    """Parse built-in and checked-in corpus cases; return zero on completion."""
    cases = [b"", b"\x00", b"\xff" * 16, b"\x00\x00\x00\x02\xff\xff"]
    if corpus.exists():
        for path in sorted(item for item in corpus.iterdir() if item.is_file()):
            data = path.read_bytes()
            if len(data) <= _MAX_CASE_BYTES:
                cases.append(data)
    for data in cases:
        fuzz_outer_request(data)
    print(f"PASS parser fuzz cases={len(cases)}")
    return 0


def main() -> int:
    """CLI entry point with optional corpus directory."""
    corpus = Path(sys.argv[1]) if len(sys.argv) == 2 else _DEFAULT_CORPUS
    if len(sys.argv) > 2:
        print("usage: parser_fuzz.py [CORPUS]", file=sys.stderr)
        return 2
    return run(corpus)


if __name__ == "__main__":
    raise SystemExit(main())
