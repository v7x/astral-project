# ADR-0001: Python version, uv project layout, typing, and test policy

## Problem

Trusted project needs reproducible Python foundation before protocol or daemon code.

## Choices

- Python 3.12 with `uv`, `src/` package layout, Hatchling build backend, strict mypy, Ruff, pytest, and coverage.
- Unbounded Python support or system-package-only environment.

## Chosen choice

Use Python `>=3.12` in package metadata, with Python 3.12 as the development and type-checking baseline; pin development and build dependencies in `uv.lock`; keep code below `src/astral_project`; use Ruff format/lint, strict mypy, pytest, and branch coverage.

Ubuntu package gates certify the distro `/usr/bin/python3` actually exercised: Python 3.12.3 on Ubuntu 24.04 and Python 3.14.4 on Ubuntu 26.04. This is a certified-interpreter matrix, not an unconditional promise for every Python version. Production trusted processes use the fixed distro interpreter plus fixed application path with Python `-I`; `uv run` remains development-only.

## Security effect

Lockfile gives exact artifacts for review. Isolated launch prevents current-directory, user-site, `.pth`, and `PYTHONPATH` injection into trusted process.

## Rejected choices

- Unbounded interpreter claims: behavior and security patches drift without a certified distro gate.
- Unlocked dependencies: review cannot identify artifact.
- `uv run` production launch: user environment controls resolution and interpreter path.

## Tests

```bash
uv sync --locked --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest
```

## Reconsideration trigger

A certified Ubuntu platform changes its distro Python, or a production launcher gate proves `-I` alone insufficient; update the certified matrix and package policy together.
