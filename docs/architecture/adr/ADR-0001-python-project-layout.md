# ADR-0001: Python version, uv project layout, typing, and test policy

## Problem

Trusted project needs reproducible Python foundation before protocol or daemon code.

## Choices

- Python 3.12 with `uv`, `src/` package layout, Hatchling build backend, strict mypy, Ruff, pytest, and coverage.
- Unbounded Python support or system-package-only environment.

## Chosen choice

Use Python `>=3.12,<3.13`; pin development and build dependencies in `uv.lock`; keep code below `src/astral_project`; use Ruff format/lint, strict mypy, pytest, and branch coverage.

Production trusted processes later use fixed interpreter plus fixed application path with Python `-I`. `uv run` remains development-only.

## Security effect

Lockfile gives exact artifacts for review. Isolated launch prevents current-directory, user-site, `.pth`, and `PYTHONPATH` injection into trusted process.

## Rejected choices

- Broad Python range: behavior and security patches drift.
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

Supported platform cannot run pinned Python 3.12, or production launcher gate proves `-I` alone insufficient.
