# Packets 30–32 acceptance evidence

## Scope

Private profile state and the descriptor-confined overlay backend are covered
by `tests/unit/test_homed_private.py` and `tests/unit/test_homed_overlay.py`.
The FUSE mount adapters are wired in `src/astral_project/homed/fuse.py`; the
sandbox command exposes `--private-root` and `--overlay-root`, propagates them
through the fixed plan ABI, and binds writable projected homes read-write.
The installed writable FUSE acceptance passed on the Ubuntu 26.04 test VM;
its raw transcript is `docs/evidence/packet-30-32-ubuntu26-raw.txt`. The local
checkout lacks pyfuse3, so local import-safe tests remain environment-dependent.

## Required properties

- Private state is persistent per profile, quota-bounded, mode-sanitized, and
  isolated from the host lower tree.
- Overlay reads merge lower and upper state; writes copy regular lower files to
  the upper with atomic rename; lower state remains unchanged.
- Deletion uses reserved `.wh.<name>` markers, including directory whiteouts.
- Same-root rename is supported; cross-rule-root rename returns `EXDEV`.
- SQLite WAL metadata journaling, fsync ordering, orphan-temp cleanup, corrupt
  journal rejection, crash injection at begin/commit for each mutation kind,
  nested copy-up cleanup, and restart recovery are tested.
- Symlinks, special nodes, hardlink aliases in writable roots, xattrs, mmap,
  POSIX locks, and unsafe metadata are rejected with stable errors.

## Command results

Recorded from the final acceptance run:

- `uv run pytest -q`: 699 passed, 1 skipped.
- `uv run ruff check src tests`: passed.
- `uv run mypy`: passed.
- `git diff --check`: passed.
- `uv run coverage run -m pytest -q && uv run coverage report`: 100% configured gate.
- Installed Ubuntu 26.04 acceptance, driven by
  `scripts/writable_home_acceptance.py`: private write/read and persistence,
  overlay copy-up/whiteout, lower immutability, and mount cleanup all passed.
