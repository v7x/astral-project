# Packets 25–27 acceptance

The canonical packet map is `docs/architecture/adr/ADR-0025-packet-numbering-authority.md`:

- Packet 25: empty projected-home FUSE core;
- Packet 26: pure profile schema and deterministic matcher;
- Packet 27: host-backed read-only projected-home access.

## Repository gates

- `uv lock --check`: passed; `pyfuse3==3.5.0` and `trio==0.31.0` are pinned in the `fuse` optional install extra.
- `./scripts/test`: passed — 591 tests passed, 1 skipped, 100% coverage.
- `git diff --check`: passed.

The optional `fuse` extra is intentional: ordinary repository quality gates remain runnable on systems without libfuse development headers, while packaged projected-home acceptance installs the pinned FUSE stack with `dist/astral_project-0.1.0-py3-none-any.whl[fuse]`.

## Installed acceptance

`scripts/projected_home_acceptance.py` builds a disposable host-home tree and runs the packaged wheel as the unprivileged `testuser`. It does not read the user's real HOME, durable configuration, or credentials.

- Ubuntu 24.04.4 amd64: passed; raw install/hash/probe transcript: `docs/evidence/packet-25-27-ubuntu24-raw.txt`
  - empty FUSE projected HOME mounts, passes the ordinary `/home/sandbox` HOME binding probe, and contains no entries;
  - exact `host-ro` read succeeds;
  - unapproved host-root listing fails closed while subtree listing exposes only the disposable approved subtree;
  - sibling access, symlink escape, write-back, chmod, and truncate are denied;
  - a live host-file mutation is visible through the projected mount;
  - forced daemon crash and stale-mount cleanup complete;
  - mount cleanup completes.
- Ubuntu 26.04 amd64: passed with the same probes; raw install/hash/probe transcript: `docs/evidence/packet-25-27-ubuntu26-raw.txt`

The fixture includes a deliberately non-secret harness-style `.codex/config.toml`, a sibling, an unapproved root file, and a symlink. Host writes are attempted only against the disposable fixture.

## Boundary proof

No profile lifecycle commands, sealing, trusted approval, unknown-path mediation, private/overlay write mode, credential access, real-home access, global AppArmor weakening, or security-sysctl weakening is included in these packets.
