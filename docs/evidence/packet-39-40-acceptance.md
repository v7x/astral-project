# Packets 39–40 acceptance

Status: complete pending detached auditor approval.

Packets 39 and 40 convert authoritative remote and local threat lists into an
executable checked-in matrix. `docs/evidence/packet-39-40-threat-matrix.json`
contains 20 remote IDs (`R01`–`R20`) and 22 local IDs (`L01`–`L22`). The
matrix tests parse every referenced test or installed driver and reject missing
references. `R18` is explicitly marked `residual-rootless-race`; it is not
presented as a proven race pass.

Local adversarial gates cover path pinning, grant context, replay/revocation,
runtime closure, FD and resource isolation, mediation bounds, approval and
terminal control, session relay, rclone transport, FUSE/overlay recovery, and
native hardening. Installed Packet 40 acceptance additionally proves hidden
home and host-process targets, socket and credential absence, network isolation,
capability-set zeroing, native negative controls, and AppArmor enforcement.

## Evidence

- source closure: `4e9d30d7487b46aca06678dd9d6b331e523c82ad`
- package SHA-256: `df138f9a75294d0bf54c473bcb50da583ef3147901e107a5e866018f781b6ca8`
- threat matrix SHA-256: `ea8b23b02c8fbac5b05531f3b17234abbd1a8cef48bb6d32321ee00ee7e5209b`
- local validation SHA-256: `a5cecf682605f72218baad2d33eca977127a5c3089498bfe86392457d428d861`
- Ubuntu 24.04 raw SHA-256: `eda4bf3df62a76a61f5b844fc87010401ce438a878167f8728f289b11fbf0706`
- Ubuntu 26.04 raw SHA-256: `2ff501ae80e5dea7e3066f0571af218861b06f81238ab3480cb2cb61d518851c`

## Gates

- `./scripts/test`: 915 passed, 2 skipped, 100% coverage.
- `uv run pytest -q tests/adversarial`: 44 passed.
- Ruff and strict mypy: pass.
- Strict native builds, AppArmor parser, and parser fuzz: pass.
- Installed adversarial sandbox acceptance with projected-home FUSE and empty inherited CapBnd: pass on Ubuntu 24.04 and 26.04.
- Installed real-kernel remote audit export, retention, pre-opened failure
  recording, and production `run_plan` failure evidence: pass on both releases.
- `git diff --check`: pass; pushed HEAD equals `origin/master`.

Raw commands and outputs live in:

- `docs/evidence/packet-39-40-ubuntu24-raw.txt`
- `docs/evidence/packet-39-40-ubuntu26-raw.txt`
- `docs/evidence/packet-39-40-local-validation.txt`
