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

- source closure: `9a12fd2f13f1a21981be232511952a2b86e243d3`
- package SHA-256: `51c603734a86400b1926e323bed75f8a2704ee1f1fd73e3822bf0ebfecb36367`
- threat matrix SHA-256: `a7b7bd3be19e9171b1947e7be6abf6a2ba84982607aacb11b6328d0f0fad83e1`
- local validation SHA-256: `cf2a2d9a570929e29e0d54f7138c0f83356a03c13f1cd6800245a726a70917d6`
- Ubuntu 24.04 raw SHA-256: `553002a9c8d1f052e03378d9a94984a8797f0bed97175d979f4ae87a9c4074fa`
- Ubuntu 26.04 raw SHA-256: `6e8bea8036a45be8af1acc77efc43fe5cc3495295cd00be58a0a615696551734`

## Gates

- `./scripts/test`: 915 passed, 2 skipped, 100% coverage.
- `uv run pytest -q tests/adversarial`: 44 passed.
- Ruff and strict mypy: pass.
- Strict native builds, AppArmor parser, and parser fuzz: pass.
- Installed adversarial sandbox acceptance: pass on Ubuntu 24.04 and 26.04.
- Installed real-kernel remote audit export, retention, pre-opened failure
  recording, and production `run_plan` failure evidence: pass on both releases.
- `git diff --check`: pass; pushed HEAD equals `origin/master`.

Raw commands and outputs live in:

- `docs/evidence/packet-39-40-ubuntu24-raw.txt`
- `docs/evidence/packet-39-40-ubuntu26-raw.txt`
- `docs/evidence/packet-39-40-local-validation.txt`
