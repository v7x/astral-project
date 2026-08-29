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
native hardening. The checked-in Packet 39 driver additionally executes every
fixed Landlock role, allowed/denied filesystem operation, audit protocol,
retention/rotation/tamper/concurrency, real nested-mount pinning, and revoked
mount operation against the installed package. Installed Packet 40 acceptance
additionally proves hidden home and host-process targets, socket and credential
absence, network isolation, capability-set zeroing, native negative controls,
and AppArmor enforcement.

## Evidence

- source closure: `4cb50d147d5cdb6112c4a0fd0b2ed7fcbc6a386c`
- package SHA-256: `80898ff6d9ef12e3b31a8cd34024b69e56e2bac5413b8ab6daf1a6890fe39c6c`
- threat matrix SHA-256: `8521de9aac2b01a31e34d2e79f5825c0299e67ad1cf713bff1403e322d1c30e1`
- local validation SHA-256: `732c5b0750271fb5d85241f670b75fb7fba2377a2c15ee60a34d15deb37bfb90`
- Ubuntu 24.04 raw SHA-256: `21ae887500e9cd75e08a0fee0cd30d66e945d2f05bb4c6d46bc0f956ab62d4f0`
- Ubuntu 26.04 raw SHA-256: `54e55f6ffe3228eb187d0c7b2621859938ac099e51154a8f541d1dfe875d4d98`

## Gates

- `./scripts/test`: 931 passed, 2 skipped, 100% coverage.
- `uv run pytest -q tests/adversarial`: 60 passed.
- Ruff and strict mypy: pass.
- Strict native builds, AppArmor parser, and parser fuzz: pass.
- Installed adversarial sandbox acceptance with projected-home FUSE and empty inherited CapBnd: pass on Ubuntu 24.04 and 26.04.
- Checked-in installed Packet 39 driver: all four Landlock roles and their
  allowed/denied operation matrices, audit protocol abuse, hashing/redaction,
  provenance, retention/rotation/tamper/concurrency, nested mount pinning,
  revoked operation rejection, remote export, and failure ordering pass on both
  releases.
- `git diff --check`: pass; pushed HEAD equals `origin/master`.

Raw commands and outputs live in:

- `docs/evidence/packet-39-40-ubuntu24-raw.txt`
- `docs/evidence/packet-39-40-ubuntu26-raw.txt`
- `docs/evidence/packet-39-40-local-validation.txt`
