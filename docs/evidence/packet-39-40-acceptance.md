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

- source closure: `3f7d7f09132f684e549773d9420041a33011642e`
- package SHA-256: `79687cf39c25972273fb10c2c2b5a48b8f5f30bd35e418c03bdecdf21935d491`
- threat matrix SHA-256: `e0b2ef90052b857a3caf84a697ca343ddf9a7678d229d42659274825094eef7e`
- local validation SHA-256: `fb13fc72ba0f971d63a21342f1f44f9657c0f9dcaef00d2c30266785ecc60a38`
- Ubuntu 24.04 raw SHA-256: `45751016ebc9505c8cacb2cee4d7a65c1b15e21b2b60cfcb8c8fd06c236e2717`
- Ubuntu 26.04 raw SHA-256: `11bdbb1082f9d91d1feedf1c9eb2096edfb549621a312ac1d9daeded4844a4d2`

## Gates

- `./scripts/test`: 931 passed, 2 skipped, 100% coverage.
- `uv run pytest -q tests/adversarial`: 60 passed.
- Ruff and strict mypy: pass.
- Strict native builds, AppArmor parser, and parser fuzz: pass.
- Installed adversarial sandbox acceptance with projected-home FUSE and empty inherited CapBnd: pass on Ubuntu 24.04 and 26.04.
- Checked-in installed remote audit export, retention, pre-opened failure
  recording, and production `run_plan` failure evidence: pass on both releases.
- `git diff --check`: pass; pushed HEAD equals `origin/master`.

Raw commands and outputs live in:

- `docs/evidence/packet-39-40-ubuntu24-raw.txt`
- `docs/evidence/packet-39-40-ubuntu26-raw.txt`
- `docs/evidence/packet-39-40-local-validation.txt`
