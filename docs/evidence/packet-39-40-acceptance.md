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

- source closure: `ae41ed80f8c2b0ddab17a799f592c6991a8ae33c`
- package SHA-256: `2e5ed2ef9ff3c65991c2321debb4080c5de30bd6f60ade145c144ccda418e2dc`
- threat matrix SHA-256: `ffd5a5a2709139c2f224adbb8dab862a9fbf64e4f123a2839a0fe2e221b1441c`
- local validation SHA-256: `d89b2db5fa746425a82039cc4451b6acdd970615d227aa716ea9c7d07edf7c1c`
- Ubuntu 24.04 raw SHA-256: `95d762639cafaf281a442f365275080005bb6220a37b90c74e906c10437e9a93`
- Ubuntu 26.04 raw SHA-256: `3c53a345c850c0d256e6606ebb4edfaecb15e58d91f724ba2fa6d0c9bd908624`

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
