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

- source closure: `0cba915bafde1a8500e1c01ab4a9ad9302e9cea8`
- package SHA-256: `4707c585f9123b54883e65e8c91862e84475f976e019105534ad874cc91bc01b`
- threat matrix SHA-256: `ffd5a5a2709139c2f224adbb8dab862a9fbf64e4f123a2839a0fe2e221b1441c`
- local validation SHA-256: `7f03bd0fc7a5db721bb06617734dc7d457e237038d513e89735de7dbdd2e3aa2`
- Ubuntu 24.04 raw SHA-256: `29235a7d9694fb9d71691b44c4751a06c21bbdb8e342547f899b07f6a0d361b6`
- Ubuntu 26.04 raw SHA-256: `00adeaf71f2a7ad99ad5f79dac24a27993554d376d72a830837bfe455838a3e5`

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
