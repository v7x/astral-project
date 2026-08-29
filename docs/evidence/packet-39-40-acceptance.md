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

- source closure: `44319bed74c693fd1f41bfe7612108d34857452a`
- package SHA-256: `fc4ad72fe95f4660f1d458aa20c053f9b31e9bb8c919b69736639dbe32bfd10e`
- threat matrix SHA-256: `ea8b23b02c8fbac5b05531f3b17234abbd1a8cef48bb6d32321ee00ee7e5209b`
- local validation SHA-256: `bde22bddffa690c4c3a3cfee5083ec3a560f1158734717d5c865728d4a5936e9`
- Ubuntu 24.04 raw SHA-256: `4c5439460626bdf87fc003f37055071830367299ae7adaa75650c2ba9e965cde`
- Ubuntu 26.04 raw SHA-256: `94dc5d15328e6751c482dd4122ec53902588e77ace4a5bb0245946c8ece1e859`

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
