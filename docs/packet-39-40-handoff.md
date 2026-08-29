# Packets 39–40 handoff

## Gate

Packets 39 and 40 are complete. Detached audit approval remains required.
Packet 41 is out of scope and untouched.

Source closure is `44319bed74c693fd1f41bfe7612108d34857452a`; final package is
`fc4ad72fe95f4660f1d458aa20c053f9b31e9bb8c919b69736639dbe32bfd10e`.
Evidence-only documentation commits must preserve this source closure.

## Contract

Every authoritative Packet 39 remote attack and Packet 40 local attack has an
ID in `docs/evidence/packet-39-40-threat-matrix.json` and an executable target.
The matrix validator rejects missing target files or test functions. Remote
hardlink alias race `R18` is marked residual-rootless-race, never a false pass.

Adversarial work preserves Packet 37–38 security boundaries: no raw remote
audit export, secret/path leakage, Landlock overgrant, AppArmor weakening,
namespace or capability relaxation, or Packet 24 session API expansion.

## Required final evidence

- full suite, focused adversarial matrix, strict mypy, and Ruff;
- strict native builds, AppArmor parser validation, and parser fuzz;
- installed Packet 40 positive/negative acceptance with projected-home FUSE
  and empty inherited CapBnd on Ubuntu 24.04 and 26.04;
- installed real-kernel Landlock, AppArmor/native, capability, network,
  hidden-home, socket, FD, remote-audit, retention, and failure-order probes;
- exact source, package, matrix, and raw transcript hashes;
- `git diff --check` and pushed refs equal.

See `docs/evidence/packet-39-40-acceptance.md` for gate results and raw
transcript paths.
