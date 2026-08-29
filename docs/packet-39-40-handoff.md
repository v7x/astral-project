# Packets 39–40 handoff

## Gate

Packets 39 and 40 are complete. Detached audit approval remains required.
Packet 41 is out of scope and untouched.

Source closure is `4e9d30d7487b46aca06678dd9d6b331e523c82ad`; final package is
`df138f9a75294d0bf54c473bcb50da583ef3147901e107a5e866018f781b6ca8`.
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
