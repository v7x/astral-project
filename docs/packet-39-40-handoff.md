# Packets 39–40 handoff

## Gate

Packets 39 and 40 are complete. Detached audit approval remains required.
Packet 41 is out of scope and untouched.

Source closure is `9a12fd2f13f1a21981be232511952a2b86e243d3`; final package is
`51c603734a86400b1926e323bed75f8a2704ee1f1fd73e3822bf0ebfecb36367`.
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
- installed Packet 40 positive/negative acceptance on Ubuntu 24.04 and 26.04;
- installed real-kernel Landlock, AppArmor/native, capability, network,
  hidden-home, socket, FD, remote-audit, retention, and failure-order probes;
- exact source, package, matrix, and raw transcript hashes;
- `git diff --check` and pushed refs equal.

See `docs/evidence/packet-39-40-acceptance.md` for gate results and raw
transcript paths.
