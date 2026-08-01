# ADR-0024: Ubuntu release support policy

Status: proposed; local planning record. Do not commit before all packets complete.

## Decision

Astral Project supports every Ubuntu release in Canonical standard support at package-build and gate time, subject to one mandatory per-release Packet 15F evidence record. Ubuntu 24.04 is no longer sole acceptance target. Ubuntu 26.04 is first additional target.

Initial scope remains `amd64`. Project interpreter contract is Python `>=3.12`, with no upper bound. Each supported Ubuntu release must still receive dependency-resolution, package-build, and Packet 15F evidence before support claim. Other Ubuntu architectures and non-Ubuntu distributions require their own runtime-closure and Packet 15F records before support claims.

## Consequences

- Package build must not hard-code Ubuntu 24.04 library paths, AppArmor parser behavior, systemd version, or kernel release.
- Runtime closure discovery derives loader and library roots from target release/architecture package metadata; package constants may only select fixed workload identity.
- AppArmor policy must parse and load on every supported release. A profile is not accepted solely because `apparmor_parser -p` succeeds on build host.
- Systemd units must verify against every supported systemd release.
- Packet 15F writes release-qualified evidence, including Ubuntu version, kernel, AppArmor/systemd versions, runtime manifest digest, and negative-control outcomes.
- Failure on one supported release blocks release for that release only; it must not cause global AppArmor/sysctl weakening or downgrade another release's policy.

## Release matrix before installation

For each release: clean VM, read-only capability probe, package build/install rehearsal, AppArmor load rehearsal, systemd verification, runtime closure creation, Packet 15F preflight, and full positive/negative gate.

Current known Ubuntu 26.04 evidence: kernel `7.0.0-28-generic`, systemd `259`, AppArmor parser `5.0.0~beta1`, user namespace creation denied under host policy, SFTP loader `/lib64/ld-linux-x86-64.so.2`, and `libc.so.6` direct dependency.
