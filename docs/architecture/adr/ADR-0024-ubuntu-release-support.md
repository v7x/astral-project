# ADR-0024: Platform certification and Ubuntu POC support policy

## Status

Proposed; local planning record. Supersedes obsolete blanket Ubuntu-release policy.

## Decision

Support is certified per distribution, release, and architecture by appropriate security evidence. Passing on one platform does not imply support on another.

Current POC matrix:

| Target | Result | Evidence |
|---|---|---|
| Ubuntu 26.04 amd64 | certified | `docs/packet-15f-ubuntu-26.04-evidence.md` |
| Ubuntu 24.04 amd64 | uncertified; packaged gate failed | `docs/packet-15f-ubuntu-24.04-evidence.md` |

Ubuntu 24.04 failure is an AppArmor/package integration failure: packaged `aspr-broker` was denied access to the Ubuntu 24.04 Python site path and administrator source-root include. Diagnostic VM-only policy additions allowed the substantive path, descriptor, DAC, SFTP, and lifecycle checks, but do not count as acceptance. No weaker fallback is permitted.

Packet 16 is not blocked for this POC by Ubuntu 24.04 uncertainty. It begins on certified Ubuntu 26.04 amd64 and must preserve Packet 15 boundary.

After the POC, first intended additional distribution targets are Debian, Fedora, and Rocky Linux. They are future portability targets, not current support claims or Packet 16 requirements. Other distributions remain out of scope for now.

## Portable architecture and Ubuntu realization

Broker authority, signed grants, target-user DAC resolution, descriptor pinning, sealed internal plans, synthetic-root construction, fixed workload identity, authority removal, and fail-closed behavior constitute the Linux remote security architecture.

systemd and AppArmor are current Ubuntu 26.04 host integration/confinement realization. They are not external protocol authorities and must not become caller-selectable grant or request fields. Future ports may require different packaging, service integration, MAC policy, runtime closure, or kernel evidence. Every port must preserve the same invariants; portability never justifies a weaker fallback.

SELinux, Landlock, seccomp, OpenRC, RPM packaging, and generic plugin/backend abstractions are not designed by this record. Each is later work requiring evidence and, where security boundary changes are involved, its own ADR.

## Consequences

- Every claimed target receives release-qualified package, AppArmor/MAC, systemd/service, runtime, kernel, filesystem, positive, and negative evidence as applicable.
- Ubuntu 26.04 evidence cannot certify Ubuntu 24.04.
- Ubuntu 24.04 remains pending for remediation/retest in operational planning, but matrix result is recorded as failed/uncertified, never passed.
- A failed target does not weaken policy or silently downgrade another target.
- Packet 15 runtime closure and namespace construction are complete responsibilities of Packets 15C–15F; Packet 16 owns SFTP functional acceptance and integration.
