# ADR-0023 — Administrator-bootstrapped broker authority

## Status

Accepted. Primary Ubuntu backend after one-time administrator package installation. Ordinary operation thereafter is unprivileged.

## Revision history

- 2026-03-12: Checkpoint remediation adopted in `docs/packet-15-remediation-plan.md`: composite client-nonce replay key; typed broker response/cancellation unions; configured UID/GID binding; per-root ceilings; collision-safe worker FD handoff; separated stream/log FDs; non-executing runtime discovery; closure-only smoke evidence. No remote installation authorized.
- 2026-03-12: `CreateNamespaceV1` remains sole broker wire request. Prerelease nested remote-request schema withdrawn. Version remains `1`; no compatibility decoder. Request now has fixed request/session IDs, canonical Grant envelope, client nonce, and `sftp_v1` workload. Response is `NamespaceReadyV1` or `NamespaceRejectedV1`; ready transfers exactly one stream FD through `SCM_RIGHTS`. `CreateSessionV1` is unsupported.

## Packet 13A closure

`aspr-test` proves permanent negative controls:

- direct Python identity-map setup denied;
- parent-mapped unprofiled child mount-namespace creation denied `EPERM`.

These are expected AppArmor host-policy results, not descriptor-pinning failures. Rootless backend is deferred.

## Current canonical remote path

The production remote path is: signed grant → remote `aspr-server`/broker request → root-owned broker → peer authentication and independent grant/server-ceiling validation → target-user-DAC source resolution → pinned source descriptors → sealed bounded internal execution plan → namespace/mount worker → private synthetic root → fixed digest-verified `sftp_v1` runtime → setup-authority removal → final confined OpenSSH `sftp-server`.

Bubblewrap is not the production remote backend. It remains permitted for the planned local agent sandbox. systemd and AppArmor are Ubuntu host integration/confinement mechanisms; neither authenticates or authorizes callers, and neither is selectable through external protocol fields.

## Authority model

Remote root-owned broker is sole authority for namespace execution. Broker:

- authenticates peer and validates signed `GrantV1` or signed session request;
- validates root-owned server ceiling independently;
- owns atomic replay states: `issued`, `consumed`, `expired`, `revoked`;
- opens and pins source descriptors;
- forks bounded worker;
- selects fixed workload `sftp_v1`.

Client daemon and remote unprivileged Python neither sign plans nor receive mount authority.

Worker receives sealed `memfd` execution plan and directly inherited pinned descriptors. Plan is internal, bounded, and carries descriptor slots plus recorded device/inode/mount identity. It carries no source/staging path authority, executable path, argv, environment, profile, mount flags, or workload selector. Separate internal plan signature is rejected unless later ADR proves `memfd` sealing and descriptor provenance insufficient.

Worker FD ABI V1 is fixed: mapping-ready `3`, mapping-continue `4`, sealed plan `5`, broker stream `6`, source descriptors from `10` through `73`. Broker duplicates source descriptors into slots, retains ownership until child fork succeeds, then closes parent copies. Worker may never receive source path bytes.

Remote server sends framed `CreateNamespaceV1`, waits framed `NamespaceReadyV1`, then relays opaque SFTP bytes between SSH stdio and same broker stream. Before ready, disconnect cancels request. After ready, broker owns child lifetime; worker has parent-death kill and stream EOF ends workload. Terminal state goes to broker audit, never SFTP stdout.

Fixed packaging identities: `aspr-broker.service`; runtime directory `/run/astral-project`; automatic AppArmor profiles `usr.libexec.astral-project.aspr-broker`, `usr.libexec.astral-project.aspr-mount-worker`, and `usr.libexec.astral-project.aspr-sftp-server`. No caller invokes `aa-exec` or selects profile.

## AppArmor role

AppArmor confines broker and fixed final workload. It does not authorize callers. Final workload has no mount capability or user-namespace authority.

## Packet order

1. Packet 13A: closed negative-control evidence.
2. Packet 13B: this approved ADR freezes broker/worker authority, signed external request, sealed internal plan, replay and server-ceiling ownership, AppArmor role, fixed workload, and rootless deferral.
3. Packet 14 onward: pure schemas, contracts, broker, worker, confinement, and package implementation.
4. Packet 15C: minimal fixed SFTP runtime closure.
5. Packet 15D: final namespace, authority drop, and fixed workload.
6. Packet 15E: systemd/AppArmor package.
7. Packet 15F: final per-platform descriptor-pinned mount and confinement gate after broker, worker, closure, AppArmor, and packaging exist. Ubuntu 26.04 amd64 passed; Ubuntu 24.04 amd64 failed packaged AppArmor integration and remains uncertified.

Packet 14 begins only after 13B approval. Packet 16 begins from the certified Ubuntu 26.04 `result=passed` gate. It owns full SFTP functional acceptance and integration, not runtime closure or namespace construction. No native launcher or mount code begins before Packet 14, 14A, and 14B contracts, canonical fixtures, signature fixtures, replay tests, and server-ceiling tests pass.
