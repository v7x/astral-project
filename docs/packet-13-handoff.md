# Historical Packet 13 handoff — 13A closed; 13B broker contract frozen

> Historical record. Packet 15C–15F subsequently implemented and gated descriptor-pinned execution, runtime closure, synthetic-root construction, authority removal, and Ubuntu packaging. Current truth: `docs/15-continuation.md` and Packet 15F evidence.

## Packet 13A — permanent negative-control evidence

`aspr-test`: Ubuntu 24.04.4, kernel `6.8.0-136-generic`, `apparmor_restrict_unprivileged_userns=1`.

- Direct Python identity-map write denied: `unsupported`, `direct_unprofiled_python`, `uid_gid_map`, `apparmor_denied_identity_map`.
- Parent-mapped unprofiled child mount namespace denied `EPERM`: `unsupported`, `unprofiled_rootless_backend`, `mount_namespace_creation`.

No descriptor mount syscall ran. Rootless backend is deferred; results are host-policy evidence, not pinning failures.

## Packet 13B — administrator-bootstrapped broker

One-time administrator package installation creates root-owned broker. Normal callers remain unprivileged. Broker authenticates external signed GrantV1/session request, independently validates root-owned server ceiling, owns replay state, opens/pins descriptors, forks worker, and chooses fixed `sftp_v1` workload.

Worker receives sealed `memfd` internal plan and directly inherited descriptors. No source/staging path authority, command, argv, environment, profile, mount flags, or workload selector crosses worker boundary. No internal plan signature unless later ADR proves sealed `memfd` insufficient.

AppArmor confines broker/workload; it never authorizes callers. Final workload has neither mount nor user-namespace authority.

## Next packets

Packet 13 is closed. Do not return for positive acceptance. Packet 14, 14A, and 14B are complete: deterministic descriptor-slot planner; canonical `OpenSessionV1`, remote-session, and `CreateNamespaceV1` schemas; `SO_PEERCRED` rule; atomic replay-state model; root-owned server-ceiling schema/validation; path-free audit and worker-result schemas. Golden canonical-byte fixtures, GrantV1 signature fixture, replay tests, and server-ceiling tests pass.

Packet 14 contract amendment freezes worker FD ABI (ready `3`, continue `4`, sealed plan `5`, stream `6`, source slots `10..73`), framed `NamespaceReadyV1`, opaque post-ready SFTP relay, pre-ready disconnect cancellation, broker-owned post-ready child lifetime, parent-death kill, source-FD ownership, and fixed systemd/AppArmor identities.

Packet 15 root broker skeleton and Packet 15A mapping are complete: root-only Unix socket, kernel `SO_PEERCRED` check before parse, independent GrantV1/server-ceiling validation, bounded request parsing, path-free audit, fixed native worker invocation, synchronized `CLONE_NEWUSER|CLONE_NEWNS`, and broker-parent UID/GID mapping. Mapping worker accepts no caller arguments or environment. It makes no descriptor mount, capability-drop, or workload-execution call.

Planner moved minimal fixed SFTP runtime closure to Packet 15C. Packet 15B descriptor worker and sealed-plan pieces exist but are not integrated with broker source opening/FD handoff. Packet 15C now builds closure; 15D owns synthetic root, authority drop, and fixed workload; 15E owns package/AppArmor; 15F owns Ubuntu gate. No unconfined SFTP execution is permitted.

Packet 16 may proceed on the certified Ubuntu 26.04 amd64 POC target once Packet 15F and repository quality gates pass. Ubuntu 24.04 certification is desirable but not required. Section 7 of `docs/15-continuation.md` proposes `CreateSessionV1`, which conflicts with frozen `CreateNamespaceV1`; planner must explicitly declare replacement or compatibility before broker request integration.
