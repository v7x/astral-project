# Current Unresolved Issues

## Resolved by Packet 15

These are implemented and evidenced for Ubuntu 26.04 amd64. They are frozen inputs to Packet 16, not open design work:

- descriptor-pinned source resolution and mount construction;
- target-user DAC enforcement;
- broker-side signed-grant and independent root-owned server-ceiling enforcement;
- replay state and rejection;
- fixed digest-verified `sftp_v1` runtime closure;
- synthetic-root construction and setup-authority removal;
- final workload mount, user-namespace, network, shell, and broker-state denial;
- cancellation and expiry supervision;
- Ubuntu 26.04 AppArmor/systemd packaged evidence.

Ubuntu 24.04 AppArmor rule downgrade was diagnosed and fixed by explicit `abi <abi/4.0>,` policy pinning. Clean packaged final-profile socket controls now pass; exact evidence is recorded. No weaker fallback is permitted.

## Packet 16 — genuinely remaining

Packet 16 is split into five ordered subphases:

- **16A — Direct SFTP acceptance harness:** packaged-path harness; INIT/VERSION, REALPATH, STAT/LSTAT, directory enumeration, read/write handles, MKDIR/RMDIR, REMOVE, basic RENAME, and RO/RW baselines. Direct SFTP precedes rclone.
- **16B — Filesystem and authority-sensitive semantics:** traversal, rename/overwrite, cross-export behavior, symlinks, hardlinks, file/dir grants, RO/RW, extension allowlist, nested/export boundaries, and stable SFTP failures.
- **16C — Concurrency, coherence, and large I/O:** active sessions and handles, external changes, identity-versus-descendant semantics, races, offsets, interruption, disconnects, and boundary-oriented large-file cases.
- **16D — Lifecycle, readiness, errors, and logging:** expiry, cancellation, cleanup, expired setup rejection, existing revocation-interface validation, readiness order, failure classes, and clean logging.
- **16E — rclone compatibility:** compatibility evidence for ADR-0007 pinned versions against fixed remote SFTP only.

`RemoteSessionReadyV1` means authenticated, confined SFTP byte stream is ready to receive client `SSH_FXP_INIT`; it does not include VERSION exchange. Order is authenticated request → worker registration → `NamespaceReadyV1` → `RemoteSessionReadyV1` → raw stream → client INIT → server VERSION.

Packet 16 owns expiry and cancellation integration. Revocation acceptance is limited to already-defined authoritative interfaces; broader grant lifecycle remains later work. No new revocation database, polling system, daemon-to-broker protocol, public revoke CLI, or background distribution belongs here.

Descriptor pinning stabilizes export-root identity, not descendant snapshots. A renamed/replaced export pathname leaves an existing session on its pinned object; changes inside that object follow normal kernel/filesystem semantics. Symlinks must not enlarge authority beyond the synthetic namespace. Hardlinks follow normal kernel/filesystem limits and must not escape the grant; no bespoke inode policy without evidence.

Concurrent active workers do not require concurrent broker parsing. Brief serialized setup plus independently supervised workers is acceptable until acceptance proves otherwise. Packet 16 is not `aspr transport` or any private local transport capability; those remain Packet 18. Fixed Packet 15 boundary changes require Packet 15 regression evidence on certified platforms.

## Later product work

- transport and public lifecycle commands;
- local agent bubblewrap sandbox;
- projected-home/FUSE learner and approval UI;
- audit hardening and attack-suite expansion;
- filesystem, rclone, harness, and portability matrices;
- packaging operations beyond current Ubuntu POC.

No weaker remote backend or pathname-reopen fallback is permitted. Any change to frozen Packet 15 invariants requires ADR/security review.
