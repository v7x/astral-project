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

- complete SFTP operation matrix;
- concurrent connections and coherent external modifications;
- rename/overwrite, large-file, traversal, extension, hardlink, and symlink semantics;
- stable SFTP error mapping;
- expiry/revocation integration with functional client behavior;
- remote preface integration;
- rclone compatibility;
- readiness semantics;
- production logging.

## Later product work

- transport and public lifecycle commands;
- local agent bubblewrap sandbox;
- projected-home/FUSE learner and approval UI;
- audit hardening and attack-suite expansion;
- filesystem, rclone, harness, and portability matrices;
- packaging operations beyond current Ubuntu POC.

No weaker remote backend or pathname-reopen fallback is permitted. Any change to frozen Packet 15 invariants requires ADR/security review.
