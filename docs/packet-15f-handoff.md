# Packet 15F Handoff

## Status

Packet 15F passed for Ubuntu 26.04 amd64 and Ubuntu 24.04 amd64 after explicit AppArmor ABI pinning. Historical pre-ABI warnings and failures remain in exact evidence. Packet 16 requires one certified POC target, not simultaneous certification of both releases.

Evidence:

- `docs/packet-15f-ubuntu-26.04-evidence.md`
- `docs/packet-15f-ubuntu-24.04-evidence.md`
- `docs/15-continuation.md`

## Frozen Packet 15 boundary

Remote production path:

```text
signed grant
→ remote aspr-server/broker request
→ root-owned broker
→ peer authentication and independent grant/server-ceiling validation
→ target-user-DAC source resolution
→ pinned source descriptors
→ sealed bounded execution plan
→ mapped namespace/mount worker
→ private synthetic root
→ fixed digest-verified sftp_v1 runtime
→ setup-authority removal
→ final confined OpenSSH sftp-server
```

No caller selects executable, argv, environment, profile, staging root, arbitrary mount flags, or workload. No pathname reopen fallback exists. Bubblewrap remains only for planned local-agent sandboxing.

## Packet 16 entry

Packet 16 consumes this boundary in five ordered subphases:

- **16A — Direct SFTP acceptance harness:** packaged path, basic SFTP operation and RO/RW baseline matrix. Direct SFTP precedes rclone.
- **16B — Filesystem and authority-sensitive semantics:** traversal, rename/overwrite, cross-export behavior, symlink/hardlink rules, grants, extension allowlist, nested boundaries, stable SFTP failures.
- **16C — Concurrency, coherence, and large I/O:** active sessions/handles, external changes, races, offset correctness, interruptions, disconnects, and boundary-oriented large-file tests.
- **16D — Lifecycle, readiness, errors, and logging:** expiry, cancellation, cleanup, expired setup rejection, existing revocation interfaces, readiness ordering, error classes, and byte-clean logging.
- **16E — rclone compatibility:** evidence only against fixed remote SFTP and ADR-0007 pinned versions.

Packet 16 does not rebuild runtime closure, synthetic root, fixed workload, namespace construction, or confinement. It does not implement Packet 18 private local transport. Expiry/cancellation integration is in scope; revocation acceptance uses only already-defined authoritative interfaces, while broader grant lifecycle remains later work.

`RemoteSessionReadyV1` means authenticated, confined SFTP byte stream is ready to receive client `SSH_FXP_INIT`; VERSION exchange has not occurred. Order: authenticated request → worker registration → `NamespaceReadyV1` → `RemoteSessionReadyV1` → raw stream → client INIT → server VERSION.
