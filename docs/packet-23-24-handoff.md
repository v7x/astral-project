# Packet 23–24 Handoff

## Status

Packets 23–24 passed on Ubuntu 24.04 amd64 and Ubuntu 26.04 amd64.

Acceptance:

- `./scripts/test`: 551 passed, 1 skipped, 100% total coverage (Packet 24A closure).
- Ruff, mypy, `git diff --check`, and JSON validation pass.
- Installed package acceptance returned exit 0 on both releases.
- Final acceptance details: `docs/packet-23-24-acceptance.md`.
- Raw VM output and package hashes: `docs/evidence/packet-23-24-vm-output.txt`.
- Positive and negative matrix: `docs/evidence/daemon-sandbox-matrix.json`.

## Frozen execution boundary

Local sandbox path:

```text
signed/daemon-authorized session state
→ LocalSandboxPlan
→ ASPRSB01 typed stdin plan
→ root-owned fixed aspr-bwrap-launch
→ fixed /usr/bin/bwrap
→ aspr-bwrap-setup AppArmor domain
→ fixed aspr-sandbox-entry
→ stacked aspr-sandbox-payload domain
→ payload with dropped capabilities and NoNewPrivs
```

The launcher accepts no command-line arguments. It independently validates plan magic/version, fields, bounds, command paths, namespace/network mode, remote bindings, mount identity markers, socket path, and trailing bytes. It constructs all bwrap arguments itself. No caller can select bwrap, entrypoint, helper, raw flags, arbitrary capabilities, or network fallback.

`network=none` is literal: bwrap receives `--unshare-net`; payload sees private loopback only, with no host interfaces, routes, DNS, or sockets. `network=inherit` remains explicit and separate.

## Frozen AppArmor boundary

`aspr-bwrap-setup` grants only the capabilities required and observed for distro bubblewrap setup:

- `CAP_SYS_ADMIN`
- `CAP_NET_ADMIN`
- `CAP_SETPCAP`

Setup namespace and mount operations are narrow and audited. `aspr-sandbox-payload` has no capability rules and is stacked at the fixed entrypoint. Package configuration fails closed if profile loading fails; no direct-bwrap or unconfined fallback exists.

Runtime capability evidence comes from kernel AppArmor `AUDIT` records captured after a pre-probe audit serial boundary. Capability parsing is restricted to `operation=capable`; profile text is not treated as runtime evidence. Packet 15’s `aspr-sftp-v1` global `deny unix` boundary remains unchanged.

Installed launcher and entrypoint are `root:root`, mode `0555`, non-setuid, and have no file capabilities.

## Packet 24 semantics retained

The following remain frozen and accepted:

- one signed grant may authorize repeated remotes;
- second grants and target collisions are rejected;
- daemon-created mount markers are required and validated exactly;
- remote views are visible inside sandbox and disappear on cleanup;
- hidden daemon, transport, rclone, credential, and `/dev/fuse` authority remains outside payload;
- session API stays narrow;
- remote loss terminates sandbox and cleans mount state.

## Packet 24A closure findings

Packet 24A remediation is closed. The sandbox cleanup, session API, grant shorthand, descendant selection, Python policy, minimal CI, and RW writeback repair are implemented and locally/installed tested. Installed source-authority negatives explicitly returned `ancestor=rejected`, `sibling=rejected`, and `traversal=rejected` on both Ubuntu releases. Two installed descendant bindings also proved `descendant_scope_isolated=passed`: each binding read its own file while ancestor and sibling files were absent. The installed destructive harness produced independent exact-byte readback for both pinned rclone versions on Ubuntu 24.04 and Ubuntu 26.04; all four runs returned `first_close=closed`, `independent_readback=passed`, and the same 22,020,107-byte SHA-256. Installed expiry, revocation, and explicit forced-close probes returned closed/detached outcomes for every release/pin pair, with expired/revoked sessions recorded as retired. The first empirical failure also exposed a fixed-workload AppArmor create-permission defect; the final profile permits writes only within the already-pinned mount namespace while the mount worker still enforces RO versus RW. `MountManager.close()` drains through a private rclone RC socket, positively rechecks unmount detachment, and returns `DRAINING` with `flush_warning` while preserving live recovery state whenever the queue or detachment cannot be proven. Installed fault-injection acceptance covered queue uncertainty, nonzero unmount failure, and a successful-but-still-attached unmount; each preserved the mount path and returned `DRAINING`. Complete raw JSON/stdout/exit-status evidence is in `docs/evidence/packet-24a-writeback-raw.txt`, `docs/evidence/packet-24a-cleanup-raw.txt`, and `docs/evidence/packet-24a-descendant-raw.txt`.

Packet 25 may begin only from the exact entry point below. No Packet 25–44 implementation was started during this closure.

## Packet 25 entry

Packet 25 begins the projected-home FUSE core. Read the authoritative implementation section at:

- `docs/architecture/plain-english/astral-project-implementation-plain-english.md`, section **Packet 25 — Implement the projected-home FUSE core**;
- `docs/architecture/caveman/astral-project-implementation-caveman.md`, section **Packet 25 — FUSE core**;
- ADR and security constraints in `docs/architecture/` before choosing the FUSE binding.

Packet 25 objective: mount a reliable empty projected home using FUSE before exposing host files.

Required first decisions and work:

1. Choose and pin Python FUSE3 binding and async runtime by ADR; prefer `pyfuse3` with Trio unless testing rejects it.
2. Add internal `aspr homed` mode.
3. Implement mount lifecycle, synthetic inode table, and file-handle table.
4. Implement `lookup`, `getattr`, `open`, `release`, and `forget` with empty/deny behavior.
5. Bound request queue and memory; handle cancellation.
6. Add crash cleanup and stale-mount cleanup.
7. Bind projected mount into sandbox at ordinary `$HOME`; keep admin socket outside sandbox.

Packet 25 completion requires an empty stable filesystem first. Do not expose real host home content, add policy matching, or add host-backed reads in Packet 25; those belong to later packets.

## Explicit exclusions

Do not weaken global AppArmor or security sysctls. Do not install setuid or file-capability helpers. Do not expose raw bwrap flags. Do not add proxy networking, learned profiles, multi-grant sandboxes, FUSE/projected-home features ahead of Packet 25, or production remote bubblewrap in Packets 23–24.
