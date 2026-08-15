# Astral Project — Accomplishments to Date

_Last updated: 2026-08-11_

## Executive summary

Astral Project now has a substantial security-first foundation for granting a remote session narrowly scoped access to host resources. The project has moved from protocol and policy design into a working root broker, descriptor-pinned namespace worker, fixed SFTP runtime closure, AppArmor confinement, Debian packaging, and a passing Ubuntu 26.04 Packet 15F gate.

This document records what exists. It does not imply that the entire long-range project is finished. Later product and operations packets remain open.

## Foundations

- Canonical CBOR protocol encoding and exact-field decoding are implemented.
- Typed identifiers, grants, signed grants, source identities, server ceilings, and stable security errors exist.
- Grant validation covers issuer authorization, host binding, remote-user binding, expiry, nonce handling, export limits, source roots, access modes, object kinds, and policy hashes.
- Deterministic namespace planning maps signed exports to fixed virtual targets and descriptor slots.
- Path resolution uses trusted roots and descriptor-backed source identity checks.
- SQLite state primitives and host/enrollment record structures are present.
- The repository contains explicit architecture and implementation documents under `docs/architecture/caveman/`, packet handoffs, runbooks, and checkpoint reviews.

## Broker and worker security path

The root-owned broker is now a real constrained composition point rather than a design placeholder:

- systemd socket activation and a root-owned Unix broker socket are packaged;
- peer identity is taken from kernel `SO_PEERCRED`, not request bytes;
- only the enrolled UID/GID is accepted;
- requests are bounded, canonical, and authenticated before worker launch;
- the broker transfers exactly one validated Unix stream descriptor;
- replay state binds the signed grant and client nonce and rejects duplicate issuance;
- active sessions are supervised, cancellable, and expiry-bound;
- worker termination is killed, reaped, and staging-cleaned.

The native worker follows the required authority order:

1. create the user namespace;
2. wait for parent-written UID/GID maps;
3. enter broker-created staging;
4. assume the mapped identity;
5. validate the sealed execution plan;
6. verify source descriptor identity and mount evidence;
7. create and privatize the mount namespace;
8. construct the synthetic filesystem from detached mount descriptors;
9. attach the fixed runtime closure;
10. pivot to the synthetic root;
11. transition to the fixed final AppArmor profile;
12. drop setup authority and execute only `sftp_v1`.

No pathname-reopen fallback is used for signed sources.

## Source and capability controls

- Source paths are resolved under the target user's DAC credentials in a short-lived resolver child.
- Descriptors cross back to the root broker through `SCM_RIGHTS`; the broker then clones and re-verifies them before worker handoff.
- Signed source device, inode, filesystem type, and object kind are checked.
- Descriptor replacement after signing/pinning is rejected or rendered harmless by the pinned descriptor.
- Read-only exports reject write/create/truncate attempts.
- Root-owned mode `0700` sources inaccessible to the target user are rejected.
- Detached mount identity is checked before the worker enters the mount namespace.
- Sealed memfd execution plans and fixed descriptor layouts prevent caller-selected executable, argv, environment, mount flags, or profile selection.

## Runtime closure and final workload

The final gate uses the actual OpenSSH `sftp-server`, not a substitute verifier.

- A content-addressed runtime closure is installed under `/var/lib/astral-project/runtime/sftp_v1/`.
- The closure includes the exact loader, SFTP server, required libraries, and generated minimal identity/configuration files.
- Runtime manifests and digests are checked before launch.
- The synthetic root does not expose host `/usr`, `/lib`, or wholesale host `/etc`.
- The installed workload completed an SFTP v3 handshake over the transferred stream.
- The final workload runs under `aspr-sftp-v1 (enforce)`.

## AppArmor and packaging

The Debian package now installs the broker, native workers, runtime Python closure, systemd units, tmpfiles/sysusers definitions, AppArmor policy, and the fixed gate tools.

The packaged policy has been tightened after diagnosis:

- broad temporary `allow mount,` permission was removed;
- broad `/proc/** rw,` diagnostic permission was removed;
- setup mounts are staging-bound and narrowly specified;
- the final profile denies mount, user-namespace creation, capabilities, networking, and socket creation;
- broker-to-final-profile `SIGKILL` signaling is explicitly allowed for expiry supervision;
- no `aa-exec` path is used;
- no global AppArmor or user-namespace restriction was weakened.

Debian purge handling removes generated Python bytecode before package-directory cleanup, so a clean purge/reinstall does not retain interpreter-generated package residue.

## Packet 15F Ubuntu 26.04 acceptance

The final VM-built package was purged and reinstalled on the disposable Ubuntu 26.04 amd64 VM. The following passed from packaged artifacts:

- package installation and clean reinstall;
- AppArmor parser load and enforce-mode profile presence;
- systemd socket activation;
- fixed-runtime SFTP handshake;
- descriptor replacement after pinning;
- read-only export write denial;
- unregistered peer denial;
- UID and GID mismatch denial;
- wrong-user and expired-grant denial;
- replay denial;
- target-user DAC denial;
- final-workload mount, `open_tree`, `mount_setattr`, `move_mount`, nested user-namespace, alternate-root, Unix-socket, and network denial;
- cancellation and expiry worker termination plus staging cleanup;
- the installed `packet15f-gate` evidence command.

Evidence is recorded in:

- `docs/packet-15f-ubuntu-26.04-evidence.md`
- `packaging/matrix/ubuntu-26.04-amd64.json`

Ubuntu 24.04 remains explicitly pending its own release-specific gate.

## Verification state

At the time of this record:

- focused Packet 15F contract: **22 passed**;
- full repository suite: **252 passed, 1 skipped**;
- `git diff --check`: passed;
- packaged AppArmor policy contains no broad diagnostic mount or `/proc` allowance;
- final VM evidence reports Ubuntu 26.04 LTS and kernel `7.0.0-29-generic`.

## Work still open

The project is not yet a complete end-user product. The repository's unresolved-work record still identifies, among other things:

- trusted-process isolated launcher and runtime artifact verification for earlier packets;
- the public daemon/server/transport command tree;
- full transport integration and remote SFTP functional integration;
- grant lifecycle, revocation, and broader state/audit workflows;
- Packet 13 remote capability evidence and portability work;
- full Packet 16 SFTP integration and later rclone/sandbox functionality;
- integrated attack suites, compatibility matrices, packaging operations, and release workflows;
- Ubuntu 24.04's independent Packet 15F gate.

The governing principle remains unchanged: later functionality must not widen the authority already proven in Packet 15F.
