# Packets 28–29 acceptance evidence

This document records the packaged acceptance for the canonical current packet map in ADR-0025.

## Scope

- Packet 28: bounded, fail-closed unknown-path mediation for projected-home access.
- Packet 29: parent-controlled PTY approval terminal and exact-session external approval.
- Later packet work is excluded: profile lifecycle/sealing, private writes, overlays, environment/PATH/FD changes, sockets/credentials, audit, hardening, and authoritative full-path observers.

The observer receives only the minimal `PendingRequest` display object, which carries a bounded `ProvenanceSkeleton` for diagnostics. Observer output and provenance are non-authoritative and cannot grant access. Full host paths remain internal to descriptor-pinned host access and the trusted mediation bridge.

## Local gates

`./scripts/test` passed: 627 tests passed, 1 skipped, and 100% branch coverage. The single skip is the existing optional-runtime skip; packaged FUSE acceptance covers the optional runtime.

Also passed:

```text
uv lock --check
uv run ruff check .
uv run mypy src tests
git diff --check
git diff --cached --check
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-bwrap-launch.c
```

Focused tests cover pending request identity and monotonic numbering, bounded timeout/queue/rate behavior, coalescing, allow-once session caching, deny/hide, opaque traversal/list denial, observer non-authority, remote mediation, exact-session approval, PTY escape/input authority, output buffering caps, resize, SIGINT/SIGTSTP/SIGCONT job control, external approval, terminal cleanup, guard-crash recovery, and sandbox socket absence.

## Packaged Ubuntu acceptance

The raw, inspectable transcripts are:

- `docs/evidence/packet-28-29-ubuntu24-raw.txt`
- `docs/evidence/packet-28-29-ubuntu26-raw.txt`

Both transcripts show:

- release identity and the packaged fixed native launcher path used for the user-facing sandbox probe;
- wheel SHA-256 `220184a69f5fc6a510b11f4304412dfa6716e60bb51faab3b7f53f79d88edef5`;
- strict native launcher compilation, including terminal-safe plan parsing, PTY-safe ASCII plan transport, and owned-FUSE projected-home binding;
- installation of the wheel with the pinned `fuse` extra (`pyfuse3==3.5.0`, `trio==0.31.0`);
- execution as the unprivileged disposable test user with `PYTHONPATH` removed;
- remote trusted mediation, exact-session denial, opaque-ancestor list denial, user-facing `sandbox-projected-mediation` with automatic private mediation socket and Ctrl-] approval, trusted PTY, normal cleanup, explicit `terminal-guard-crash`, and absent sandbox approval socket probes.

Acceptance uses only throwaway fixture files and temporary runtime/socket paths. No real HOME, credentials, or durable host configuration is read or modified.
