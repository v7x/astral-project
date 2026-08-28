# Packets 37–38 handoff

## Gate

Packet 37 gate: HOLD pending final auditor approval.
Packet 38 gate: HOLD pending final auditor approval.

Executable source closure is `4e458d74a83b814e83345cdc4bf3461e930c23c4`; final package is
`d74cb320d368bed08aedc4c2747655af5f4eaa53d7f4cb5eed2a4fb40546e138`. Do not begin
Packet 39. Final acceptance names one committed source tree and one rebuilt
`.deb`; evidence-only commits prove source-tree equivalence.

## Contract

Audit uses one versioned `AuditEvent` vocabulary for local SQLite and remote
JSONL state. Payload schema/allowlist rejects secret-bearing fields and
recognizable secret values. Default export redacts all path-bearing scalar and
collection fields; explicit hash mode uses deterministic SHA-256. Remote audit
writes use a private adjacent inter-process lock. Chain validation is linear,
and count retention is automatic on both stores. Retention preserves retained
event bytes and records append-only immutable digest-boundary segments whose full history is validated.

Remote audit export uses local daemon operation `audit.remote.export` and an
enrolled SSH forced-command marker. Server performs redaction or hashing before
transport; raw export and arbitrary remote paths are not supported.

Landlock minimum ABI is 3. Python and native code handle every filesystem right
through `TRUNCATE`, while fixed root roles control grants: read-only,
regular-writable, socket-runtime, and device-runtime. Socket-runtime roots grant
only traversal/read and socket creation, not regular-file, removal, symlink, REFER,
or truncation rights. Ordinary writable trees do not receive device/socket/FIFO/block
creation. Affected startup fails closed on
unavailable/insufficient ABI, probe, ruleset, rule, restrict-self, or process
control failure and records bounded failure evidence where storage remains
available.

## Required final evidence

- `./scripts/test`, strict mypy, Ruff, focused audit/hardening tests;
- local parser fuzz, strict native builds, AppArmor parser acceptance;
- real-kernel Landlock allowed/outside operation probe on Ubuntu 24.04 and
  Ubuntu 26.04, including unchanged denied targets;
- failure-before-workload probe with stable hardening error and audit event;
- installed sandbox/AppArmor acceptance and direct SFTP read-only/read-write
  acceptance on both releases;
- remote audit lock/mode, redaction/hash, retention/boundary, concurrency, and
  local/remote provenance evidence;
- exact source, package, driver, and raw transcript hashes: source `4e458d74a83b814e83345cdc4bf3461e930c23c4`; package `d74cb320d368bed08aedc4c2747655af5f4eaa53d7f4cb5eed2a4fb40546e138`; Ubuntu 24 raw `e847506e2ad822827a878ded240bed8a90120be124481939620101d8733bb18c`; Ubuntu 26 raw `68732281468196a211193cc638372c05b85e690df7cfe89f503f2d57b5edf934`;
- `git diff --check` and pushed refs equal.
