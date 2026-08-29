# Packets 37–38 handoff

## Gate

Packet 37 gate: HOLD pending final auditor approval.
Packet 38 gate: HOLD pending final auditor approval.

Executable source closure is `a78229342e333dfd5fd063de2ae1f974646227ac`; final package is
`d48f15f9d8267510bebebc886ec5e907e05f6329d0bb176f9803114c861ba5d5`. Do not begin
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
- exact source, package, driver, and raw transcript hashes: source `a78229342e333dfd5fd063de2ae1f974646227ac`; package `d48f15f9d8267510bebebc886ec5e907e05f6329d0bb176f9803114c861ba5d5`; Ubuntu 24 raw `0e80903225262306edd10840b115aa85f44f82681a0d4decbc90e35010aed289`; Ubuntu 26 raw `82569666a4927ef16bcda9ab8ed07611a376023598fe0917fa92d6a5cfed4180`;
- `git diff --check` and pushed refs equal.
