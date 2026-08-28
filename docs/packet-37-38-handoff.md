# Packets 37–38 handoff

## Gate

Packet 37 gate: HOLD pending final auditor approval.
Packet 38 gate: HOLD pending final auditor approval.

Executable source closure is `631c2ee3483b36b0b28a2f87c2a8e6add02a6463`; final package is
`18cf3cdc9bdd7b08d017fd5e02a2c565b3092af6c8ed9fd16148417d7f6ffb1e`. Do not begin
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
- exact source, package, driver, and raw transcript hashes: source `631c2ee3483b36b0b28a2f87c2a8e6add02a6463`; package `18cf3cdc9bdd7b08d017fd5e02a2c565b3092af6c8ed9fd16148417d7f6ffb1e`; Ubuntu 24 raw `743d6bed56442ed231956699fdbd24c42aa084915e478626e4b4c94b3adcb615`; Ubuntu 26 raw `c37d65c49f5e838549fbbf4c1b5b7017e5f8d27ca96590d7e5ecc0f935865c37`;
- `git diff --check` and pushed refs equal.
