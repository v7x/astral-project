# Packets 37–38 handoff

## Gate

Packet 37 gate: HOLD pending final auditor approval.
Packet 38 gate: HOLD pending final auditor approval.

Executable source closure is `4d97d38b153156304baaae566ac778bdfa5a9a09`; final package is
`c985e3cc0cfcd7e67dfdf3d2b9f943c5b2c32cc4a98e34b378bde6a1696b4fd6`. Do not begin
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
regular-writable, socket-runtime, and device-runtime. Ordinary writable trees do
not receive device/socket/FIFO/block creation. Affected startup fails closed on
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
- exact source, package, driver, and raw transcript hashes: source `4d97d38b153156304baaae566ac778bdfa5a9a09`; package `c985e3cc0cfcd7e67dfdf3d2b9f943c5b2c32cc4a98e34b378bde6a1696b4fd6`; Ubuntu 24 raw `831327bb255ba277be20108aa93746db83f92249ef17f5bdc62ab7bb667ed938`; Ubuntu 26 raw `6d253511c831198a09d4c6ab429a1b6024308158aea5d617f88c0789ad298244`;
- `git diff --check` and pushed refs equal.
