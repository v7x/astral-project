# ADR-0026: Packet 37–38 audit and hardening boundaries

## Status

Accepted.

## Decision

Packets 37 and 38 are implemented as one audited scope. Packet 37 covers both local daemon state and remote server state. Both surfaces use the same versioned event vocabulary and preserve provenance across enrollment, grant, session, transport, mount, profile, sandbox, and hardening transitions. Existing private state roots remain authoritative; ownership and restrictive modes are mandatory.

Audit records are validated before persistence through one explicit payload schema/allowlist. Private keys, credentials, file contents, secret environment values, secret-bearing command arguments, and recognizable secret values never enter payloads. Export redacts all path-bearing scalar and collection fields by default; explicit hashing mode is deterministic and intended only for correlation. Malformed legacy events are skipped with an explicit diagnostic rather than crashing the reader. A private adjacent lock serializes remote JSONL append/rotation. Chain validation is linear and detects forks. Both local SQLite and remote JSONL use automatic count retention (`AUDIT_RETENTION_LIMIT`), preserve retained event bytes, and record an immutable digest-bound retention boundary rather than rewriting event history.

Packet 38 is a second wall, never a replacement for mount namespaces or AppArmor. Affected startup fails closed below `LANDLOCK_MINIMUM_ABI = 3`, on ABI probe/ruleset/rule/restrict-self failure, or on process-control failure. Failure is still reported through safe doctor/audit status where storage is available. The full ABI-3 filesystem right set is handled. Fixed root roles grant read-only, regular-writable, socket-runtime, or device-runtime authority; ordinary writable trees do not receive device/socket/FIFO/block creation. Capability dropping, `no_new_privs`, rlimits, core-dump suppression, secure temporary files, dependency reporting, and local parser-fuzz corpus execution are explicit controls with regression tests.

Authorized remote audit export uses a narrow local-daemon operation and fixed SSH forced-command marker; the remote server redacts or hashes before transport and exposes no raw mode or arbitrary path. No Packet 39+ behavior, hosted parser-fuzz workflow, global AppArmor/sysctl relaxation, compatibility fallback, or policy broadening is part of this scope.

## Consequences

The daemon and remote server must expose enough lifecycle hooks to emit the shared event schema, while event payload validation remains independent of callers. A kernel without Landlock cannot silently receive a weaker session. Operator tooling must distinguish unavailable hardening from successful enforcement and must not reveal redacted values.

## Verification

Focused unit and integration tests cover event schema/versioning, secret exclusion, deterministic redaction and hashing, malformed legacy data, linear/fork provenance, inter-process locking, automatic shared retention, immutable boundary metadata, authorized remote export, Landlock ABI-3 rights and root-role parity, fail-closed behavior, process controls, and secure temporary creation. Installed acceptance on Ubuntu 24.04 and 26.04 records real-kernel Landlock isolation, failure-before-workload, SFTP, raw results, exact package/source hashes, and preserved Packet 23–36 boundaries.
