# ADR-0026: Packet 37–38 audit and hardening boundaries

## Status

Accepted.

## Decision

Packets 37 and 38 are implemented as one audited scope. Packet 37 covers both local daemon state and remote server state. Both surfaces use the same versioned event vocabulary and preserve provenance across enrollment, grant, session, transport, mount, profile, sandbox, and hardening transitions. Existing private state roots remain authoritative; ownership and restrictive modes are mandatory.

Audit records are validated before persistence. Private keys, credentials, file contents, secret environment values, and secret-bearing command arguments never enter payloads. Export redacts sensitive paths by default; explicit hashing mode is deterministic and intended only for correlation. Malformed legacy events are skipped with an explicit diagnostic rather than crashing the reader. Rotation and retention never weaken permissions or rewrite the trusted event history silently.

Packet 38 is a second wall, never a replacement for mount namespaces or AppArmor. Affected startup fails closed when required Landlock ABI detection or rule loading is unavailable. Failure is still reported through safe doctor/audit status where storage is available. Landlock rules allow only signed/granted roots, minimal runtime dependencies, and standard streams. Capability dropping, `no_new_privs`, rlimits, core-dump suppression, secure temporary files, dependency reporting, and parser-fuzz corpus execution are explicit controls with regression tests.

No Packet 39+ behavior, global AppArmor/sysctl relaxation, compatibility fallback, or policy broadening is part of this scope.

## Consequences

The daemon and remote server must expose enough lifecycle hooks to emit the shared event schema, while event payload validation remains independent of callers. A kernel without Landlock cannot silently receive a weaker session. Operator tooling must distinguish unavailable hardening from successful enforcement and must not reveal redacted values.

## Verification

Focused unit and integration tests cover event schema/versioning, secret exclusion, deterministic redaction and hashing, malformed legacy data, provenance links, retention, Landlock fail-closed behavior, process controls, and secure temporary creation. Installed acceptance on Ubuntu 24.04 and 26.04 records raw results, exact package/source hashes, and preserved Packet 23–36 boundaries.
