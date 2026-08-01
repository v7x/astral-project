# Current Unresolved Issues

## Packet 0

- Trusted-process isolated launcher gate not implemented. `-I`, fixed interpreter/app path, environment sanitization, and artifact-digest verification wait.
- Lockfile protects resolution; runtime artifact verification absent.

## Packet 1

- Hidden `daemon`, `server`, `transport`, and `homed` dispatches are placeholders; they return unavailable.
- CLI supports only `version`; public command tree waits later packets.
- Git revision lookup uses normal `git` discovery; trusted fixed-launch environment not built.

## Packet 2

- UUID4 IDs intentionally unsortable. ADR-0002 records constraint.
- Config loader enforces top-level unknown fields only; future nested schemas must enforce same rule.
- Local path helpers use pathname operations; remote resolver is descriptor-pinned, but staging mount gate remains blocked in Packet 13.

## Packet 3

- Immutable Python bytes and cryptography key objects cannot promise zeroization. Mutable temporary buffers clear.
- Grants carry claimed source identity; remote revalidation and descriptor pinning absent until Packets 12–13.
- No grant lifecycle, revocation, expiry session enforcement, or server policy yet.

## Packet 4

- Database schema exists; repository APIs, lifecycle operations, audit policy, and revocation behavior remain unimplemented.
- `audit_events` has no append-only enforcement yet; Packet 37 owns audit system.
- WAL/SHM sidecars check during initialization, not after every later transaction-created sidecar.
- Crash test proves uncommitted transaction recovery. Post-commit crash semantics lack separate test.
- Destructive backups have no retention, restore command, or operator workflow yet.

## Packet 13

- Descriptor-pinned staging probe now reports each namespace, resolver, and mount-syscall stage. Remote AppArmor evidence is pending. Do not infer cause from outer `EPERM`, and do not continue to Packet 14 until probe passes on named enrolled host.
- No pathname-reopen fallback is permitted.

## Global gates still open

- Python runtime injection gate.
- Transport gate: Packets 10/11.
- Descriptor-pinned mount gate: Packet 13.
- SFTP runtime gate: Packet 16.
- Integrated learner, attack suites, compatibility matrices, packaging, and operations.
