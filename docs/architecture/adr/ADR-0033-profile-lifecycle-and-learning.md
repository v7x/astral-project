# ADR-0033: Persistent profile lifecycle and learning transactions

## Problem

Reusable projected-home policy needs durable lifecycle commands without allowing an
interrupted learning session or editor to corrupt an active profile.

## Chosen design

Profiles remain strict TOML version 1 documents. New lifecycle metadata uses explicit
fields with deterministic defaults: `revision`, `provenance`, `sockets`, `credentials`,
`environment`, and `raw_socket`. Unknown fields and unsupported future versions fail
closed. Profile
files live below a private XDG configuration directory, with one path component per
profile identifier.

Creation is exclusive. Edit writes a private temporary file, invokes the configured
editor without a shell, validates the complete candidate, increments revision, and
atomically replaces the prior file. Learning stages all approvals in an in-memory
draft and commits the complete validated batch as one revision only after successful
learner completion; nonzero exit, exception, cancellation, or teardown failure
leaves the prior revision authoritative. The batch uses the same per-profile lock and
atomic replacement. Export/import round-trips the full
policy document; archive moves the prior file into a private archive directory.
Sealing increments revision and makes learning/editing unavailable until explicit
unseal.

Approval provenance stores bounded source, session, request digest, and timestamp only;
no credential or file content is stored. Learner invocations may pass repeated
`--remote` bindings, but only alongside a selected signed grant; the sandbox daemon
creates and tears down those pre-mounted views.

## Security effect

Interrupted or invalid lifecycle operations leave prior revision authoritative. Profile
IDs cannot redirect storage. Policy meaning is unchanged for existing valid files.

## Rejected choices

- In-place writes permit truncated profiles after interruption.
- Permissive migration hides malformed policy and weakens strict validation.
- Shell editor invocation permits command injection through editor configuration.
- Trace-only learning is not authorization and is not shipped.

## Tests and evidence

`tests/unit/test_profile_lifecycle.py` covers round-trip, revision/provenance,
transactional failures, strict parsing, sealing, editor safety, CLI commands, and
approval persistence. `scripts/profile_boundary_acceptance.py` is the reproducible
installed-package boundary acceptance driver.
