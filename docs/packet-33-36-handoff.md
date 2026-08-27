# Packets 33–36 handoff

## Delivered

- `aspr profile` lifecycle: create, review, diff, safe edit, seal/unseal, list,
  export/import, archive, revision and approval provenance. Per-profile transactions
  serialize revision validation and replacement, preserving concurrent learning rules.
  Learner approvals remain in an in-memory draft and commit as one revision only after
  successful completion; failed, cancelled, exceptional, or teardown-failed runs discard it.
- Strict profile schema evolution with deterministic defaults and fail-closed
  unknown/future fields.
- Environment allowlist, explicit unset list, secret-name filtering, visible PATH
  filtering propagated through the native launcher, descriptor inventory/closure
  helpers, and the same secret/PATH boundary for rclone and SSH subprocesses.
- Exact pathname socket and credential policy. Abstract and dangerous sockets deny by
  default; credential-sensitive sockets and home rules require strong confirmation,
  with redacted diagnostics.
Raw sockets are disabled by default and remain gated by explicit strong confirmation.
- Fixed native sandbox ABI now carries approved socket binds and closes unlisted
  descriptors before bubblewrap execution.
- Integrated learner API and command:
  `aspr profile learn agents-default -- any-program`
  with `--external` mode, trusted mediation, persistent approved rules, private or
  overlay writable state, repeated signed-grant `--remote` bindings, and sealed-session
  denial.
- Packet 36A closes the integrated learner findings: one composite FUSE inode and
  handle namespace dispatches host/private/overlay operations; cross-root rename
  fails with `EXDEV`; opaque ancestors permit lookup/stat of sealed descendants but
  reject enumeration; mediated terminal transport has no external approval authority
  without `--external`; and host-rx executes one exact profile-approved projected-home
  command while the projected HOME mount remains `noexec`.
- The packaged closure declares `python3-pyfuse3` beside `python3-cbor2` and
  `python3-cryptography`; Ubuntu 24.04 no longer relies on an ambient `/usr/local`
  extension.

## Acceptance

Run unit and integration gates from `docs/evidence/packet-33-36-acceptance.md`.
Packaged profile/resource acceptance uses `scripts/profile_boundary_acceptance.py`.
Projected-home FUSE acceptance uses `scripts/writable_home_acceptance.py`.
Integrated learner acceptance uses `scripts/learner_acceptance.py` for external
approval and `scripts/learner_interactive_acceptance.py` for trusted terminal approval.
The learner driver also proves reuse from a distinct second home/project with the
same persisted profile, sealed known-path restart, and unrelated-home hiding; remote
binding forwarding is covered by the learner and packaged CLI gates.
Ubuntu 24.04 and Ubuntu 26.04 transcripts belong in corresponding raw evidence files.
The final Packet 36A artifact SHA-256 is
`b02da997a875c721c2bdb550ed6819ae29d083cc147e44c5cde54f2d4607d498`;
its raw learner/host-rx and final Packet 23–24 confinement outputs are recorded in
`docs/evidence/packet-33-36-ubuntu24-raw.txt` and
`docs/evidence/packet-33-36-ubuntu26-raw.txt`. Both releases passed external
approval, persistence/reuse, sealing, unrelated-home hiding, projected-HOME
`noexec`, exact host-rx, unapproved-host-rx denial, and the installed native
confinement harness.

## Boundaries

Packets 37+ remain out of scope. Observer output is diagnostic only. No full broker,
abstract socket support, ambient environment inheritance, or real-home writable
passthrough is introduced. No supplied Packet 36A security or correctness finding
remains open.
