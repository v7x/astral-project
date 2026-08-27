# Profiles and learning

Profiles are local, revisioned policy documents. Profile identifiers are single
path components; profile files are stored below the XDG configuration directory.
A profile may be sealed to make its policy immutable and to hide unknown home
paths.

## Lifecycle commands

```text
aspr profile create ID [--name NAME]
aspr profile list
aspr profile review ID
aspr profile diff ID CANDIDATE.toml
aspr profile edit ID
aspr profile seal ID
aspr profile unseal ID
aspr profile export ID DESTINATION.toml
aspr profile import SOURCE.toml [ID]
aspr profile archive ID
```

`edit` uses the configured safe editor and commits only a valid candidate whose
identifier matches the selected profile. `learn` stages approved rules and
provenance in memory, then commits the complete draft as one revision only when
the learner exits successfully; failure, cancellation, exception, or teardown
failure discards the draft.
Exports and imports require absolute, non-symlink paths and preserve revisions
and approval provenance. Archived profiles are removed from the active list.

## Learner command

```text
aspr profile learn ID -- PROGRAM [ARGUMENT...]
aspr profile learn ID --external -- PROGRAM [ARGUMENT...]
aspr profile learn ID --grant GRANT_ID \
  --remote GRANT_ID:/SOURCE=/TARGET[:ro|rw] \
  -- PROGRAM [ARGUMENT...]
```

`--external` uses the user-owned approval socket supplied by
`ASPR_APPROVAL_SOCKET` (or the session runtime default). Without it, approvals
are made through the trusted interactive terminal controller. A learner may
repeat `--remote` for already-created daemon mounts, but every remote requires
the selected signed grant and is mounted only at its fixed target.

The learner starts the local sandbox, projected home, environment policy,
pathname-socket policy, approval mediator, and optional remote views as one
lifecycle. Unknown paths are denied, hidden, or prompted according to the
profile; an approval is staged after the trusted decision and persisted only
when the learner exits successfully, with non-secret provenance. Sealed profiles
cannot learn. They can still be
restarted for known approved paths without an approval prompt.

Credential-sensitive home rules always require a live strong approval; a
credential rule is never sufficient by itself. Abstract sockets and dangerous
sockets are denied. Raw sockets are disabled by default, and an explicit raw
socket opt-in still requires strong confirmation. Approval displays and
provenance never contain credential contents.
