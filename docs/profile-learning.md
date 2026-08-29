# Profiles and learning

This page is retained as a focused reference. Full user workflow is in
[local sandbox and profiles](user/local-use.md); command syntax is in the
[CLI reference](user/reference.md).

Profiles are local, revisioned policy documents stored below
`$XDG_CONFIG_HOME/astral-project/profiles/`, or `$HOME/.config/astral-project/profiles/`.
Profile IDs are single path components. Profile files and directories are
private to invoking user.

## Lifecycle commands

```sh
aspr profile create ID [--name NAME]
aspr profile list
aspr profile review ID
aspr profile diff ID /absolute/CANDIDATE.toml
aspr profile edit ID
aspr profile seal ID
aspr profile unseal ID
aspr profile export ID /absolute/DESTINATION.toml
aspr profile import /absolute/SOURCE.toml [ID]
aspr profile archive ID
```

`edit` uses `$EDITOR` or `vi`, validates candidate TOML, and commits a new
revision only when valid. Sealed profiles cannot be edited or learned.
Import/export require absolute, non-symlink paths. Archived profiles leave the
active list but remain in the private archive directory.

## Learner

```sh
aspr profile learn ID -- PROGRAM [ARGUMENT...]
aspr profile learn ID --external -- PROGRAM [ARGUMENT...]
aspr profile learn ID --grant GRANT_ID \
  --remote GRANT_ID:/SOURCE=/TARGET[:ro|rw] \
  -- PROGRAM [ARGUMENT...]
```

Learning runs command inside local sandbox with `--network none`, profile
projected home, and interactive unknown-path mediation. `--external` uses
`ASPR_APPROVAL_SOCKET` when set; otherwise it uses session runtime default.
Remote learning requires an already imported grant and one or more matching
`--remote` entries.

Unknown-path `ALLOW_ONCE` approvals become exact host-read or exact host-exec
rules with non-secret provenance. Draft rules persist only after successful
learner exit. Failure, cancellation, or teardown failure discards draft.
Credential-sensitive access always needs live strong approval. Approval output
and provenance never contain credential contents.

The learner needs Linux FUSE support and the optional `fuse` dependencies. A
sealed profile can run known approved paths but cannot accept new learning.
