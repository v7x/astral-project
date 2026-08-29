# Local sandbox and profiles

Local sandbox execution is explicit. `--network inherit` preserves network
access; `--network none` disables it. No network mode is implicit.

## Run command without profile

After package installation (or from an environment containing its fixed native
launchers):

```sh
aspr sandbox --network none -- /bin/true
aspr sandbox --network inherit -- /usr/bin/env
```

The command's standard output and standard error pass through. Exit status is
normally the command's status. Astral rejects malformed requests or failed
security setup with an error, normally exit status `70`.

## Create and inspect profile

Profile IDs are one path component. Profiles are stored below
`$XDG_CONFIG_HOME/astral-project/profiles/`, or
`$HOME/.config/astral-project/profiles/` when `XDG_CONFIG_HOME` is unset.
Profile and state directories are private to the invoking user.

```sh
aspr profile create agents-default --name "Coding agents"
aspr profile list
aspr profile review agents-default
```

A profile starts with no home rules. Unknown home paths are prompted during
learning and hidden when a sealed profile is used. A profile rule can expose a
host path read-only, authorize exact host execution, provide private or
overlay write access, or deny access. Directory listing is separately
controlled by a rule's `list = true` field.

## Learn, then seal

After package installation, learning requires FUSE projected-home support and
an existing profile:

```sh
aspr profile learn agents-default -- /bin/sh
aspr profile review agents-default
aspr profile seal agents-default
```

During learning, unknown paths are mediated. `ALLOW_ONCE` approvals become
exact rules and non-secret approval provenance. Denials do not become rules.
The complete draft is committed only when the learner exits successfully;
failure, cancellation, or teardown failure leaves the prior profile revision
active.

A sealed profile cannot be edited or learned. It can still run known approved
paths:

```sh
PROFILE="$HOME/.config/astral-project/profiles/agents-default.toml"
aspr sandbox --network none \
  --profile "$PROFILE" --home-root "$HOME" -- /bin/sh
```

Use `XDG_CONFIG_HOME` in `PROFILE` when configured. `--profile` and
`--home-root` must be supplied together. A profile-driven sandbox needs a
working Linux FUSE environment; without it Astral reports that host projected
home is unavailable.

## Profile maintenance

```sh
aspr profile edit agents-default
aspr profile diff agents-default /absolute/candidate.toml
aspr profile export agents-default /absolute/export.toml
aspr profile import /absolute/export.toml
aspr profile unseal agents-default
aspr profile archive agents-default
```

`edit` uses `$EDITOR`, defaulting to `vi`, and commits only valid TOML. Import
and export require absolute, non-symlink paths and private files. `archive`
removes a profile from the active list but retains an archive copy under the
private profile directory.

## Approval sockets

The normal learner uses its trusted interactive terminal controller. External
approval uses:

```sh
export ASPR_APPROVAL_SOCKET=/absolute/path/approval.sock
aspr profile learn agents-default --external -- /bin/sh
```

The external controller must own and service that socket. If the variable is
absent, external learning uses a session runtime default. Do not expose the
socket to another user.

Remote mounts can be added to learning only with one selected signed grant and
matching `--remote` values; see [remote operation](remote-operation.md).
