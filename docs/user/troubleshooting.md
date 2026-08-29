# Troubleshooting

Start with version and status evidence. Keep diagnostics from standard error.

```sh
aspr version
aspr version --json
aspr doctor
aspr audit list
```

`doctor` and lifecycle commands need the broker socket. `version` does not.

## Command rejected

Astral does not implement general `--help`; use [CLI reference](reference.md).
Strict public-dispatch and command-shape errors normally return status `2`.
Sandbox parsing and validation errors return status `70`, as do operational,
dependency, authentication, configuration, and security failures. Check
positional order and the exact `--` separator for `sandbox` and `profile learn`.
Some handlers are permissive about extra arguments, so a command that exits
successfully after ignoring an argument does not make that argument supported.

Read the structured `ASPR_*` code, `Security result`, `Why`, and `Fix` lines on
standard error.

## Missing XDG environment

`HOME` and `XDG_RUNTIME_DIR` are required absolute paths. `XDG_CONFIG_HOME`
and `XDG_STATE_HOME` default below `HOME`, but any supplied value must also be
absolute.

```sh
printf 'HOME=%s\nXDG_RUNTIME_DIR=%s\n' "$HOME" "${XDG_RUNTIME_DIR-}"
test -n "${XDG_RUNTIME_DIR-}" && test -d "$XDG_RUNTIME_DIR"
```

Fix the environment before retrying. Do not point trusted state at a shared or
user-writable path owned by another user.

## Profile or approval failure

Check profile syntax and permissions:

```sh
PROFILE="$HOME/.config/astral-project/profiles/agents-default.toml"
stat -c '%U %a %n' "$PROFILE" "${PROFILE%/*}"
aspr profile review agents-default
```

Profile files/directories must be private to current user. A sealed profile
cannot be edited or learned. Profile learning needs Linux FUSE support and
`pyfuse3`/`trio`; install source optional extra with `uv sync --locked
--all-groups --extra fuse`.

For external approval, verify `ASPR_APPROVAL_SOCKET` is absolute, exists when
the controller expects it, and is not exposed to another user. A missing or
stalled controller leaves unknown-path requests unresolved; it does not grant
access.

## Broker unavailable

Check socket and service state as administrator:

```sh
sudo systemctl status astral-project-broker.socket astral-project-broker.service
sudo journalctl -u astral-project-broker.service --no-pager -n 100
stat -c '%U %G %a %n' /run/astral-project/broker.sock
aspr doctor
```

If package configuration failed, inspect AppArmor and dependency availability:

```sh
command -v apparmor_parser
sudo apparmor_status
command -v bwrap
/usr/bin/python3 --version
```

Repair package prerequisites, then reinstall or reconfigure package. Do not
bypass AppArmor or replace fixed launchers with `uv run`.

## Grant or session failure

```sh
aspr grant list --all
aspr grant show GRANT_ID
aspr grant validate GRANT_ID
aspr session list
```

A grant can fail because signature, issuer, host ID, SSH fingerprint, remote
user, validity window, extension policy, revocation, or administrator ceiling
does not match. Import the grant with its correct issuer public key. Only one
active remote session is supported; close stale sessions before opening another.

## Mount failure

Mount path must be an existing absolute directory, owned by current user, mode
`0700`, and not already mounted:

```sh
mkdir -m 700 "$HOME/astral-remote"
stat -c '%U %a %n' "$HOME/astral-remote"
aspr mount list
aspr mount show MOUNT_ID
```

Remote mount also requires an enrolled host, valid SSH identity file, working
SFTP server, bubblewrap/runtime closure, and a running broker. A mount that is
not `ready` is unusable. Do not report it as successful.

If close reports a flush warning or remains `draining`, preserve mount path and
state. Investigate remote connectivity and writeback before removing files.

## Remote enrollment failure

`aspr host probe USER@HOST` changes no remote files. It can fail on SSH
connectivity, missing remote shell utilities, missing `python3`, missing
`bwrap`, failed user namespaces, or absent SFTP server. `aspr host doctor
--probe-file FILE` requires an existing valid host record.

A probe does not enroll a host. Current public CLI has no host enrollment,
grant issuance, or authority-artifact generator. If remote setup stops after
probe, contact the trusted enrollment/administrator process; do not improvise a
replacement shell command or SSH key entry.

## Audit evidence

```sh
aspr audit list
aspr audit export
aspr audit export --hash
```

Audit output is redacted by default. Hash mode preserves path correlation
without printing path text. Broken chain evidence or missing remote export is a
failure to investigate, not proof that operation succeeded.
