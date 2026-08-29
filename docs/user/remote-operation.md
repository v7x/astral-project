# Remote operation

Astral's remote path is signed, grant-bound SFTP access. It is not a general
remote shell and it does not accept arbitrary SSH commands.

## Current boundary

The public CLI can probe a host and consume an already issued grant. It cannot
currently perform complete host enrollment or issue/renew grants:

- `aspr host probe USER@HOST` is read-only and reports probe data plus the SSH
  host-key fingerprint.
- `aspr host doctor --probe-file /absolute/record.toml` inspects an existing
  host record.
- `host enroll`, `host update-server`, and `host remove` are not public
  commands. `host update-server` and `host remove` are reserved for a trusted
  enrollment service and are rejected.
- `grant create FILE [ISSUER_KEY]` is accepted as the current import operation;
  it does not create a new grant. Grant issuance, renewal, and authority
  artifact generation are outside the public CLI.

Therefore an operator or trusted enrollment service must first install the
remote bundle, configure its private `server.toml`, install restricted SSH
key material, enroll issuer keys, and issue a signed grant. Do not treat a
successful probe as enrollment.

## Probe remote host

The probe uses the existing OpenSSH configuration, `BatchMode=yes`, and one
fixed POSIX shell script. It writes no remote files:

```sh
uv run aspr host probe remote-user@example-host > /absolute/host-probe.json
```

The target must accept SSH and provide the probe's required shell utilities.
The report records OS, architecture, remote user/home, bubblewrap, user
namespace, SFTP server, SSH authorized-key paths, and capabilities that the
shell probe can establish. Kernel features it cannot establish are reported as
unknown, not supported.

The probe's observed SSH host-key fingerprint must be reviewed and pinned by
the enrollment authority. Never replace it merely because a later connection
reports a different key.

## Import and validate signed grant

After the host has been enrolled and a signed grant plus its issuer public key
have been supplied through a trusted channel, run the broker and import both
files:

```sh
aspr grant import /absolute/grant.cbor /absolute/issuer.pub
aspr grant list
aspr grant validate GRANT_ID
```

The grant must match enrolled host ID, SSH host-key fingerprint, remote user,
issuer, validity window, and server ceiling. A grant is rejected when its
signature, time window, extension policy, or source/access scope fails.

`grant show GRANT_ID` returns the stored signed envelope as base64 CBOR.
`grant revoke GRANT_ID --reason "..."` disables it locally before attempting
any optional remote revocation. An expired or revoked grant cannot create a
new mount; active resources are retired by daemon lifecycle enforcement.

## Session and mount

Mount directory must already exist, be absolute, owned by invoking user, mode
`0700`, and not already be mounted:

```sh
mkdir -m 700 "$HOME/astral-remote"
aspr session open GRANT_ID
aspr ls "GRANT_ID:/" --recursive
aspr mount open "$HOME/astral-remote" /workspace/remote ro
aspr mount list
```

`session open` prints a JSON object containing `session_id`. One active remote
session is allowed. `mount open` selects a signed export by virtual target;
`rw` is allowed only when grant and server ceiling both allow it:

```sh
aspr mount open "$HOME/astral-remote" /workspace/remote rw --read-write
```

Close mounts before closing their session:

```sh
aspr mount close MOUNT_ID
aspr session close SESSION_ID
```

Mount readiness is positive: a mount is usable only after the daemon reports
`state: ready`. A failed mount is not success and must be diagnosed from
`aspr mount show MOUNT_ID`, daemon status, and logs.

## Run sandbox with remote view

A remote view can be created for one command. Source and target paths must be
absolute and normalized. Select the grant explicitly, then omit its prefix
from each remote:

```sh
aspr sandbox --network none \
  --grant GRANT_ID \
  --remote /srv/project=/workspace:ro \
  -- /bin/sh
```

Alternatively, prefix a remote with its grant ID and let the sandbox infer the
selected grant:

```sh
aspr sandbox --network none \
  --remote GRANT_ID:/srv/project=/workspace:ro \
  -- /bin/sh
```

The sandbox owns temporary session and mount cleanup. `--grant GRANT_ID`
without `--remote` is shorthand only when grant has exactly one export; its
view is placed at `/workspace/remote`. All remote entries in one sandbox must
resolve to the same grant.

Inside a remote sandbox, `aspr ls` is the only Astral administrative surface.
It uses the sandbox session socket and cannot list or mutate host-level grants,
sessions, or mounts.

## Remote audit export

After remote enrollment, the local daemon can request bounded, redacted remote
audit data:

```sh
aspr audit export --remote HOST_ID
aspr audit export --remote HOST_ID --hash
```

The remote audit command accepts only its fixed marker, returns at most the
implemented bounded response, and redacts or hashes paths according to the
selected mode.
