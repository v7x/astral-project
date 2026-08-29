# Administrator setup

Package installation creates root-owned service and confinement files. It does
not complete authority setup. Administrator-owned authority is required before
the broker can authorize remote sessions.

## Installed paths

| Purpose | Path |
| --- | --- |
| Public commands | `/usr/bin/aspr`, `/usr/bin/astral-project` |
| Trusted workers and launchers | `/usr/libexec/astral-project/` |
| Broker configuration | `/etc/astral-project/broker.toml` |
| Authority reference | `/etc/astral-project/authority.toml` |
| Per-user ceilings | `/etc/astral-project/ceilings/` |
| Enrolled issuer keys | `/etc/astral-project/issuers/` |
| Runtime closures | `/var/lib/astral-project/runtime/` |
| Broker socket | `/run/astral-project/broker.sock` |

`/etc/astral-project/broker.toml` is a fixed package input. Its supported
values are version `1`, workload `sftp_v1`, backend
`admin_bootstrapped_broker_v1`, and the fixed installed paths. Do not edit
those paths to redirect trusted workers.

## Authority inputs

A complete root-owned `/etc/astral-project/authority.toml` points to a separate
root-owned ceiling file. It must declare:

- expected client UID and GID;
- host ID, remote user, and pinned SSH host-key fingerprint;
- enrolled transport-key IDs;
- enrolled issuer public keys as base64-encoded Ed25519 keys;
- absolute `ceiling_path`.

The ceiling is canonical version-1 CBOR. It independently limits source roots,
export kinds, access mode, issuer IDs, export count, grant lifetime, forbidden
roots, and policy hash. The broker rejects unknown fields, unsafe ownership,
symlinks, non-absolute paths, and invalid permissions.

This repository currently has no public command that generates these authority
artifacts. Obtain them from your trusted administrator/enrollment process. Do
not substitute a hand-written file unless its values and ownership have been
reviewed by that administrator.

## Enable broker reachability

The package creates group `astral-project` and a socket owned by `root` with
that group. Group membership grants socket reachability only; it does not grant
session, source-root, or grant authority.

```sh
sudo usermod --append --groups astral-project USER
sudo systemctl enable --now astral-project-broker.socket
sudo systemctl status astral-project-broker.socket
```

Start a new login session after changing group membership. The broker is
socket-activated. Its service runs as root under systemd restrictions and
AppArmor; ordinary user sessions must not run broker workers with `sudo`.

## AppArmor source-root rules

When authority exists, render its exact source-root include as administrator:

```sh
sudo /usr/libexec/astral-project/render-apparmor-roots
sudo apparmor_parser --replace /etc/apparmor.d/usr.libexec.astral-project.aspr-broker
```

The renderer reads only root-owned authority and ceiling inputs, writes one
fixed root-owned include, rejects unsafe values, and is idempotent. Package
installation loads the fixed sandbox profile. It does not alter global
AppArmor policy or user-namespace sysctls.

## Remote host prerequisites

Remote host setup requires a trusted enrollment operation. The remote host
must have the fixed server bundle, an enrolled issuer public key, a transport
key restricted to the fixed forced command, private `server.toml`, and a
working SSH/SFTP environment. The enrollment must pin the SSH host-key
fingerprint observed during the read-only probe.

Remote `server.toml` lives at:

```text
$HOME/.config/astral-project/server.toml
```

It is version `1`, owned by remote user, and mode `0600` or stricter. It
contains the remote host ID, pinned SSH fingerprint, remote user, enrolled
transport-key IDs, and issuer-key map. The forced key accepts only
`SSH_ORIGINAL_COMMAND=aspr-channel-v1`; it is not general shell access.

Automatic host enrollment is not exposed by current public CLI. See
[remote operation](remote-operation.md) for the currently usable boundary.
