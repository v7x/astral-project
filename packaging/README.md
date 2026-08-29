# Ubuntu package assets

This directory contains inputs for building Astral Project's current amd64
Ubuntu package. It is not an installer and development commands must not copy
these files into host paths. See [installation](../docs/user/installation.md)
and [administrator setup](../docs/user/setup.md) for user operation.

## Build

```sh
./packaging/debian/build-deb.sh /absolute/output-directory
```

Build script only builds `.deb`; it does not install, enable services, load
AppArmor, or contact another host. It compiles fixed C workers, embeds the pure
Python wheel, and uses target `/usr/bin/python3` plus Ubuntu runtime packages.
The package is currently built for `amd64` and certified only on Ubuntu 24.04
and Ubuntu 26.04.

## Installed layout

- public launchers: `/usr/bin/aspr` and `/usr/bin/astral-project`;
- broker, server, transport, namespace, mount, and sandbox workers:
  `/usr/libexec/astral-project/`;
- broker configuration: `/etc/astral-project/broker.toml`;
- administrator authority and ceilings: `/etc/astral-project/`;
- verified runtime closure: `/var/lib/astral-project/runtime/`;
- socket runtime: `/run/astral-project/`.

Package operation installs root-owned files. The post-install hook creates the broker reachability group and runtime
directories, renders source-root rules when administrator authority already
exists, and loads the fixed AppArmor profile.
It fails when `apparmor_parser` is unavailable; no unconfined fallback exists.

Enable socket activation after installation:

```sh
sudo systemctl enable --now astral-project-broker.socket
```

The socket's `astral-project` group grants reachability only. Signed grants,
`SO_PEERCRED` UID/GID checks, replay protection, source-root ceilings, issuer
keys, host identity, and revocation remain broker checks. Normal sessions do
not require `sudo`.

## Trusted process rules

Production broker, server, transport, namespace, mount, and FUSE launchers
use fixed application paths and Python isolated mode. They remove ambient
`PYTHON*` influence and do not use `uv run`. Fixed native entrypoints are
root-owned and non-writable after installation.

The package does not change global AppArmor policy or user-namespace sysctls,
and does not install setuid or file-capability helpers. It does not create
usable administrator authority or remote enrollment artifacts by itself.
