# Installation

Astral Project has two distinct use paths:

- **Certified package use:** Ubuntu 24.04 or Ubuntu 26.04, amd64. This is
  current production support. The package requires AppArmor, systemd,
  bubblewrap, Python 3.12 or newer, and Ubuntu packages for `cbor2`,
  `cryptography`, and `pyfuse3`.
- **Source use:** Linux development and manual testing with Python 3.12 or
  newer. Source use is not a production launcher or a certification claim for
  another distribution.

Windows, macOS, other distributions, and other architectures are not current
support claims.

## Source environment

Install `uv`, a C compiler if native package work is needed, and repository
sources:

```sh
git clone <repository-url>
cd astral-project
uv sync --locked --all-groups --extra fuse
```

`--extra fuse` installs optional projected-home dependencies. It is required
for profile-driven projected homes and profile learning. Source profile/state
commands and repository tests run from the checkout; executable sandbox and
profile-learning workflows also require fixed native launchers from the
Ubuntu package.

Before running profile, daemon, or sandbox commands, `HOME` and
`XDG_RUNTIME_DIR` must be set to absolute paths. `XDG_CONFIG_HOME` and
`XDG_STATE_HOME` are optional:

```sh
: "${HOME:?HOME must be set}"
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
test -d "$XDG_RUNTIME_DIR"
uv run aspr version
uv run aspr version --json
```

Do not replace `uv run` with a trusted production launcher. The development
launcher may use the checkout and development environment; trusted package
processes use fixed paths and Python isolated mode.

## Build and install Ubuntu package

Package building is not installation. Build from the repository on a system
with `uv`, `cc`, `dpkg-deb`, and `/usr/bin/python3`:

```sh
uv sync --locked --all-groups --extra fuse
mkdir -p /absolute/package-output
./packaging/debian/build-deb.sh /absolute/package-output
```

The script writes an amd64 `.deb`. It does not install files, enable services,
load AppArmor, or contact another host.

On a certified Ubuntu target, install as administrator:

```sh
sudo apt install /absolute/package-output/astral-project_0.1.0_amd64.deb
sudo systemctl enable --now astral-project-broker.socket
sudo systemctl status astral-project-broker.socket
```

Package configuration fails if `apparmor_parser` is unavailable. The package
also needs working systemd, AppArmor enforcement, bubblewrap, FUSE support,
and declared Ubuntu runtime packages. Installation alone does not create
administrator authority, source-root ceilings, issuer keys, or remote host
enrollment. Complete [administrator setup](setup.md) before remote operation.

The package installs the public commands as both `aspr` and
`astral-project`. They invoke the same CLI.
