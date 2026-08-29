# Astral Project

Astral Project gives coding agents bounded file access instead of general host
authority. It constrains local commands and remote SFTP views with explicit
network policy, profile rules, signed grants, administrator ceilings, and
fail-closed lifecycle checks.

Current release is `0.1.0` and pre-alpha. Read [installation](docs/user/installation.md)
before use.

## Human Notes from the author, Andrew Mack @v7x

Astral Project was almost exclusively AI developed - I gave the clanker an idea of what I wanted, discussed how I wanted it to feel to use and what my security concerns were, and bantered about the architecture before asking it to develop a plan for implementation I could feed to an coding agent. As development progressed I continued to discuss the project with an architecting agent ensuring progress was being made in a direction I deemed viable for release, but I allowed it to lead. This development style was largely an experiment on my part for my own purposes, as most of my work with AI development to this point was on modifying pre-existing codebases rather than creating anything substantial from scratch. All of this is to say that while AI tools are very impressive and useful they are not perfect - there may be blind spots here I have not yet reveiwed.

Inspiration for this project arose from my experience administrating high performance compute (HPC) clusters where the files I needed to access and work on often sat on servers that also had access to sensitive proprietary data. I didn't want to risk inadvertantly exposing that data to AI tools who may record everything they see and send it back to their vendors - even if such behavior is rare (which I doubt) both I and the customers I serve need assurance it won't happen. I needed a tool that would allow me to project the remote files I need to an agent I run locally without risk of exposing other files on the system, especially through malicious means. Astral Project is the solution to that problem.

Currently only Ubuntu 24 and 26 are supported as both host and client, but I fully intend to add support for Fedora, RHEL and its clones like Rocky and Alma, Debian, and possibly even MacOS and beyond. If you think this tool would be useful to you and would like to help out please start testing vigorously. If you have additions or changes you'd like to make, please let me know by opening an issue and we can discuss contribution. I do not expect the pre-alpha to last long, and alpha only as long as it takes to get a few more supported linux distributions under our belt. Beta will last as long as is needed to ensure the codebase is reasonably secure. I'm a one-man team at the moment and while I hope to bring on some help I can't say how long it all will take me, but I fully intend to see development of this tool through. With that, I'd like to thank you for your interest and hope Astral Project can make your life just a bit easier.

## Current support

| Use | Current support |
| --- | --- |
| Certified packaged operation | Ubuntu 24.04 amd64 and Ubuntu 26.04 amd64 |
| Source development/testing | Linux with Python 3.12 or newer |
| Other distributions, macOS, Windows, architectures | Not supported |

The certified package path requires AppArmor, systemd, bubblewrap, FUSE, and
Ubuntu runtime packages for `cbor2`, `cryptography`, and `pyfuse3`. Passing
source tests or package metadata does not certify another platform.

## What works now

- local sandbox execution with explicit `inherit` or `none` network mode;
- revisioned projected-home profiles and interactive approval learning;
- signed, time-bounded remote grants and daemon-managed SFTP mounts;
- redacted local and bounded remote audit export;
- root-owned broker authority and independently enforced source-root ceilings.

Remote use requires prior trusted host enrollment and an issued signed grant.
Current public CLI can probe a host and import a grant; it does not expose
complete host enrollment, grant issuance/renewal, or authority-artifact
generation. See [remote operation](docs/user/remote-operation.md).

## Quick source start

```sh
uv sync --locked --all-groups --extra fuse
export XDG_RUNTIME_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
test -d "$XDG_RUNTIME_DIR"
uv run aspr version
uv run aspr profile create agents-default
```

Source commands can inspect and manage profile/state data and run repository
checks. Executable sandbox and profile-learning workflows require the fixed
native launchers installed by the package. See [local use](docs/user/local-use.md)
for operation. `uv run` is development-only; trusted package processes use
fixed isolated launchers.

## User documentation

- [Installation and package build](docs/user/installation.md)
- [Administrator and remote-host setup](docs/user/setup.md)
- [Local sandbox and profiles](docs/user/local-use.md)
- [Remote operation](docs/user/remote-operation.md)
- [CLI and configuration reference](docs/user/reference.md)
- [Security model](docs/user/security.md)
- [Troubleshooting](docs/user/troubleshooting.md)

## Explicit exclusions

Astral does not currently provide generic remote shell access, arbitrary SSH
commands, automatic public host enrollment, public grant issuance, support for
uncertified platforms, or a fallback that disables AppArmor or security
sysctls. Do not infer future platform work from architecture or packet files.
