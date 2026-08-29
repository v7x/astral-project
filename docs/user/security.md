# Security model

Astral Project gives coding agents bounded file authority instead of general
host access. Security decisions are made by fixed code paths and independently
checked policy, not by a caller-supplied shell command or arbitrary sandbox
flags.

## Local boundary

A sandbox requires explicit network mode. `none` removes network access;
`inherit` preserves it. Environment, pathname sockets, projected home, and
remote views are separately constructed from fixed policy.

A profile is a local revisioned policy document. Its files and parent
directories must be owned by the current user and private. Unknown paths are
not silently granted. Learning approval is mediated, recorded with bounded
non-secret provenance, and persisted only after successful learner completion.
Credential-sensitive paths require live strong approval; credential contents
are never placed in approval displays or provenance.

Profile rules distinguish host read-only, exact host execution, private write,
overlay write, and denial. Exact rules do not grant directory listing unless
`list = true`. Sealed profiles cannot be learned or edited and hide or deny
unknown paths according to their sealed policy.

Abstract sockets, dangerous Docker/Podman sockets, and raw sockets are not a
way around profile authority. Profile-driven sandbox startup rejects raw socket
opt-in.

## Remote boundary

Every remote session uses a signed grant. The grant binds:

- host identity;
- SSH host-key fingerprint;
- remote user;
- validity window;
- issuer key;
- exported source paths, virtual targets, object kinds, and access modes.

The remote server verifies the grant before path work or SFTP negotiation. The
root broker independently checks the grant against administrator-owned source
root ceilings, forbidden roots, allowed issuers, export count, maximum lifetime,
and policy hash. A grant cannot widen a server ceiling.

Remote SSH keys are restricted forced-command entries. The accepted command is
exactly `aspr-channel-v1`; no general shell, PTY, port forwarding, agent
forwarding, or X11 forwarding is granted. The installed remote workload is
fixed SFTP. It has no network, mount, capability, or arbitrary-execution allow
rule.

Remote mount access requires a broker session. Mount directories are existing
private directories owned by invoking user. Mounts become usable only after
positive readiness. Revocation and expiry prevent new use and are enforced by
daemon lifecycle handling; close and writeback failures are reported rather
than declared clean.

## Administrator boundary

The broker is root-owned and socket-activated. Membership in group
`astral-project` gives reachability to its socket, not authority to choose
source roots, issuers, remote hosts, or capabilities. The broker authenticates
peer UID/GID and reads only root-owned configuration and ceiling artifacts.

Package trusted launchers use fixed interpreter/application paths with Python
isolated mode. Development `uv run` must not be used as a production trusted
launcher. Package installation does not weaken global AppArmor policy or user-
namespace sysctls and does not install setuid or file-capability helpers.

## Trust assumptions

You must trust the administrator who creates ceilings, issuer keys, authority
artifacts, and remote enrollment. Protect transport private keys, issuer
private keys, grant files, profile files, approval sockets, and SSH host-key
pinning. A successful host probe is evidence, not enrollment; review its
fingerprint through a trusted channel before authorizing a host.

Astral does not make an untrusted kernel, root administrator, SSH host, or
issuer trustworthy. It constrains authority after those trust decisions.
