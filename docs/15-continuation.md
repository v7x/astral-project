# Astral Project: Packets 15C–15F Implementation Handoff

**Status:** Planning decision and implementation contract  
**Applies after:** Packet 15B descriptor-pinned mount worker  
**Blocks:** Packet 16 full SFTP integration  
**Primary target:** Ubuntu 24.04 LTS  
**Administrator model:** One-time installation and upgrades only; no administrator involvement during normal sessions

> This document replaces the former ordering in which the SFTP runtime closure was owned entirely by Packet 16. The runtime closure is a prerequisite for proving confinement of the actual final workload, so it moves before the external Ubuntu gate.

---

## 1. Planning decision

Choose the runtime-closure split.

The new order is:

```text
15B  Descriptor-pinned mount worker
15C  Minimal fixed sftp_v1 runtime closure
15D  Final namespace, authority drop, and fixed sftp_v1 execution
15E  systemd and AppArmor packaging
15F  External Ubuntu security gate
16   Full SFTP functional acceptance and integration
```

Do not use a non-SFTP verifier for the final confinement gate. Packet 15F must test the actual `sftp_v1` workload inside the synthetic root.

Do not run `sftp-server` against the host root, host `/usr`, or host `/etc`.

---

## 2. Security decisions frozen by this handoff

1. The broker runs as root and is started by systemd socket activation.
2. The remote `aspr-server` process runs as the enrolled remote user.
3. The broker authenticates the connecting process with `SO_PEERCRED`.
4. Socket group membership grants reachability only. It grants no namespace authority by itself.
5. The broker independently validates:
   - signed grant;
   - issuer authorization;
   - host and UID binding;
   - expiry;
   - replay state;
   - server ceiling;
   - source-root authority;
   - fixed workload identity.
6. Source resolution occurs under the target user’s DAC authority.
7. Root DAC bypass must not make an otherwise inaccessible source grantable.
8. Source objects are pinned before mount construction.
9. The mount worker receives pinned descriptors, not free-form source path authority.
10. The only workload in this track is the enum `sftp_v1`.
11. No request may select an executable, argv, environment, AppArmor profile, bwrap flags, staging root, or arbitrary mount flags.
12. The internal execution plan is passed through a sealed `memfd` and inherited descriptors.
13. A separate internal plan signature is not required unless a later ADR proves that fork/exec plus sealed descriptors is insufficient.
14. The final workload receives:
    - no mount capability;
    - no new-user-namespace authority;
    - no ability to modify the staging topology;
    - no network authority;
    - no shell.
15. AppArmor confines components. AppArmor does not authenticate callers.
16. No `aa-exec` design is permitted.
17. No global AppArmor or user-namespace restriction is disabled.
18. No pathname-reopen fallback is permitted.

---

## 3. Packet definitions

## Packet 15C — Minimal fixed `sftp_v1` runtime closure

### Objective

Build a content-addressed runtime closure that can start the exact OpenSSH `sftp-server` workload inside an otherwise empty filesystem namespace.

### Prerequisites

- Packet 15B is complete.
- The target architecture and libc are known.
- The exact `sftp-server` binary and dynamic loader have been discovered.
- Runtime artifacts are built or collected in a trusted build environment.

### Deliverables

1. A deterministic runtime-closure builder.
2. A canonical runtime manifest.
3. Digest verification for every runtime object.
4. Explicit dynamic-loader invocation.
5. Minimal generated identity files when required:
   - `etc/passwd`;
   - `etc/group`;
   - `etc/nsswitch.conf`.
6. An empty-namespace SFTP handshake smoke test.
7. Tests for:
   - loader resolution;
   - shared-library closure;
   - NSS behavior;
   - locale behavior;
   - logging behavior;
   - randomness requirements;
   - mapped UID/GID identity;
   - missing-file failure.
8. Atomic runtime installation and rollback.

### Required layout

```text
/var/lib/astral-project/runtime/sftp_v1/<manifest-digest>/
├── manifest.cbor
├── manifest.toml
├── ld.so
├── sftp-server
├── lib/
│   └── <exact required libraries>
└── etc/
    ├── passwd
    ├── group
    └── nsswitch.conf
```

The `etc` files are generated specifically for the workload. They are not copied wholesale from the host.

### Constraints

- No bind of host `/usr`.
- No bind of host `/lib`.
- No bind of host `/etc`.
- No unexplained file in the closure.
- No lookup through ambient `LD_LIBRARY_PATH`.
- No caller-supplied loader, entry point, argv, or environment.
- No network access while building or running the installed closure.
- No grant may target or overlap `/.astral-project-runtime`.

### Acceptance criteria

- The manifest is deterministic.
- Every listed digest verifies.
- An unlisted or modified file causes failure.
- The runtime starts in an empty namespace.
- The runtime reaches an SFTP protocol handshake over standard input/output.
- Removing any required file causes a clear failure.
- Adding an unexplained file causes manifest validation failure.
- The smoke test uses the fixed workload and fixed argv.
- Full filesystem semantics are deferred to Packet 16.

### Handoff

Record:

- target architecture;
- libc family and version floor;
- loader path;
- `sftp-server` build identity;
- exact runtime file list;
- manifest digest;
- smoke-test transcript;
- unresolved portability issues.

---

## Packet 15D — Final namespace, authority drop, and fixed `sftp_v1` execution

### Objective

Construct the complete synthetic root, install the runtime closure, remove setup authority, and execute `sftp_v1` as the final confined workload.

### Prerequisites

- Packets 15B and 15C are complete.
- `ExecutionPlanV1` is frozen.
- The fixed workload enum and runtime manifest are frozen.

### Deliverables

1. Synthetic-root construction from pinned mounts.
2. Fixed runtime attachment at:

```text
/.astral-project-runtime
```

3. Private mount propagation.
4. Minimal synthetic `/dev` only when tests require it.
5. No host `/proc`, `/sys`, `/etc`, home, policy, keys, or unrelated mounts.
6. Descriptor allowlist and closure.
7. Environment allowlist.
8. Capability drop.
9. `no_new_privs`.
10. Fixed AppArmor transition into `aspr-sftp-v1`.
11. Fixed loader invocation:

```text
/.astral-project-runtime/ld.so
    --library-path /.astral-project-runtime/lib
    /.astral-project-runtime/sftp-server
    -e
    -l
    INFO
```

12. Parent supervision and child termination.
13. Negative tests after transition.

### Constraints

The final workload must not be able to:

- call `mount`;
- call `open_tree` with clone authority;
- call `mount_setattr`;
- call `move_mount`;
- create a new user namespace;
- alter the completed mount topology;
- execute another program;
- open a network socket;
- reach the broker socket;
- read broker configuration;
- read issuer keys;
- read replay state.

### Acceptance criteria

- Only planned export paths and the runtime closure exist.
- Read-only exports remain kernel read-only.
- The runtime directory is read-only.
- The SFTP handshake succeeds.
- All forbidden namespace and mount operations fail.
- The final workload cannot reach the host root through `/proc`, inherited descriptors, or alternate roots.
- The supervisor can terminate the workload on cancellation or expiry.

---

## Packet 15E — systemd and AppArmor packaging

### Objective

Install the broker, worker, runtime closure, systemd units, AppArmor policy, configuration directories, and client-access group through one administrator-approved package operation.

### Prerequisites

- Packets 15B–15D are complete.
- Unit and profile templates pass syntax validation.
- Exact package paths and runtime digest are known.

### Deliverables

1. Root-owned broker launcher.
2. Root-owned source resolver.
3. Root-owned mount worker.
4. Root-owned runtime closure.
5. Broker socket and service units.
6. AppArmor profiles and local source-root include.
7. `sysusers.d` group declaration.
8. `tmpfiles.d` directory declaration.
9. Broker configuration.
10. Per-user ceiling configuration.
11. Issuer public-key installation.
12. User registration command or package hook.
13. Atomic install, update, rollback, and uninstall behavior.
14. `aspr doctor` checks for every installed artifact.

### Administrator workflow

The administrator performs installation and user registration once:

```bash
sudo apt install ./astral-project_<version>_amd64.deb
sudo aspr-admin user add testuser \
    --source-rw /home/testuser/projects \
    --source-rw /scratch/testuser \
    --issuer-key /path/to/issuer.pub
```

Normal operation thereafter requires no `sudo`, no administrator approval, and no profile selection.

### Acceptance criteria

- Every trusted executable and configuration file is root-owned and not user-writable.
- AppArmor profiles load in enforce mode.
- The broker socket has the required group and mode.
- An unregistered user cannot connect.
- A registered user can connect but cannot exceed the configured ceiling.
- Package upgrade preserves administrator configuration.
- Package removal disables the socket and leaves no privileged executable active.
- No installer changes global AppArmor or user-namespace sysctls.

---

## Packet 15F — External Ubuntu security gate

### Objective

Prove the completed administrator-bootstrapped backend on a disposable Ubuntu 24.04 host.

### Required host evidence

Record:

- Ubuntu release;
- kernel release;
- AppArmor package version;
- loaded-profile names and hashes;
- systemd version;
- filesystem type and mount options;
- runtime-manifest digest;
- exact Astral Project revision;
- broker configuration digest;
- per-user ceiling digest.

### Required positive tests

1. Registered user opens a valid session.
2. Broker authenticates the peer UID.
3. Signed grant verifies.
4. Server ceiling permits the requested roots.
5. Source descriptors are opened under target-user DAC.
6. Path replacement after pinning does not redirect the mount.
7. `open_tree`, `mount_setattr`, and `move_mount` complete.
8. Read-only files and directories reject writes.
9. Nested mounts obey the declared policy.
10. `sftp_v1` starts inside the synthetic root.
11. A standard SFTP client completes basic allowed operations.
12. Supervisor terminates the workload on cancellation.

### Required negative tests

1. Ordinary Python remains unable to use the setup authority.
2. Ordinary `unshare` remains denied under the host’s normal policy.
3. An unregistered user cannot connect to the broker.
4. Group membership without a valid signed grant gains no authority.
5. A peer-UID mismatch is rejected.
6. An expired grant is rejected.
7. A replayed nonce is rejected.
8. A grant exceeding the source-root ceiling is rejected.
9. A grant exceeding the RO/RW ceiling is rejected.
10. A changed source identity is rejected.
11. A request selecting another workload is rejected.
12. A request containing executable, argv, environment, profile, staging-root, or mount-flag fields is rejected.
13. The final workload cannot mount.
14. The final workload cannot create a user namespace.
15. The final workload cannot reach broker state or the host root.
16. Modified runtime files fail digest verification.
17. AppArmor denial evidence is captured for forbidden operations.

### Gate result

Packet 15F passes only when all required positive and negative tests pass.

Packet 16 must not begin before Packet 15F passes.

---

## Packet 16 — Full SFTP functional acceptance and integration

Packet 16 no longer owns runtime-closure creation.

It owns:

- complete SFTP operation matrix;
- multiple concurrent connections;
- coherent external modifications;
- rename and overwrite behavior;
- large file transfer;
- directory traversal semantics;
- extension allowlist;
- hardlink and symlink policy;
- error mapping;
- expiry and revocation integration;
- remote preface integration;
- rclone compatibility;
- readiness protocol;
- production logging.

---

## 4. Installation tree

```text
/usr/libexec/astral-project/
├── aspr-broker
├── aspr-source-resolver
├── aspr-mount-worker
└── aspr-admin

/usr/lib/astral-project/
├── app/
└── runtime/
    └── python/

/etc/astral-project/
├── broker.toml
├── users.d/
│   └── <uid>.toml
└── issuers.d/
    └── <uid>/
        └── <key-id>.pub

/etc/apparmor.d/
├── usr.libexec.astral-project
└── local/
    └── astral-project-source-roots

/usr/lib/systemd/system/
├── astral-project-broker.socket
└── astral-project-broker.service

/usr/lib/sysusers.d/
└── astral-project.conf

/usr/lib/tmpfiles.d/
└── astral-project.conf

/var/lib/astral-project/
├── replay.sqlite3
└── runtime/
    └── sftp_v1/
        └── <manifest-digest>/

/run/astral-project/
└── broker.sock
```

---

## 5. Template conventions

The following placeholders must be replaced by the build or installer:

```text
@RUNTIME_DIGEST@
@ARCH@
@LIBC@
@LOADER_SHA256@
@SFTP_SERVER_SHA256@
@LIBRARY_ENTRIES@
@ISSUER_KEY_ID@
@ISSUER_PUBLIC_KEY@
@UID@
@GID@
@USERNAME@
```

Do not substitute placeholders through a shell command constructed from untrusted input.

Generate files from typed values, write to a temporary file in the target directory, `fsync`, set ownership and mode, then atomically rename.

---

# 6. Complete draft file contents

## 6.1 `/etc/astral-project/broker.toml`

```toml
version = 1

[service]
socket_path = "/run/astral-project/broker.sock"
state_directory = "/var/lib/astral-project"
replay_database = "/var/lib/astral-project/replay.sqlite3"
work_directory = "/run/astral-project/work"
client_group = "astral-project-client"

[protocol]
version = 1
maximum_request_bytes = 262144
maximum_response_bytes = 262144
request_timeout_seconds = 15
plan_ttl_seconds = 30

[limits]
maximum_exports = 16
maximum_path_bytes = 4096
maximum_total_target_bytes = 32768
maximum_grant_ttl_seconds = 28800
maximum_session_ttl_seconds = 28800

[workload]
id = "sftp_v1"
runtime_manifest = "/var/lib/astral-project/runtime/sftp_v1/@RUNTIME_DIGEST@/manifest.cbor"
runtime_target = "/.astral-project-runtime"
loader = "/.astral-project-runtime/ld.so"
entrypoint = "/.astral-project-runtime/sftp-server"
argv = ["-e", "-l", "INFO"]

[replay]
backend = "sqlite"
consume_transaction = "immediate"
expired_retention_seconds = 86400

[audit]
backend = "journald"
include_source_paths = false
include_file_contents = false
```

Permissions:

```text
owner: root
group: root
mode:  0644
```

The file contains ceilings and paths, but no private key.

---

## 6.2 `/etc/astral-project/users.d/@UID@.toml`

```toml
version = 1

[user]
uid = @UID@
gid = @GID@
username = "@USERNAME@"
enabled = true

[authorization]
issuer_key_ids = ["@ISSUER_KEY_ID@"]
allowed_workloads = ["sftp_v1"]

[ceiling]
maximum_grant_ttl_seconds = 28800
maximum_session_ttl_seconds = 28800
maximum_exports = 16
allow_read_write = true
allow_regular_files = true
allow_directories = true
allow_nested_mounts = false
require_source_identity = true
require_mount_identity = true

[[source_roots]]
path = "/home/@USERNAME@/projects"
access = "rw"

[[source_roots]]
path = "/scratch/@USERNAME@"
access = "rw"

[reservations]
deny_home_ssh = true
deny_astral_control_paths = true
deny_kernel_pseudo_filesystems = true
deny_devices = true
deny_sockets = true
```

Permissions:

```text
owner: root
group: root
mode:  0644
```

`source_roots.path` values are canonical absolute paths, not globs.

---

## 6.3 `/etc/astral-project/issuers.d/@UID@/@ISSUER_KEY_ID@.pub`

```text
ed25519 @ISSUER_KEY_ID@ @ISSUER_PUBLIC_KEY@
```

Permissions:

```text
owner: root
group: root
mode:  0644
```

The parser must require exactly one record and reject trailing fields.

---

## 6.4 `/usr/lib/systemd/system/astral-project-broker.socket`

```ini
[Unit]
Description=Astral Project namespace broker socket
Documentation=man:astral-project(8)

[Socket]
ListenStream=/run/astral-project/broker.sock
SocketUser=root
SocketGroup=astral-project-client
SocketMode=0660
DirectoryMode=0750
RemoveOnStop=yes
Service=astral-project-broker.service

[Install]
WantedBy=sockets.target
```

---

## 6.5 `/usr/lib/systemd/system/astral-project-broker.service`

```ini
[Unit]
Description=Astral Project namespace broker
Documentation=man:astral-project(8)
Requires=astral-project-broker.socket
After=local-fs.target

[Service]
Type=simple
ExecStart=/usr/libexec/astral-project/aspr-broker --systemd-socket
User=root
Group=root
UMask=0077

RuntimeDirectory=astral-project
RuntimeDirectoryMode=0750
StateDirectory=astral-project
StateDirectoryMode=0700
ConfigurationDirectory=astral-project
ConfigurationDirectoryMode=0755

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=full
ProtectHome=no
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictAddressFamilies=AF_UNIX
SystemCallArchitectures=native

CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_KILL

ReadWritePaths=/var/lib/astral-project
ReadWritePaths=/run/astral-project
InaccessiblePaths=/root

StandardOutput=journal
StandardError=journal
SyslogIdentifier=astral-project-broker

KillMode=mixed
TimeoutStopSec=30s
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
```

Notes:

- Do not add `PrivateUsers=yes`.
- Do not add `ProtectHome=yes`.
- Do not change `ProtectSystem=full` to `strict` until source-resolution and runtime tests prove compatibility.
- The broker should drop unused effective capabilities immediately. The bounding set exists for the fixed worker path.
- Add a syscall filter only after the exact syscall trace is frozen.

---

## 6.6 `/usr/lib/sysusers.d/astral-project.conf`

```text
g astral-project-client - - "Astral Project broker clients"
```

No dedicated broker user is created because the broker must perform root-owned setup and then create a target-user namespace.

---

## 6.7 `/usr/lib/tmpfiles.d/astral-project.conf`

```text
d /run/astral-project 0750 root astral-project-client -
d /run/astral-project/work 0700 root root -
d /var/lib/astral-project 0700 root root -
d /var/lib/astral-project/runtime 0755 root root -
d /var/lib/astral-project/runtime/sftp_v1 0755 root root -
d /etc/astral-project 0755 root root -
d /etc/astral-project/users.d 0755 root root -
d /etc/astral-project/issuers.d 0755 root root -
```

The broker creates `replay.sqlite3` itself with mode `0600` using exclusive creation and verifies ownership before every open.

---

## 6.8 `/etc/apparmor.d/usr.libexec.astral-project`

> This is a complete **bootstrap profile draft**, not a claim of final least privilege. It must pass `apparmor_parser` validation and the Packet 15F audit suite on Ubuntu 24.04. New mount-API mediation varies by kernel and AppArmor version; tighten rules from observed audit evidence without broadening the trusted interface.

```text
abi <abi/4.0>,

#include <tunables/global>

@{ASPR_LIBEXEC}=/usr/libexec/astral-project
@{ASPR_APP}=/usr/lib/astral-project
@{ASPR_STATE}=/var/lib/astral-project
@{ASPR_RUN}=/run/astral-project
@{ASPR_ETC}=/etc/astral-project

profile aspr-broker @{ASPR_LIBEXEC}/aspr-broker flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  @{ASPR_LIBEXEC}/aspr-broker mr,
  @{ASPR_APP}/** r,
  @{ASPR_APP}/runtime/** mr,

  @{ASPR_ETC}/ r,
  @{ASPR_ETC}/broker.toml r,
  @{ASPR_ETC}/users.d/ r,
  @{ASPR_ETC}/users.d/*.toml r,
  @{ASPR_ETC}/issuers.d/ r,
  @{ASPR_ETC}/issuers.d/** r,

  @{ASPR_STATE}/ r,
  @{ASPR_STATE}/replay.sqlite3 rwk,
  @{ASPR_STATE}/replay.sqlite3-wal rwk,
  @{ASPR_STATE}/replay.sqlite3-shm rwk,
  @{ASPR_STATE}/runtime/ r,
  @{ASPR_STATE}/runtime/** r,

  @{ASPR_RUN}/ r,
  @{ASPR_RUN}/broker.sock rw,
  @{ASPR_RUN}/work/ rw,
  @{ASPR_RUN}/work/** rwk,

  /proc/sys/kernel/** r,
  /proc/[0-9]*/status r,
  /proc/[0-9]*/setgroups rw,
  /proc/[0-9]*/uid_map rw,
  /proc/[0-9]*/gid_map rw,

  unix (accept,getattr,getopt,setopt,r,w) type=stream addr="@{ASPR_RUN}/broker.sock",

  capability kill,
  capability setuid,
  capability setgid,
  capability setpcap,

  @{ASPR_LIBEXEC}/aspr-source-resolver Px -> aspr-source-resolver,
  @{ASPR_LIBEXEC}/aspr-mount-worker Px -> aspr-mount-worker,

  deny /bin/** x,
  deny /usr/bin/** x,
  deny /usr/local/bin/** x,
}

profile aspr-source-resolver @{ASPR_LIBEXEC}/aspr-source-resolver flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  @{ASPR_LIBEXEC}/aspr-source-resolver mr,
  @{ASPR_RUN}/work/** rw,

  # Exact administrator-approved roots are generated here.
  #include if exists <local/astral-project-source-roots>

  unix (getattr,getopt,setopt,send,receive,r,w) type=stream,

  deny capability,
  deny userns,
  deny mount,
  deny umount,

  deny /bin/** x,
  deny /usr/bin/** x,
  deny /usr/local/bin/** x,
}

profile aspr-mount-worker @{ASPR_LIBEXEC}/aspr-mount-worker flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  @{ASPR_LIBEXEC}/aspr-mount-worker mr,
  @{ASPR_STATE}/runtime/sftp_v1/** r,
  @{ASPR_RUN}/work/** rwk,

  # Descriptor-backed mount operations may still be mediated by source path.
  #include if exists <local/astral-project-source-roots>

  /proc/sys/kernel/** r,
  /proc/[0-9]*/status r,
  /proc/[0-9]*/setgroups rw,
  /proc/[0-9]*/uid_map rw,
  /proc/[0-9]*/gid_map rw,

  userns,

  capability sys_admin,
  capability setuid,
  capability setgid,
  capability setpcap,
  capability kill,

  # Bootstrap allowance. Packet 15F must tighten this from audit evidence.
  mount,
  remount,
  umount,

  unix (getattr,getopt,setopt,send,receive,r,w) type=stream,

  /.astral-project-runtime/ld.so Px -> aspr-sftp-v1,
  @{ASPR_STATE}/runtime/sftp_v1/*/ld.so Px -> aspr-sftp-v1,

  deny /bin/** x,
  deny /usr/bin/** x,
  deny /usr/local/bin/** x,
}

profile aspr-sftp-v1 flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>

  / r,
  /** rwlk,

  /.astral-project-runtime/ r,
  /.astral-project-runtime/** mr,

  deny /.astral-project-runtime/** wklx,

  deny capability,
  deny userns,
  deny mount,
  deny remount,
  deny umount,

  deny network,
  deny unix,

  deny /bin/** x,
  deny /usr/bin/** x,
  deny /usr/local/bin/** x,
}
```

Important review points:

1. The broad `mount` rule exists only in the fixed mount-worker profile.
2. The mount worker accepts no arbitrary command or mount request.
3. The final SFTP profile has no mount, user namespace, capability, network, or Unix-socket authority.
4. The broad file rule in `aspr-sftp-v1` is bounded by the synthetic mount namespace. Dynamic grant targets make a fixed per-path AppArmor allowlist impractical.
5. Packet 15F must prove that the final profile cannot reach host paths absent from the namespace.
6. Parser warnings and downgrade behavior are gate failures until reviewed.

---

## 6.9 `/etc/apparmor.d/local/astral-project-source-roots`

This file is generated by the administrator registration command.

Example for `testuser`:

```text
/home/testuser/projects/ r,
/home/testuser/projects/** r,

/scratch/testuser/ r,
/scratch/testuser/** r,
```

For a source root whose grants may be read-write, the source resolver still needs only read/traversal authority because it opens and pins the object. Write authority is enforced by DAC and the final mounted export mode.

Do not put `/home/**`, `/scratch/**`, or `/**` in this file.

---

## 6.10 Runtime manifest source: `manifest.toml`

The builder emits this human-readable source and canonicalizes the same data into `manifest.cbor`.

```toml
version = 1
workload_id = "sftp_v1"
architecture = "@ARCH@"
libc = "@LIBC@"

runtime_target = "/.astral-project-runtime"
loader = "ld.so"
entrypoint = "sftp-server"
argv = ["-e", "-l", "INFO"]

allow_network = false
allow_shell = false
allow_dynamic_environment = false

[[files]]
path = "ld.so"
type = "regular"
mode = 493
sha256 = "@LOADER_SHA256@"

[[files]]
path = "sftp-server"
type = "regular"
mode = 365
sha256 = "@SFTP_SERVER_SHA256@"

@LIBRARY_ENTRIES@

[[files]]
path = "etc/passwd"
type = "generated"
mode = 292
sha256 = "@PASSWD_SHA256@"

[[files]]
path = "etc/group"
type = "generated"
mode = 292
sha256 = "@GROUP_SHA256@"

[[files]]
path = "etc/nsswitch.conf"
type = "generated"
mode = 292
sha256 = "@NSSWITCH_SHA256@"
```

Generated minimal identity files should resemble:

### `etc/passwd`

```text
aspr:x:0:0:Astral Project SFTP:/:/usr/sbin/nologin
```

### `etc/group`

```text
aspr:x:0:
```

### `etc/nsswitch.conf`

```text
passwd: files
group: files
shadow: files
```

The builder may omit these files only after the empty-namespace test proves they are unnecessary.

---

# 7. Broker request contract summary

The socket request must be a bounded canonical message. It may contain:

```text
CreateNamespaceV1 {
    protocol_version = 1
    request_id: bytes[16]
    session_id: bytes[16]
    grant_envelope: bytes[1..131072]
    client_nonce: bytes[32]
    requested_workload = sftp_v1
}
```

It must not contain:

```text
source path chosen outside signed grant
staging path
executable path
argv
environment
AppArmor profile
bwrap arguments
raw mount flags
runtime path
runtime digest override
UID or GID override
```

`CancelNamespaceV1` is separate control message. It never multiplexes cancellation into SFTP bytes.

The broker derives UID/GID from `SO_PEERCRED` and the per-user root-owned configuration.

The broker response union is:

```text
NamespaceReadyV1 {
    request_id: bytes[16]
    session_id: bytes[16]
    backend_id
    effective_exports_digest: bytes[32]
    runtime_manifest_digest: bytes[32]
    expires_at
    stream_fd_count = 1
}

NamespaceRejectedV1 {
    request_id: bytes[16]
    stable_error_code
    stage
    safe_message
}
```

`NamespaceReadyV1` transfers exactly one connected `AF_UNIX SOCK_STREAM` FD through `SCM_RIGHTS`. The broker control socket never carries raw SFTP bytes.

---

# 8. Installation and validation instructions

Do not install on the test host until the implementation agent has:

1. implemented the files;
2. replaced every placeholder;
3. passed unit and integration tests without root;
4. emitted an installation manifest;
5. requested explicit approval for root installation.

After approval, an administrator performs:

```bash
sudo systemd-sysusers /usr/lib/sysusers.d/astral-project.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/astral-project.conf

sudo apparmor_parser -Q /etc/apparmor.d/usr.libexec.astral-project
sudo apparmor_parser -r /etc/apparmor.d/usr.libexec.astral-project

sudo systemctl daemon-reload
sudo systemctl enable --now astral-project-broker.socket
```

Register the user:

```bash
sudo usermod -aG astral-project-client testuser
```

A new login session is required before supplementary group membership is visible.

Validate:

```bash
getent group astral-project-client
systemctl status astral-project-broker.socket
systemctl status astral-project-broker.service
sudo aa-status | grep -E 'aspr-(broker|source-resolver|mount-worker|sftp-v1)'
stat -c '%U %G %a %n' \
    /usr/libexec/astral-project/aspr-broker \
    /usr/libexec/astral-project/aspr-source-resolver \
    /usr/libexec/astral-project/aspr-mount-worker \
    /etc/astral-project/broker.toml
```

The service may remain inactive until the first socket connection. That is normal for socket activation.

---

# 9. Required implementation-agent handoff

At the end of each packet, the implementation agent must provide:

- exact files changed;
- exact tests run;
- root-required actions not yet performed;
- current AppArmor audit denials;
- current systemd hardening score;
- remaining broad AppArmor rules;
- runtime-manifest file list and digest;
- unresolved architecture questions;
- clean next packet entry point.

No packet may hide a security failure behind a permissive fallback.

