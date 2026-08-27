# Packets 23–24 acceptance

The packaged acceptance runs as `testuser` against installed `/usr/bin/aspr` on Ubuntu 24.04 and Ubuntu 26.04. Both systems use distro `/usr/bin/bwrap`; no setuid or file-capability helper is installed. The driver exercises temporary `/tmp` and normal `/run/user/<uid>/astral-project` layouts, verifies root ownership/mode and empty file capabilities, and runs the complete installed confinement harness. It records post-baseline kernel AppArmor evidence for an allowed tmpfs mount and `CAP_SYS_ADMIN`; then it unloads and reloads the exact packaged profile before one dedicated native `SIOCSIFFLAGS` probe. That probe must produce allowed `CAP_NET_ADMIN` evidence. A temporary copy with exactly the one `audit capability net_admin,` rule removed must deny the same probe and break installed `--network none`; restoring the packaged profile must restore success. A separate clean installed `--network none` run records `CAP_SETPCAP` and `CAP_SYS_ADMIN`. No evidence is inferred from profile text.

Hosted CI/CD is intentionally deferred while the core packet sequence is under development because the current GitHub account does not have hosted Actions billing enabled. Packet completion is therefore determined by checked-in local verification scripts and required installed Ubuntu acceptance gates. Hosted CI/CD will be reconsidered after completion of the packet sequence. This is an execution-policy deferral, not missing packet evidence. Local gates are `uv lock --check`, locked dependency synchronization, `./scripts/test`, and `git diff --check`; no replacement hosted provider is planned.

## Fixed execution boundary

`LocalSandboxPlan` emits the versioned `ASPRSB01` typed plan over the launcher's stdin. The root-owned launcher independently bounds and validates the network mode, command count, path normalization, remote bindings, socket, plan size, FUSE mount superblock type, and a daemon-created `.aspr-mount-<mount_id>` authority marker for every remote source. The mount identity is serialized in ASPRSB01 and checked independently before argv construction. It constructs the complete bubblewrap argv itself. The caller cannot supply bwrap flags, an alternate bwrap path, an alternate entrypoint, or a network fallback.

The launcher runs `/usr/bin/bwrap` with fixed PID/IPC/UTS namespaces, the explicit `--unshare-net` only for `network=none`, fixed `/usr` and runtime bindings, `--cap-drop ALL`, and the fixed `/usr/libexec/astral-project/aspr-sandbox-entry`. Runtime access covers `/run/user/*/astral-project/**`; administrator-approved `/scratch` and `/datasets` roots are supplied through the rendered `local/astral-project-source-roots` include. The entrypoint accepts only an absolute bounded payload executable, requires the fixed setup-profile label even for direct invocation, and performs no option interpretation. The session API uses a launcher-created relay and an in-sandbox `/run/astral-project/session.sock`; the host socket is never directly bind-mounted across the sandbox transition.

## AppArmor and capability boundary

The package installs and loads `packaging/apparmor/usr.libexec.astral-project.aspr-bwrap-launch` as two domains:

* `aspr-bwrap-setup` grants only the observed setup capabilities required by distro bubblewrap (`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, and `CAP_SETPCAP`) and the narrowly declared namespace/mount and user-namespace-map operations. Its inet/inet6 stream and datagram rules are deliberate: bubblewrap uses datagram sockets while configuring loopback, and the setup domain must already contain inherited-network permissions so the restrictive payload stack cannot gain them; `network=none` still removes host interfaces before payload execution.
* `aspr-sandbox-payload` is stacked at the fixed entrypoint with `Px -> aspr-bwrap-setup//&aspr-sandbox-payload`. The payload has no capability rules and is intersected with bwrap's namespace filesystem and network view.

Package configuration invokes `apparmor_parser --replace`; if AppArmor cannot be loaded, configuration fails rather than falling back to direct bwrap or an unconfined command. The two installed binaries were observed on both VMs as `root:root`, mode `0555` (executable but not writable by any principal), with no setuid bits and empty `getcap` output.

Ubuntu 24.04 operationally exhibited delayed and suppressed repeated allowed capability records from ordinary Bubblewrap setup. The driver therefore drains prior audit output, unloads and reloads the exact profile, captures a fresh serial baseline, and issues one dedicated first-request native probe. This is an evidence-method correction, not an authority relaxation; the tightening probe and installed runtime failure prove `CAP_NET_ADMIN` remains required.

The VM acceptance captures AppArmor setup-domain denials for attempted `CAP_SYS_PTRACE`, `CAP_DAC_OVERRIDE`, and unauthorized payload mounts, plus successful audit records for the three permitted capability operations and a confined tmpfs mount. On Ubuntu 24.04, removing and reloading the profile before the dedicated probe avoids older allowed-capability audit suppression; the driver waits for audit delivery without rerunning workloads. No unlisted setup capability is authorized. The existing `aspr-sftp-v1` final-workload Unix boundary remains intact (`deny unix`); Packet 23 adds no global AppArmor permission. Successful fixed namespace/mount/network behavior and runtime audit observations are recorded in the raw harness output.

Observed payload status on both releases:

```text
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000000000000000
CapAmb: 0000000000000000
NoNewPrivs: 1
```

## Raw acceptance commands

On each VM, after package build/install and Packet 15F, run `sudo SUDO_USER=testuser ASPR_PACKAGE=/absolute/final.deb python3 scripts/sandbox_installed_acceptance.py`. The driver compiles checked-in `scripts/apparmor_net_admin_probe.c` only for acceptance, using a root-owned ephemeral path under `/usr/libexec/astral-project`; it never installs that probe as package content. It runs `scripts/sandbox_enforce_acceptance.py` as `testuser` with `XDG_RUNTIME_DIR=/run/user/<uid>`; that harness checks both network modes, every payload capability set, every non-loopback interface, DNS and all network socket tables, hidden daemon/transport sockets and credential paths, namespace denial, and native negative controls.

On each VM:

```sh
sudo aa-status | grep -E 'aspr-bwrap-setup|aspr-sandbox-payload'
stat -c '%n %U:%G %a %A' \
  /usr/libexec/astral-project/aspr-bwrap-launch \
  /usr/libexec/astral-project/aspr-sandbox-entry
getcap /usr/libexec/astral-project/aspr-bwrap-launch \
  /usr/libexec/astral-project/aspr-sandbox-entry
sudo -u testuser env XDG_RUNTIME_DIR="$runtime" XDG_STATE_HOME="$state" \
  /usr/bin/aspr sandbox --network inherit -- /bin/sh -c \
  'grep -q NoNewPrivs: /proc/self/status'
sudo -u testuser env XDG_RUNTIME_DIR="$runtime" XDG_STATE_HOME="$state" \
  /usr/bin/aspr sandbox --network none -- /bin/sh -c \
  'set -e; grep -q lo /proc/net/dev; ! grep -q eth /proc/net/dev; \
   test "$(cat /proc/net/route | tail -n +2 | wc -l)" -eq 0; \
   mkdir /tmp/blocked; ! mount -t tmpfs tmpfs /tmp/blocked'
```

The installed native negative control also submits a valid ASPRSB01 plan with `--unshare-net`, `/tmp/alternate-helper`, and `/usr/bin/alternate-entrypoint`; each invocation is rejected before plan execution with exit 70.

The positive remote matrix additionally verified repeated remotes under one signed grant, hidden daemon/session sockets and `/dev/fuse`, mount cleanup, and termination after the daemon-created remote view was closed. Packet 15F returned exit 0 on both releases. Full machine results are in `docs/evidence/daemon-sandbox-matrix.json`; raw installed command output is in `docs/evidence/packet-23-24-vm-output.txt`.

## Explicit exclusions

This packet does not add FUSE or projected-home support, proxy egress, learned profiles, multi-grant sandboxes, or production remote bubblewrap. Those remain Packet 25+ work. It does not weaken global AppArmor policy or security sysctls, install setuid/file-capability helpers, or expose raw bubblewrap arguments.
