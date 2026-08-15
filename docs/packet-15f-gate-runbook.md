# Packet 15F Ubuntu gate runbook

Status: executed on Ubuntu 26.04 amd64 (passed) and Ubuntu 24.04 amd64 (failed final-profile socket denial). Ubuntu 24.04 startup/source-root integration now passes; final socket-creation control remains incompatible with observed AppArmor semantics. Support follows evidence per distribution/release/architecture; see ADR-0024. Do not treat VM-only diagnostic policy changes as acceptance.

## Preconditions

1. Administrator-approved package operation installed Packet 15E assets.
2. Root-owned broker configuration, issuer keys, per-user ceiling, and one runtime closure exist.
3. AppArmor profiles `aspr-broker`, `aspr-namespace-setup`, and `aspr-sftp-v1` load in enforce mode.
4. `astral-project-broker.socket` is enabled. No global AppArmor or user-namespace sysctl changes occurred.

## Evidence command

Run only as root on disposable Ubuntu target:

```text
/usr/libexec/astral-project/packet15f-gate
```

It writes fixed evidence path:

```text
/var/lib/astral-project/evidence/packet15f.json
```

It fails closed unless package paths, ownership/modes, loaded profiles, socket unit, runtime manifest, broker configuration, and per-user ceilings are present.

## Required manual adversarial phase

Run after preflight evidence and record each result:

- valid registered-user fixed SFTP handshake;
- descriptor replacement after source pinning;
- RO export write denial;
- unregistered peer denial;
- UID and GID mismatch denial;
- expired/replayed grant denial;
- forbidden mount, `open_tree`, `mount_setattr`, `move_mount`, user-namespace, alternate-root, socket, and network operations from final workload;
- cancellation/expiry supervisor termination.

Packet 15F passes only when packaged preflight and every positive/negative case are recorded `passed`. Ubuntu 26.04 amd64 satisfies this. Ubuntu 24.04 remains uncertified after packaged final-profile socket-control failure; exact evidence is retained. Packet 16 proceeds on certified Ubuntu 26.04 POC target and does not weaken or rebuild Packet 15.
