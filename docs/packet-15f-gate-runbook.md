# Packet 15F Ubuntu gate runbook

Status: prepared only. Do not run package install or this gate on `aspr-test` without explicit administrator approval.

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

Packet 15F passes only when preflight evidence and every positive/negative case are recorded `passed`. Packet 16 remains blocked otherwise.
