# Packet 15F Ubuntu 24.04 evidence

Status: **passed after explicit AppArmor ABI pinning** on 2026-08-15. Ubuntu 24.04 is now certified for this Packet 15F profile and package.

## Target and package

- OS: Ubuntu 24.04.4 LTS, amd64.
- Kernel: `6.8.0-137-generic`.
- AppArmor package: `4.0.1really4.0.1-0ubuntu0.24.04.7`; parser `4.0.1`.
- systemd: `255.4-1ubuntu8.17`.
- Repository profile change: explicit `abi <abi/4.0>,` declaration.
- Debian SHA-256: `47ba26a5faa98784cba45a97a7b764f63806905634cc1286eb7134e73ff4dba`.
- Loaded profile status JSON SHA-256: `ec6275dab5d29fb786ae5c48f1c442e0bc858c8f161510b7df47991ba6228816`.
- AppArmor evidence record profile digest: `b034b6dacb0f9ed367f99fc3c50d29ff30519371308e0aa5d6d4cc48ac9fe84f`.

## ABI/rule-enforcement investigation

Exact packaged profile, without explicit ABI declaration, was loaded with:

```text
apparmor_parser --warn=rule-not-enforced --replace /etc/apparmor.d/usr.libexec.astral-project.aspr-broker
```

Relevant complete parser warnings:

```text
Warning from profile aspr-broker: network rules not enforced
Warning from profile aspr-namespace-setup: network rules not enforced
Warning from profile aspr-sftp-v1: userns rules not enforced
Warning from profile aspr-sftp-v1: network rules not enforced
Warning from profile aspr-sftp-v1: deny unix socket rule not enforced, can't be downgraded to generic network rule
```

Warnings repeat for each matching rule. They prove prior profile was being downgraded by the parser/kernel ABI boundary; this was not a permanent Ubuntu 24.04 incompatibility.

Feature tree was captured from `/sys/kernel/security/apparmor/features/`. Relevant values:

```text
network/af_unix = yes
network_v8/af_inet = yes
network/af_mask includes unix inet
policy/versions = v5, v6, v7, v8, v9
policy/permstable32_version = 0x000003
mount/mask = mount umount pivot_root
mount/move_mount = detached
namespaces/userns_create = pciu&
namespaces/pivot_root = no
file/mask = create read write exec append mmap_exec link lock
```

Temporary exact-profile ABI trial inserted only:

```text
abi <abi/4.0>,
```

Parser output with `--warn=rule-not-enforced` then contained only:

```text
Warning from profile aspr-sftp-v1: deny unix socket rule not enforced, can't be downgraded to generic network rule
```

Loaded state remained enforced for `aspr-broker`, `aspr-namespace-setup`, and `aspr-sftp-v1`. With ABI pinning, isolated final-workload probes returned:

```text
mount=passed errno=13
open_tree=passed errno=1
mount_setattr=passed errno=1
move_mount=passed errno=1
chroot=passed errno=13
pivot_root=passed errno=1
unix_socket=passed errno=13
network_socket=passed errno=13
```

The explicit ABI declaration is therefore part of packaged policy. The remaining Unix warning is not an accepted permission: the final probe returns `EACCES`, and the profile remains fail closed.

## Clean packaged gate

- Package: `astral-project 0.1.0`, rebuilt from the ABI-pinned profile.
- Debian SHA-256: `47ba26a5faa98784cba45a97a7b764f63806905634cc1286eb7134e73ff4dba`.
- Runtime manifest digest: `d4747062e4854443c29a61171fb133b6f77722eb2185168d3256659eae7bb4ce`.
- Loaded profiles: `aspr-broker`, `aspr-namespace-setup`, `aspr-sftp-v1`; all `enforce`.
- Broker explicitly permits only worker setup `userns create` and broker-to-namespace kill signaling required by ABI-pinned profile; final `aspr-sftp-v1` retains `deny userns`, `deny capability`, `deny mount`, and socket/network denials.
- Packaged preflight: passed.
- Registered-user SFTP handshake: passed.
- Descriptor replacement: passed.
- Kernel RO denial: passed.
- Alternate-root and target-user DAC denial: passed.
- Expiry/cancellation cleanup: passed.
- Replay, expired-grant, wrong-user, source-ceiling, and RO/RW ceiling rejection: passed.
- Modified runtime closure digest: rejected on broker restart.
- Unregistered peer, UID mismatch, and GID mismatch: rejected.

Relevant audit evidence after ABI trial showed no successful socket creation in `aspr-sftp-v1`; probe denials returned `errno=13`. Earlier non-ABI records are retained in VM journal and establish the prior rule downgrade, including `apparmor="DENIED"` records for later socket attribute operations.

## Security boundary review

Final workload permissions remain limited to fixed runtime loading, required device initialization files, inherited stream inspection, read/mmap of the fixed runtime/root, and explicit denial rules. No base abstraction is included in `aspr-sftp-v1`. No arbitrary write, mount, capability, user namespace, broker-state, or unintended executable authority was added. `/** mr` is required for detached runtime shared-library mappings observed during loader startup; `/** r` permits pathname reads only and does not grant writes or execution.

## Certification

Ubuntu 24.04 amd64 is certified after explicit ABI pinning. Ubuntu 26.04 amd64 remains certified; its regression gate must be rerun against the ABI-pinned package before release of this closure.

Packet 16 is unblocked on one certified POC target; Ubuntu 24.04 certification is not a prerequisite.
