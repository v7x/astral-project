# Packet 15F Ubuntu 24.04 evidence

Status: **failed / uncertified** on 2026-08-15. Clean packaged startup remediation passed; full certification remains blocked by final-workload socket-creation denial on Ubuntu 24.04 AppArmor semantics.

## Target and package

- OS: Ubuntu 24.04.4 LTS, amd64.
- Kernel: `6.8.0-137-generic`.
- AppArmor package: `4.0.1really4.0.1-0ubuntu0.24.04.7`; parser `4.0.1`.
- systemd: `255.4-1ubuntu8.17`.
- Repository commit used to build: `b65a8ad`.
- Package: `astral-project 0.1.0`.
- Debian SHA-256: `fc03982ddbd633ad75724c816841734adf1797a851e40f2ca8794a45d68fc5de`.
- Filesystem: `/dev/vda2`, `ext4`, `rw,relatime`.
- Runtime manifest digest: `d4747062e4854443c29a61171fb133b6f77722eb2185168d3256659eae7bb4ce`.
- Broker configuration SHA-256: `efbb2f29eeb82fdf504df3043d6a7cbda0576237362b4229699bc57a9e1ade2f`.
- Server-ceiling tree SHA-256: `12f66c554a3b140d355e9d75692c95d9d8da7d3c412f60ef4a41fa8a06855409`.
- Loaded profiles: `aspr-broker`, `aspr-namespace-setup`, `aspr-sftp-v1`; all `enforce`.
- AppArmor status JSON SHA-256: `4b7575fcbe46d3ae3b82917fb9dbd3777a48c3f091fce2fdeb4a03777aeeba5b`.

## Remediation results

Trusted broker launcher now uses `/usr/bin/python3 -I -S` and inserts only `/usr/lib/astral-project/python`. Clean packaged startup no longer requests `/usr/local/lib/python3.12/dist-packages/`.

Package post-install and explicit administrator tool `/usr/libexec/astral-project/render-apparmor-roots` deterministically render the fixed root-owned local include from root-owned authority and ceiling inputs. Rendered rules contain only configured exact source roots. Normal sessions require no administrator action.

Packaged preflight passed. Registered-user SFTP handshake, descriptor replacement, kernel RO denial, alternate-root denial, target-user DAC denial, cancellation/expiry cleanup, replay rejection, expired-grant rejection, wrong-user rejection, source-root ceiling rejection, and RO/RW ceiling rejection passed with stage-specific broker results.

## Remaining failure

Final confined-profile probe output:

```text
mount=passed errno=13
open_tree=passed errno=1
mount_setattr=passed errno=1
move_mount=passed errno=1
chroot=passed errno=13
pivot_root=passed errno=1
unix_socket=FAILED rc=4 errno=0
network_socket=FAILED rc=4 errno=0
```

The final profile records explicit network and Unix-socket denial rules and removes the broad AppArmor base abstraction whose Unix grants conflicted with the frozen boundary. Ubuntu 24.04 nevertheless permits socket creation in this profile; kernel audit records denials for later socket attribute operations, not creation. Adding a permissive or weaker fallback would violate required evidence, so no such change was made.

This is a concrete Ubuntu 24.04 AppArmor/kernel integration incompatibility, not a Packet 15 architecture or mount-API failure. Ubuntu 24.04 remains uncertified. Fresh rerun required if a later security-reviewed host-integration fix is approved.
