# Packet 15E package assets

These files are package inputs. They are not an installer and must not be copied into host paths by a development command.

Package operation installs root-owned files only:

- broker and native workers: `/usr/libexec/astral-project/`;
- broker configuration and per-user ceilings: `/etc/astral-project/`;
- content-addressed runtime closures: `/var/lib/astral-project/runtime/`;
- socket directory: `/run/astral-project/`.

`astral-project-broker.socket` grants group reachability only. Signed grant, `SO_PEERCRED` UID/GID, replay, and per-root ceiling remain broker checks.

Profile roles:

- `aspr-broker`: root broker and controlled worker transition;
- `aspr-namespace-setup`: namespace/mount setup only;
- `aspr-sftp-v1`: fixed final workload. It has no network, mount, capability, or arbitrary-exec allow rule.

Validate package assets before an administrator-approved package operation:

```text
apparmor_parser -p packaging/apparmor/usr.libexec.astral-project.aspr-broker
systemd-analyze verify --root=<disposable-root> astral-project-broker.socket astral-project-broker.service
```

Packet 15F package preflight source is `packaging/tools/packet15f-gate.py`; package installs it as `/usr/libexec/astral-project/packet15f-gate`. It has no arguments and writes only fixed evidence path.

No package asset changes global AppArmor policy or user-namespace sysctls.
