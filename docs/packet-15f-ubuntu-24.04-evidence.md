# Packet 15F Ubuntu 24.04 evidence

Status: **failed / uncertified** on 2026-08-15. This record is not a certification claim.

## Target and package

- OS: Ubuntu 24.04.4 LTS, amd64.
- Kernel: `6.8.0-137-generic`.
- AppArmor package: `4.0.1really4.0.1-0ubuntu0.24.04.7`; parser `4.0.1`.
- systemd: `255.4-1ubuntu8.17`.
- Package: `astral-project 0.1.0`.
- Debian SHA-256: `2d2c07b878a90e5cd82c19851242feb6f9a43eb54df92615169f9a5bced36075`.
- Filesystem: `/dev/vda2`, `ext4`, `rw,relatime`.
- Runtime manifest digest: `d4747062e4854443c29a61171fb133b6f77722eb2185168d3256659eae7bb4ce`.
- Broker configuration SHA-256: `efbb2f29eeb82fdf504df3043d6a7cbda0576237362b4229699bc57a9e1ade2f`.
- User-ceiling SHA-256: `ecb7b4d349820adfa21201989389f0322fdc6885e9d2c4c57395a63e8bc412b7`.
- Loaded profiles: `aspr-broker`, `aspr-namespace-setup`, `aspr-sftp-v1`; all `enforce`.

## Gate result

Packaged preflight passed and wrote `/var/lib/astral-project/evidence/packet15f.json`.
The first positive request under the packaged AppArmor policy failed closed:

```text
NamespaceRejectedV1(... stable_error_code=backend_unavailable,
    stage='worker_start', safe_message='broker request could not be completed')
```

Broker journal and kernel audit identified first failing stage:

```text
apparmor="DENIED" profile="aspr-broker"
name="/usr/local/lib/python3.12/dist-packages/"
requested_mask="r"

apparmor="DENIED" profile="aspr-broker"
name="/home/testuser/astral-gate-source/"
fsuid=1002 ouid=1002
```

The packaged profile lacks the Ubuntu 24.04 Python site-path allowance and administrator-generated source-root include. No global policy or security invariant was weakened.

## Diagnostic-only rerun

For diagnosis only, an exact local AppArmor rule for `/usr/local/lib/python3.12/dist-packages/**` and the administrator source-root include were loaded on the disposable VM. This was VM drift, not acceptance evidence. Under that diagnostic policy:

- registered-user SFTP handshake: passed;
- descriptor replacement after pinning: passed;
- kernel read-only export write denial: passed;
- alternate-root denial: passed;
- target-user DAC denial after source ownership change: passed;
- expiry supervision cleanup: passed;
- replay: first request passed, identical replay rejected at `grant_validation`;
- expired grant: rejected at `grant_validation`;
- wrong remote user: rejected at `grant_validation`.

The diagnostic result does not convert the packaged artifact to a pass. UID/GID mismatch and unregistered-peer cases were not promoted to acceptance because packaged positive setup failed before those dependent tests; they remain required for any rerun.

## Classification

Concrete cause: **AppArmor/package integration on Ubuntu 24.04**, not a mount API failure or a frozen Packet 15 security-boundary failure. Ubuntu 24.04 remains uncertified. Remediation requires a reviewed packaging/AppArmor change and a fresh packaged gate; no Packet 16 support claim is made for 24.04.
