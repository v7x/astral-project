# Packet 36A final gate

Final implementation commit: `b0c8316d52d4b42a0b11fa37ebab1e91f60273a2`.
Final artifact SHA-256: `553ba41be83ccdfe4ffe148bbfbc70376c019a0dda8795ea8270e0549e4eb8e7`.

Local gates passed:

```text
uv lock --check
./scripts/test                     748 passed, 1 skipped; coverage 100%
git diff --check
cc -std=c11 -O2 -Wall -Wextra -Werror scripts/apparmor_net_admin_probe.c -o /tmp/aspr-apparmor-net-admin-probe
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-bwrap-launch.c -o /tmp/aspr-bwrap-launch
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-sandbox-entry.c -o /tmp/aspr-sandbox-entry
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-host-rx.c -o /tmp/aspr-host-rx
apparmor_parser -Q -K packaging/apparmor/usr.libexec.astral-project.aspr-bwrap-launch
```

Fresh final-artifact raw transcripts are preserved in
`packet-33-36-ubuntu24-raw.txt` and `packet-33-36-ubuntu26-raw.txt`. Each
contains exact source/artifact/driver hashes, isolated distro FUSE/Trio
versions, enforcing profile status, normal confinement, dedicated native
allowed `net_admin` evidence, exact one-rule tightening denial, tightened
installed-runtime failure, restored native allowed evidence, restored success,
all 26 learner case results, and signed remote multi-mount/loss results.

Ubuntu 24.04 certified closure: `python3-pyfuse3 3.3.0-0.1`, Trio `0.24.0`.
Ubuntu 26.04 certified closure: `python3-pyfuse3 3.4.0-3build5`, Trio `0.32.0`.
The strict CBOR fallback is covered by `tests/unit/test_crypto_cbor.py` and keeps
Ubuntu 24.04's older distro decoder fail-closed without ambient `/usr/local` imports.

Integrated Learner Gate is closed only after fresh auditor approval.
