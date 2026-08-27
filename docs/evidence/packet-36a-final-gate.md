# Packet 36A final gate

Final implementation commit: `2a945179b7135523f112e4812982045b329b0717`.
Final artifact SHA-256: `2d8459d6b5a5777ac58a0a2957538df9e0059082f57e34cb75fe83397a44dbbf`.

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
installed-runtime failure, restored success, and all 26 learner case results.

Ubuntu 24.04 certified closure: `python3-pyfuse3 3.3.0-0.1`, Trio `0.24.0`.
Ubuntu 26.04 certified closure: `python3-pyfuse3 3.4.0-3build5`, Trio `0.32.0`.

Integrated Learner Gate is closed only after fresh auditor approval.
