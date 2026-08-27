# Packet 36A final gate

Final implementation commit: `6fbd4adf115fb154d33f4de13acae4c108c2af91`.
Final artifact SHA-256: `5e272dc240d41aa1d6aefb2766bc30cb99b4a832a1c7f9c0405362744d6e4f64`.

Local gates passed:

```text
uv lock --check
./scripts/test                     773 passed, 1 skipped; coverage 100%
git diff --check
cc -std=c11 -O2 -Wall -Wextra -Werror scripts/apparmor_net_admin_probe.c -o /tmp/aspr-apparmor-net-admin-probe
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-bwrap-launch.c -o /tmp/aspr-bwrap-launch
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-sandbox-entry.c -o /tmp/aspr-sandbox-entry
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-host-rx.c -o /tmp/aspr-host-rx
apparmor_parser -Q -K packaging/apparmor/usr.libexec.astral-project.aspr-bwrap-launch
```

The artifact was built from executable source commit `6fbd4adf115fb154d33f4de13acae4c108c2af91`.
Subsequent evidence-only commits contain documentation changes only; no executable
or packaging delta separates artifact source from closure HEAD.

Fresh final-artifact raw transcripts are preserved in
`packet-33-36-ubuntu24-raw.txt` and `packet-33-36-ubuntu26-raw.txt`. Each
contains exact source/artifact/driver hashes, isolated distro FUSE/Trio
versions, AppArmor parser/package/securityfs versions, enforcing profile status,
normal confinement, dedicated native allowed `net_admin` evidence, exact one-rule
tightening denial, tightened installed-runtime failure, restored native allowed
evidence, restored success, mounted synthetic-ancestor regression, all 26 learner
case results, and signed remote multi-mount/loss results.

Ubuntu 24.04 certified closure: `python3-pyfuse3 3.3.0-0.1`, Trio `0.24.0`.
Ubuntu 26.04 certified closure: `python3-pyfuse3 3.4.0-3build5`, Trio `0.32.0`.
The versioned final-artifact rerun records AppArmor parser/package/securityfs
versions: Ubuntu 24.04 `4.0.1` / `4.0.1really4.0.1-0ubuntu0.24.04.7` / revision
`829`; Ubuntu 26.04 `5.0.0~beta1` / `5.0.0~beta1-0ubuntu7` / revision `865`.
The kernel-side version is not exposed by either running kernel; the live securityfs
revision is recorded rather than inferred.
Opaque/synthetic ancestors exist only for direct traversal and stat toward known
descendants; profile topology never grants LIST authority. Nested private/overlay
roots do not depend on corresponding host-home ancestors.

The strict CBOR fallback is covered by `tests/unit/test_crypto_cbor.py` (30 focused
cases plus full-suite coverage) and keeps
The composite synthetic-ancestor fix is covered by six focused unit tests and the
installed mounted acceptance driver `scripts/composite_projected_home_acceptance.py`.
Fresh final4 mounted runs passed nested host read, exact root/opaque EACCES listings,
hidden siblings, absent-parent private/overlay mutation, and lower immutability on both releases.
Ubuntu 24.04's older distro decoder fail-closed without ambient `/usr/local` imports.

Integrated Learner Gate is closed only after fresh auditor approval.
