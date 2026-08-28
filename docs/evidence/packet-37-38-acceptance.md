# Packets 37–38 acceptance

## Artifact identity

Final installed candidate artifact:

```text
artifact: astral-project_0.1.0_amd64.deb
sha256: d4f6917b95e37fa86fb594936e44721a643404edcd8fd5c4bcc1a5a0fac0a042
```

The artifact was rebuilt from the closure source tree after the final Landlock,
process-entrypoint, audit-protocol, and profile-audit-sink changes. The final
source closure commit is `e5e2fa0252709250d7c581210b7723513dec5d5f`.

## Local verification

```text
./scripts/test                         819 passed, 1 skipped; coverage 100%
uv run mypy src tests                   passed
uv run pytest tests/unit/test_audit.py tests/unit/test_hardening.py
                                        passed
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-bwrap-launch.c
                                        passed
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-sandbox-entry.c
                                        passed
apparmor_parser -Q -K packaging/apparmor/usr.libexec.astral-project.aspr-bwrap-launch
                                        passed
python scripts/parser_fuzz.py           passed
```

The full suite includes audit schema, path redaction and hashing, malformed-old-
event handling, chain links, rotation and retention, Landlock availability and
fail-closed branches, no-new-privileges, capability and rlimit controls, core
dump suppression, secure temporary directories, protocol rejection, and native
entrypoint adversarial cases.

## Installed Ubuntu acceptance

The same package was installed with `dpkg -i` on both disposable targets. The
raw transcripts are checked in, retain the native AppArmor audit records, and
end with an explicit PASS marker:

| target | identity | Landlock ABI | dependency report | raw transcript |
|---|---|---:|---|---|
| Ubuntu 24.04.4 | kernel 6.8.0-138-generic; AppArmor parser 4.0.1 | 4 | cbor2 5.6.2; cryptography 41.0.7 | `packet-37-38-ubuntu24-raw.txt` |
| Ubuntu 26.04 LTS | kernel 7.0.0-30-generic; AppArmor parser 5.0.0~beta1 | 8 | cbor2 5.8.0; cryptography 46.0.5 | `packet-37-38-ubuntu26-raw.txt` |

Raw transcript SHA-256 values:

```text
packet-37-38-ubuntu24-raw.txt  17ddc026ea7fd326abb5d21380466286647f8637ffc720675c7dbc0cd7fb4f2a
packet-37-38-ubuntu26-raw.txt  e2faadbb24f9d854ccb874f50928c585987c0ac5930babf9e1c0efa30414b993
```

Both installed runs passed the existing mount-namespace/AppArmor capability
and mediation acceptance: normal mount and userns audit records were present,
allowed `net_admin` was observed, the tightened profile denied it, the tightened
runtime failed closed, and the production profile was restored. The same runs
also passed payload `NoNewPrivs`, zero capability sets, empty network controls,
DNS/credential/socket absence, and native argument negative controls.

Both targets additionally passed the installed local daemon doctor/audit
surface and remote-state audit probe. Audit files were owner-private mode 0600;
secret-field insertion was rejected; default export replaced `/srv/secret` with
`<redacted>`; explicit hash export emitted the deterministic SHA-256
`4ad31b31998673d416d98575bcb234477372b14db707ef2f587514bc5af0ac19`.
Daemon audit listing reported an empty chain-error set and versioned
`hardening.status` events. No private key, credential, file content, or secret
environment value was included in the probes.

## Boundary statement

Landlock is applied in the final sandbox payload entrypoint after bubblewrap has
completed UID/GID mapping and mount construction; this preserves the existing
namespace/AppArmor authority boundary while preventing Landlock from blocking
those setup operations. `aspr-homed` applies the same second wall after its FUSE
session is mounted, preserving its already-open FUSE descriptor. No global
AppArmor or sysctl setting was weakened, and no Packet 39+ behavior was added.
