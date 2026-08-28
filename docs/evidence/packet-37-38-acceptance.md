# Packets 37–38 acceptance

## Artifact identity

Final installed candidate artifact:

```text
artifact: astral-project_0.1.0_amd64.deb
sha256: c985e3cc0cfcd7e67dfdf3d2b9f943c5b2c32cc4a98e34b378bde6a1696b4fd6
```

The artifact was rebuilt from the closure source tree after the final Landlock,
process-entrypoint, audit-protocol, and profile-audit-sink changes. The final
source closure commit is `4d97d38b153156304baaae566ac778bdfa5a9a09`. Later
commits are evidence-only; `packet-37-38-local-validation.txt` records the
source-tree equivalence check from that closure through the final evidence HEAD.

## Local verification

```text
./scripts/test                         847 passed, 1 skipped; coverage 100%
uv run mypy src tests                   passed
uv run pytest tests/unit/test_audit.py tests/unit/test_hardening.py
                                        45 passed
uv run pytest tests/unit/test_server_protocol.py::test_local_and_remote_audit_events_share_session_correlation
                                        1 passed
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-bwrap-launch.c
                                        passed
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-sandbox-entry.c
                                        passed
apparmor_parser -Q -K packaging/apparmor/usr.libexec.astral-project.aspr-bwrap-launch
                                        passed
python scripts/parser_fuzz.py           passed
```

Immutable local validation transcript:

```text
packet-37-38-local-validation.txt  f13041a2a52e26216c5d677133c272ea794575fab78d70a38a5cd5d95457f757
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

| target | identity | Landlock ABI | required ABI | dependency report | raw transcript |
|---|---|---:|---:|---|---|
| Ubuntu 24.04.4 | kernel 6.8.0-138-generic; AppArmor parser 4.0.1 | 4 | 3 | cbor2 5.6.2; cryptography 41.0.7 | `packet-37-38-ubuntu24-raw.txt` |
| Ubuntu 26.04 LTS | kernel 7.0.0-30-generic; AppArmor parser 5.0.0~beta1 | 8 | 3 | cbor2 5.8.0; cryptography 46.0.5 | `packet-37-38-ubuntu26-raw.txt` |

Raw transcript SHA-256 values:

```text
packet-37-38-ubuntu24-raw.txt  831327bb255ba277be20108aa93746db83f92249ef17f5bdc62ab7bb667ed938
packet-37-38-ubuntu26-raw.txt  6d253511c831198a09d4c6ab429a1b6024308158aea5d617f88c0789ad298244
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

Both targets additionally passed real-kernel Python Landlock isolation: allowed
create/write/truncate succeeded; outside create, mkdir, symlink, truncate, and
refer/link operations were denied with unchanged outside content and directory
entries. The installed failure harness proved `ASPR_HARDENING_UNAVAILABLE`, no
workload marker, and `hardening.failure` audit evidence. Remote retention probes
reported two retained events, a valid chain, private `0600` adjacent lock, and
explicit boundary metadata. Authorized remote audit export is exposed through
the local daemon `audit.remote.export` operation and fixed SSH marker; raw mode
is rejected, while server-side redaction/hash is covered by focused protocol
acceptance.

## Boundary statement

Landlock is applied in the final sandbox payload entrypoint after bubblewrap has
completed UID/GID mapping and mount construction; this preserves the existing
namespace/AppArmor authority boundary while preventing Landlock from blocking
those setup operations. `aspr-homed` applies the same second wall after its FUSE
session is mounted, preserving its already-open FUSE descriptor. No global
AppArmor or sysctl setting was weakened, and no Packet 39+ behavior was added.
