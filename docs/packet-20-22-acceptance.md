# Packets 20-22 acceptance evidence

Packets 20-22 now use durable grant, session, and mount records. Grant lifecycle
requires remote validation before signing, explicit approval for canonical
changes, local-first revocation, and audit events. Mount creation is daemon-owned:
fixed rclone and transport paths, private ephemeral config/cache, positive FUSE
readiness, health reconciliation, bounded drain/unmount, stale recovery, and
expiry/revocation enforcement.

## Packaged VM acceptance

Each row used installed `astral-project 0.1.0`, installed `/usr/bin/aspr`,
installed `aspr __internal daemon`, a production `StateDatabase` session, and a
root-owned pinned `/usr/bin/rclone`. No source package was imported by daemon or
CLI. Mount command performed read I/O, then close; output state was `ready` then
`closed`.

| Target | rclone | Grant | Session | Mount | Result |
|---|---:|---|---|---|---|
| Ubuntu 26.04 amd64 | 1.73.3 | `5986ab65-034e-4839-9943-78ecfa6bd9d6` | `f7b747a2-23de-47a5-8e2c-9e1abdeb395b` | `fbfc33eabc2be2e96d62d13a32d3c54f` | pass |
| Ubuntu 26.04 amd64 | 1.74.4 | `78bd0ee5-04a6-4fcd-8294-1d7c9ee290c3` | `96a9c41e-fdf6-496f-937d-3ba0a591b22e` | `08e61eb1fe0b9886a975e5f3212490f4` | pass |
| Ubuntu 24.04 amd64 | 1.73.3 | `4ad24004-0782-42d4-b962-ad924646d21f` | `fd05fd62-5258-431d-91b9-2438a821d2f6` | `f93dbf3854607ec1712d3393aaedfa2f` | pass |
| Ubuntu 24.04 amd64 | 1.74.4 | `1f183320-5145-4d05-99b1-3343464b9465` | `17deaf5d-5731-4366-82a6-5eb09ebd4ef8` | `7a4c82e49b6cbab40e64e50c4e607999` | pass |

Packet 15F gate returned exit `0` independently during package installation
on both targets. Existing listing matrix remains at
`docs/evidence/daemon-ls-matrix.json`.

## Local verification

- `./scripts/test`: 523 passed, 1 skipped, 100% branch coverage.
- Ruff and mypy pass.
- Packaged mount acceptance passed on both Ubuntu targets and both rclone pins.
