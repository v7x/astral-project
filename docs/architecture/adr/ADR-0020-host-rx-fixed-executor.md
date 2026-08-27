# ADR-0020: Fixed host-rx executor

- **Status:** Accepted
- **Scope:** Packet 36A

## Decision

Projected HOME remains mounted `noexec`. A command whose pathname is beneath
`/home/sandbox/` is admitted only when the loaded profile authorizes its relative
path for `EXECUTE` through `host-rx`. The parent creates a fresh same-UID,
non-writable mode-`0644` manifest containing that one exact sandbox pathname in a
private mode-`0700` runtime directory. The typed sandbox plan carries the manifest
path; the fixed launcher independently validates it and read-only binds it only at
`/tmp/aspr-host-rx.allow`. The leaf need not be secret: its authority is the
read-only bind and exact equality check, while the private directory prevents
ambient host-path discovery.

For such a plan the fixed launcher invokes the fixed sandbox entrypoint with only
`/usr/libexec/astral-project/aspr-host-rx` before the approved command argv. The
helper accepts no other manifest location, requires the fixed pathname prefix and
byte-for-byte manifest equality, opens a non-symlink regular executable, and copies
bounded contents into the exclusive `/tmp/aspr-host-rx.exec` staging leaf. It fixes
that leaf to mode `0500`, closes its writable descriptor, then executes the fixed
staging pathname. The helper is the initial sandbox process; no untrusted sandbox
process exists before this one-way transfer. Both stacked AppArmor profiles allow
execution only of that staging leaf. Manifest and projected-home execution fail
closed on malformed plans, ownership/mode failure, path mismatch, symlink,
replacement, copy failure, or staging collision.

## Security effect

The user cannot turn a writable or readable projected HOME pathname into ambient
execution authority, supply a different executor, change bubblewrap arguments, or
substitute a second approved target after the parent made its policy decision. The
manifest is removed when the sandbox lifecycle ends. `host-rx` remains a deliberate
compatibility exception: it authorizes exactly one profile-checked command, not an
executable HOME mount or general interpreter authority.
