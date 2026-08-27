# Packet 36A final local gate

Implementation commit: `90de0c06aba6392180c865cb3b1572b530d49c73`.
Before this gate, `git status --porcelain --untracked-files=no` was empty and
`git diff --check` passed. The only untracked local paths were harness state
`.pi-glla/` and `context.md`; neither is part of the artifact.

Commands run from the implementation commit:

```text
uv lock --check
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-bwrap-launch.c -o /tmp/aspr-bwrap-launch
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-sandbox-entry.c -o /tmp/aspr-sandbox-entry
cc -std=c11 -O2 -Wall -Wextra -Werror packaging/native/aspr-host-rx.c -o /tmp/aspr-host-rx
apparmor_parser -Q -K packaging/apparmor/usr.libexec.astral-project.aspr-bwrap-launch
./scripts/test
```

All commands exited zero. `./scripts/test` reported `748 passed, 1 skipped`,
strict mypy and Ruff passed, and configured coverage was `100%`
(`10354` statements, `0` missed; `2982` branches, `0` partial).

Evidence commit `c3ff4a0` changes only these provenance records. At that commit,
`git status --porcelain --untracked-files=no` was empty and `git diff --check`
passed; it does not alter the tested implementation or packaged artifact.

The final installed package SHA-256 is
`b02da997a875c721c2bdb550ed6819ae29d083cc147e44c5cde54f2d4607d498`.
Its Ubuntu 24.04 and 26.04 installed transcripts, including the driver hashes,
are preserved in `packet-33-36-ubuntu24-raw.txt` and
`packet-33-36-ubuntu26-raw.txt`.
