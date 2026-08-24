# Packets 16–19 acceptance evidence

Acceptance uses packaged artifacts, live signed grants, fixed SSH transport, and
ADR-0007 rclone binaries.

Machine-checkable raw command records are in `docs/evidence/daemon-ls-matrix.json`;
the matrix driver is `scripts/daemon_ls_matrix_acceptance.py`. Each row stores
the exact SSH command, package/gate preflight output, acceptance stdout and
stderr, parsed result, base64 protocol bytes, and SHA-256 for every output.

| Target | Package | rclone | SHA-256 | Grant / session | Result |
|---|---|---:|---|---|---|
| Ubuntu 26.04 amd64 | `astral-project 0.1.0` | 1.73.3 | `41bd63149d3bd281f9d8fb02fd8c0406234634a59cd0f591b86ad3f1e2f6abb7` | `7887d3f6-5422-4dad-9979-41a3e37f8243` / `a8dcf832-faed-447c-a1c9-7e696d09ff1e` | pass |
| Ubuntu 26.04 amd64 | `astral-project 0.1.0` | 1.74.4 | `9f56ca5edfac24a3ed37226c2ba1de69f1ec9e05fa2526cddee5cd97e202be6b` | `f35738ea-d5e8-4fd7-8de2-c3db632ce19b` / `fb087b72-53e5-4f33-9829-0d94790f6e7a` | pass |
| Ubuntu 24.04 amd64 | `astral-project 0.1.0` | 1.73.3 | `41bd63149d3bd281f9d8fb02fd8c0406234634a59cd0f591b86ad3f1e2f6abb7` | `7043ebd7-5ee0-4dbc-934e-5b9e773598a3` / `3f918975-9cd3-4c22-adea-abe116a41e41` | pass |
| Ubuntu 24.04 amd64 | `astral-project 0.1.0` | 1.74.4 | `9f56ca5edfac24a3ed37226c2ba1de69f1ec9e05fa2526cddee5cd97e202be6b` | `3edeb248-7aa5-4e95-8c83-82ee25c802eb` / `4e2fbf55-ed2c-41fa-beef-3c966a6aa0dd` | pass |

Each row ran packaged daemon-backed `aspr ls` against a live active signed
session. The exact result shape was identical in all four rows:

```text
table       exit=0, exact root table (fixture directory + allowed.txt), stderr empty
json        exit=0, exact normalized JSON version 1, stderr empty
raw         exit=0, exact rclone JSON framing/fields, stderr empty
recursive   exit=0, exact nested entry at --recursive --max-depth 2 and no depth-3 entry, stderr empty
timeout     exit=70, stdout empty, stderr contains "rclone listing timed out"
alternate   exit=70, stdout empty, stderr contains "selects another grant or host"
traversal   exit=70, stdout empty, stderr contains "contains traversal"
ungranted   exit=70, stdout empty, stderr contains "outside bound export"
```

The matrix invokes the installed `/usr/bin/aspr` CLI and its installed
`aspr __internal daemon`; the harness imports only `/usr/lib/astral-project/python`
and contains no in-process `DaemonServer` or source-tree import. Each pin is
installed at the daemon's fixed `/usr/bin/rclone` path immediately before its
row. The timeout path exercises daemon cancellation of the bounded rclone process;
all diagnostics remained off protocol stdout. The four negative controls prove
alternate-grant, traversal, and ungranted-path requests fail closed.

Packaged installation evidence on both targets:

```text
Ubuntu 26.04: astral-project 0.1.0; packet15f-gate exit=0 (separate command)
Ubuntu 24.04: astral-project 0.1.0; packet15f-gate exit=0 (separate command)
```

Commands:

```text
./scripts/test                         => 494 passed, 1 skipped; 100% coverage
uv run ruff check .                     => All checks passed
uv run mypy src                         => Success: no issues found in 68 source files
git diff --check                        => exit 0
sudo /usr/libexec/astral-project/packet15f-gate => exit 0 on both targets
python scripts/daemon_ls_acceptance.py <rclone> <identity> <issuer-key> <host-id> <fingerprint>
```

Packet 15 authority remained unchanged: no AppArmor weakening, namespace
boundary change, capability broadening, or grant-revocation lifecycle was
introduced.
