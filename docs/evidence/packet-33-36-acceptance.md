# Packets 33–36 acceptance

## Local verification

- Latest exact `./scripts/test`: `748 passed, 1 skipped, 9 warnings`, strict mypy and Ruff passed.
  It covers profile lifecycle, strict schema migration, mediation, private/overlay
  state, environment and resource policy (including production PATH visible-root
  wiring), native sandbox ABI, remote binding forwarding, learner persistence, and
  failed-learning draft rollback, epoch-zero provenance round-trips, and invalid UTF-8
  profile rejection through the stable CLI failure path.
- Latest exact `./scripts/test` coverage: `TOTAL 10354 0 2982 0 100%`.
- `uv run ruff check src tests scripts` passes.
- `uv run mypy` passes in strict mode.
- Native launcher compiles with `-std=c11 -O2 -Wall -Wextra -Werror`.

## Packaged environments

Run, as unprivileged user, after installing built wheel:

```text
python3 scripts/profile_boundary_acceptance.py
python3 scripts/writable_home_acceptance.py
python3 scripts/learner_acceptance.py
python3 scripts/learner_interactive_acceptance.py
```

Repeat on Ubuntu 24.04 and Ubuntu 26.04. Preserve raw stdout, installed wheel
SHA-256, package versions, and command identity in:

- `docs/evidence/packet-33-36-ubuntu24-raw.txt`
- `docs/evidence/packet-33-36-ubuntu26-raw.txt`

Acceptance must include both trusted interactive learner approval and external
noninteractive approval, second-project reuse, sealed known-path restart, unrelated
home hiding, observer-disabled operation, credential strong-confirmation denial, raw-
socket opt-in denial, and an installed sandbox child connecting to an exact approved
pathname socket. The raw Ubuntu transcripts preserve each command's output and exit
status.
The learner's repeated `--remote` arguments are forwarded with the selected signed
grant and are mounted and torn down by the daemon workflow. No approval socket or
secret value may enter sandbox namespace or diagnostic output. Native launcher ABI
changes must be rebuilt from
`packaging/native/aspr-bwrap-launch.c` and installed with the tested artifact.
