# Packet 9 handoff

## Goal

Remote key opens only Astral protocol.

## Changed

- Added `aspr server ssh-entry --transport-key <id>`.
- Enforced exact `SSH_ORIGINAL_COMMAND=aspr-channel-v1`.
- Added bounded 1 MiB, big-endian length-prefixed canonical-CBOR preface.
- Added `validate`, `open_sftp`, `revoke`, and `health` operation values.
- Added fixed remote trust configuration loader, issuer lookup, signature/context/time verification, nonce-bound binary `ready` and `error` frames.
- Kept diagnostics on stderr. Stdout emits protocol frames only.
- Added parser fuzz target and Packet 9 tests.
- Documented wire contract in `docs/protocol.md`.

## Files

- `src/astral_project/server/protocol.py`
- `src/astral_project/server/entry.py`
- `src/astral_project/server/__init__.py`
- `src/astral_project/cli.py`
- `src/astral_project/core/errors.py`
- `tests/unit/test_server_protocol.py`
- `docs/protocol.md`

## Tests

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest
```

All pass: 147 tests.

## Known failures

None.

## Next

Packet 10: rclone external-SSH release gate.

## Security assumptions

Remote `server.toml` is private, owned by remote user, mode 0600 or stricter. Enrollment must write host identity, allowed transport key IDs, and issuer public keys into it. Packet 9 performs no source path resolution, mount, SFTP launch, or revocation-state mutation.
