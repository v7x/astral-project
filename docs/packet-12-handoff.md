# Packet 12 handoff

## Goal

Resolve remote export source without escape and return pinned descriptor.

## Changed

- Added reviewed policy-free Linux syscall boundary: `openat2`, descriptor `statx`, descriptor `fstatfs`.
- Added trusted-root and resolved-source ownership types.
- Resolver uses `O_PATH|O_CLOEXEC|O_NOFOLLOW` and `RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS`.
- Resolver returns canonical display path, owned pinned descriptor, device/inode/mount ID/filesystem/type identity, and nested mount topology.
- Added strict autofs rejection and unsupported-primitive failures.
- Added stable resolver error codes.
- Added ADR-0008.

## Files

- `src/astral_project/server/linux.py`
- `src/astral_project/server/path_resolver.py`
- `src/astral_project/core/errors.py`
- `tests/unit/test_server_path_resolver.py`
- `docs/architecture/adr/ADR-0008-safe-remote-path-resolution.md`

## Tests

```text
uv run ruff format --check .
uv run ruff check .
uv run mypy src tests
uv run pytest
```

All pass: 165 tests.

Coverage includes traversal, absolute/relative symlink escape, symlink loop, proc magic link, rename race, deleted pinned file, autofs mock, mountinfo topology parse, NFS type fixture, and actual descriptor resolution.

## Known limits

No NFS or autofs host was available for live integration. NFS is represented by filesystem-magic fixture; autofs is strict-rejected. Packet 42 must run true filesystem matrix.

## Next

Packet 13: descriptor-pinned staging mount release gate.

## Security assumptions

Trusted roots are configuration-controlled paths opened before grant path handling. Only Linux x86_64/amd64 and aarch64 ABIs are supported by current reviewed syscall boundary. No `openat()` fallback exists. Later code must consume returned descriptor only; it must not reopen `canonical_path`.
