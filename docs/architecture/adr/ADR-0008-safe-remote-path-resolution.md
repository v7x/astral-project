# ADR-0008: safe remote path resolution

## Problem

Grant source strings may be raced, contain traversal, symlinks, magic links, mount transitions, or autofs triggers. Validation must return pinned descriptor, not later-reopened path string.

## Choices

1. Validate string then open pathname.
2. Component-by-component `openat()` fallback.
3. Descriptor-relative Linux `openat2()` with strict resolution flags.

## Chosen choice

Use `openat2()` from trusted root `O_PATH` descriptor with:

```text
O_PATH | O_CLOEXEC | O_NOFOLLOW
RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS
```

Python 3.12 has no `os.openat2`, so `src/astral_project/server/linux.py` is sole reviewed, policy-free `ctypes` syscall boundary. It supports only Linux x86_64/amd64 and aarch64 syscall ABIs. Other architecture or unavailable syscall fails closed.

After open, identity comes from descriptor-only `statx(AT_EMPTY_PATH, STATX_BASIC_STATS | STATX_MNT_ID)` and filesystem type from descriptor-only `fstatfs()`. Mount topology comes from fixed `/proc/self/mountinfo`; it does not reopen source. Regular files and directories only. Symlinks, magic links, devices, FIFOs, and sockets fail. Autofs `f_type=0x0187` fails strict mode pending matrix proof.

No component-dirfd fallback exists. It was not proven equal to kernel-enforced `openat2()` semantics under rename and symlink races.

## Security effect

Source is resolved below pre-opened trusted root. Descriptor remains valid after path deletion or rename. Metadata is bound to same descriptor. No checked source path is reopened.

## Rejected choices

String validation followed by pathname reopen has source-replacement race. `openat()` fallback needs broad adversarial proof and cannot be silently substituted.

## Tests

Packet 12 tests cover traversal forms, absolute and relative symlink escapes, symlink loops, rename race, deleted source descriptor, filesystem/mount metadata, NFS type fixture, and mocked autofs rejection.

## Reconsideration trigger

Add architecture only after ABI review and syscall tests. Add component fallback only after proof equal to strict `openat2()` behavior. Permit autofs only after Packet 42 filesystem matrix evidence.
