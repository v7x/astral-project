# ADR-0022: Python/native syscall boundary

## Problem

Python 3.12 does not expose `openat2`, `open_tree`, `move_mount`, `mount_setattr`, descriptor `statx`, or `fstatfs`.

## Chosen boundary

`src/astral_project/server/linux.py` is sole `ctypes` boundary. It contains fixed ABI structs, syscall numbers, descriptor mount primitives, and no policy, grant parsing, path parsing, subprocess construction, or user interface.

Supported architectures: Linux x86_64/amd64 and aarch64. Others fail with `ENOSYS` before grant use. `open_how` is 24 bytes; `mount_attr` is 32 bytes; the statx buffer is 256 bytes. Structures are zero-initialized by ctypes.

## Review rules

- Every wrapper accepts typed descriptor/bytes values only.
- Every wrapper returns descriptor or raises `OSError`; callers map errors to stable Astral errors.
- No wrapper accepts arbitrary syscall number, string command, policy object, or path-resolution decision.
- Native boundary tests run Packet 12 resolver and Packet 13 probe per supported architecture.

## Present status

Historical Packet 12/13 note: wrappers passed x86_64 descriptor-resolution tests; the development harness then blocked Packet 13 mount syscalls with `EPERM`. Packet 15C–15F later supplied enrolled-host descriptor-pinned execution evidence. This record does not authorize a pathname fallback.

## Reconsideration

A compiled helper or extension requires separate ADR only if ctypes cannot express a reviewed syscall ABI. It must retain same narrow boundary.
