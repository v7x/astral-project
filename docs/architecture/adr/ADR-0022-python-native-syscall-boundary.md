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

Packet 12 wrappers passed x86_64 descriptor-resolution tests. Packet 13 mount syscall run is blocked by `EPERM` in present harness namespace. This is inconclusive evidence for enrolled host capability, not success and not a fallback trigger.

## Reconsideration

A compiled helper or extension requires separate ADR only if ctypes cannot express a reviewed syscall ABI. It must retain same narrow boundary.
