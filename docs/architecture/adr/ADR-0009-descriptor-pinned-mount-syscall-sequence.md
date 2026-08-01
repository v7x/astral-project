# ADR-0009: descriptor-pinned staging mount syscall sequence

## Problem

Remote helper must attach exact object opened during grant validation. Reopening canonical pathname permits source-replacement race.

## Chosen sequence

1. Open source with Packet 12 `openat2()` and retain `O_PATH` descriptor.
2. Create detached bind mount with `open_tree(source_fd, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_EMPTY_PATH)`.
3. Apply `mount_setattr(mount_fd, "", AT_EMPTY_PATH, {attr_set=MOUNT_ATTR_RDONLY})` for RO export.
4. Attach only detached mount with `move_mount(mount_fd, "", AT_FDCWD, staging_target, MOVE_MOUNT_F_EMPTY_PATH)`.
5. Close detached-mount fd. Staging mount retains object reference.

No source pathname appears after step 1. Staging target is trusted runtime state, not grant input.

## ABI and errno assumptions

Linux x86_64/amd64 syscall numbers: `open_tree=428`, `move_mount=429`, `mount_setattr=442`. Linux aarch64 uses same three numbers. `struct mount_attr` is four zero-initialized `u64` fields, 32 bytes. A failure result records exact stage, syscall, flags, and errno. `EPERM` is not interpreted until syscall trace and AppArmor audit evidence identify denied operation. No pathname fallback occurs.

## Rootless backend gate

Ordinary Python is intentional negative control. On Ubuntu generic `unprivileged_userns` AppArmor, an `EACCES` or `EPERM` writing identity maps after successful user-namespace creation is reported exactly as `unsupported`, backend `direct_unprofiled_python`, stage `uid_gid_map`, reason `apparmor_denied_identity_map`. It is not pinning failure.

Positive rootless path uses parent/child setup. Parent captures UID/GID before child calls `unshare(CLONE_NEWUSER)`. Parent writes child map files; child must never derive parent identity after `unshare`. Host-policy denial is `unsupported`; invariant breach is `failed`; only unknown environmental failure is `inconclusive`.

Caller-selectable `aa-exec` setup profile is rejected: it lets unprivileged caller select profile that grants setup authority. Admin-assisted backend is deferred to ADR-0023. Hard acceptance remains pending a `result=passed` run on separate supported rootless host.

## Rejected choices

- `/proc/self/fd/<n>` bind source: requires separate adversarial proof; rejected.
- checked pathname bind mount: source replacement race; rejected.
- `openat()` fallback: cannot replace `openat2()` guarantees; rejected.

## Reconsideration

Run same probe on enrolled remote host outside harness mount syscall restrictions. Only a `result=passed` run for every supported CPU/filesystem permits Packet 14.
