# ADR-0015: Projected-home inode model

- **Status:** Accepted
- **Scope:** Packets 25–32

## Decision

`aspr-homed` assigns synthetic inode numbers to projected paths.  The inode
map is an authorization-neutral cache: every operation re-resolves the
approved path from a pinned lower or upper root descriptor.  Inodes do not
provide authority and are invalid after the projected-home instance closes.

Host and profile metadata are projected with synthetic ownership for the
sandbox uid/gid.  Setuid and setgid bits are never exposed or persisted.
Only regular files and directories are supported in writable state; symlinks,
magic links, device nodes, FIFOs, and sockets are rejected.

## Security effect

A stale inode or renamed path cannot turn into an authorization grant, and a
path cache cannot cause an absolute-path reopen.  Descriptor-relative,
`O_NOFOLLOW` traversal remains the authority boundary.

## Tests

The homed core, host, private, and overlay tests cover synthetic inode lookup,
close invalidation, lower/upper selection, symlink rejection, metadata
projection, and writable-node restrictions.

## Reconsideration trigger

Revisit only if a future packet requires stable inode identity across daemon
restarts or a broader POSIX node model, with a new security review.
