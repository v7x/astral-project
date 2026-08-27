# ADR-0018: Overlay metadata and whiteout format

- **Status:** Accepted
- **Scope:** Packets 31–32

## Decision

The upper root stores a deletion marker named `.wh.<basename>` beside the
hidden lower entry.  Marker names are reserved from projected paths and are
never returned by merged directory listings.  A marker hides the matching
lower entry, including an entry below a hidden ancestor.

Overlay metadata mutations are serialized by a per-profile lock and recorded
in a crash-recoverable journal.  The journal uses SQLite WAL with FULL
synchronous durability; temporary copy-up files are descriptor-relative and
become visible only after an atomic same-directory rename and directory
`fsync`.  Recovery removes abandoned temporary files and restores the
unfinished whiteout/rename intent without touching the lower root.

## Security effect

Deletion is represented only in profile-owned state.  The lower root is opened
read-only and is never a mutation target.  Reserved metadata cannot be used as
an escape or hidden control channel, and incomplete mutations fail closed.

## Tests

Overlay tests cover whiteout persistence, lower-change visibility, copy-up,
merged listings, lower immutability, concurrent copy-up, mutation recovery,
and randomized model equivalence.

## Reconsideration trigger

Revisit if a supported kernel/filesystem requires a different whiteout
representation or if broad POSIX semantics (hardlinks, mmap, xattrs, leases,
or exotic locks) are deliberately added.
