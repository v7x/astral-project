# Packets 30–32 writable projected-home handoff

The writable backends are `PrivateWritableBackend` and `OverlayBackend`.
Private state is kept below an application-owned per-profile directory and
uses descriptor-relative `O_NOFOLLOW` traversal. Overlay state keeps a pinned
lower root read-only and writes only to the profile upper root.

Overlay deletions use hidden `.wh.<basename>` markers. Metadata mutations are
serialized by the per-profile lock and recorded in the upper-root SQLite WAL
journal with FULL synchronous mode. Copy-up writes a temporary upper file,
fsyncs it, atomically renames it, and fsyncs the parent directory. Startup
recovery removes abandoned temporary files and completes unfinished lower
hide operations.

The first release deliberately returns stable errors for symlinks, special
nodes, hardlinks, xattrs, mmap, POSIX locks, and cross-rule-root rename.
Setuid/setgid bits are cleared and projected ownership is synthetic. The
lower root is never a mutation target. Profile identifiers are validated as
single safe path components before they can select persistent storage. Installed
writable FUSE acceptance is recorded in
`docs/evidence/packet-30-32-ubuntu26-raw.txt`.

Packet 33 profile commands and sealing are outside this handoff.
