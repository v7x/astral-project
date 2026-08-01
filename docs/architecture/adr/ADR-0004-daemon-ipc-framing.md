# ADR-0004 — Daemon IPC framing

## Problem

Local CLI needs bounded trusted control channel to daemon.

## Chosen

Use Linux pathname `AF_UNIX` socket under private XDG runtime directory. Require `SO_PEERCRED` UID equals daemon UID. Frames are four-byte network-order length plus strict JSON object, maximum 64 KiB. Every request and response carries ASCII request and cancellation IDs. Unknown fields, version, and operation fail closed.

## Rejected

Abstract sockets: mount namespaces cannot hide them. Newline JSON: ambiguous bounds. Generic RPC: would create authority before policy exists.

## Security effect

No cross-UID control; malformed input cannot cause unbounded allocation; Packet 5 exposes only ping, status, and cancellation acknowledgement.

## Tests

Same UID, peer rejection, malformed/truncated/oversized frames, request pairing.

## Reconsider

Only when binary streaming or multiplexing requires versioned replacement protocol.
