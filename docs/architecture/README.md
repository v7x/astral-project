Agents should read documents in the caveman directory, humans should read documents in the plain-english directory.

Packet-number authority is defined by `adr/ADR-0025-packet-numbering-authority.md`:

- final architecture + accepted ADRs govern security/product semantics;
- current implementation plans govern packet numbers, order, and packet scope;
- the latest handoff/acceptance documents govern the current implementation entry point and completed evidence;
- the packet schedule embedded in the final architecture is historical and must not override the current implementation-plan numbering.

When a disagreement is substantive rather than merely numbering/decomposition drift, stop and reconcile it by ADR before implementation.
