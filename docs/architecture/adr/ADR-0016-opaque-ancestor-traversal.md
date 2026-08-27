# ADR-0016: Opaque ancestor traversal

- **Status:** Accepted
- **Scope:** Packets 26–36

## Decision

When a profile has a known nested rule, its ancestors are opaque. Lookup and stat
may traverse an opaque ancestor only to reach the known descendant. `readdir` remains
denied, no sibling authority follows, and no mediation prompt occurs for this sealed
traversal. For sealed profiles, unknown paths return `ENOENT` for `unknown_sealed =
"hide"` and `EACCES` for `unknown_sealed = "deny"`.

## Security effect

Exact nested authorization works without turning parent directories into discovery
or metadata grants.
