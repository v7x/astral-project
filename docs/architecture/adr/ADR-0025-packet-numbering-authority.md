# ADR-0025: Packet numbering authority

## Status

Accepted.

## Problem

The architecture and implementation documents describe the same remaining local-sandbox/profile work with two different packet decompositions.

`docs/architecture/plain-english/astral-project-final-architecture.md`, section 21, retains an older context-window schedule in which, for example, Packet 20 is the FUSE core, Packet 21 combines the policy matcher with host-backed read-only access, Packet 26 is trusted approval, and Packet 27 is profile schema/commands/sealing.

The current implementation plans and the Packet 23–24 handoff use the later, finer-grained sequence in which Packets 23–24 are already completed and Packet 25 is the FUSE core. Leaving both numberings apparently authoritative makes packet-scoped work ambiguous and can cause an implementation agent to pull later functionality into an earlier packet.

This is numbering and work-decomposition drift, not a disagreement about the security architecture itself.

## Decision

Use the following authority order:

1. **Security and product semantics:** the final architecture and accepted ADRs govern invariants, authority boundaries, required behavior, and release claims.
2. **Packet numbers, implementation order, and packet scope:** the current implementation plans govern. The plain-English and caveman implementation plans must agree.
3. **Current entry point and completed evidence:** the latest packet handoff and acceptance documents govern repository state and what has already passed.
4. If documents disagree about a substantive security or product requirement rather than merely numbering/decomposition, stop and write or amend an ADR before implementation.

Accordingly, section 21 of the plain-English final architecture is retained for historical rationale and semantic requirements, but its packet numbers and prerequisites are **superseded** by the current implementation plans. Its headings must not be used to determine current packet scope.

No implementation behavior changes by this ADR.

## Canonical current packet map from the present handoff

The current core sequence is:

| Packet | Canonical scope |
|---|---|
| 23 | Local sandbox foundation |
| 24 | Pre-mounted remote views and narrow session capability |
| 25 | Projected-home FUSE core |
| 26 | Profile schema and deterministic policy matcher |
| 27 | Host-backed read-only projected-home access |
| 28 | Unknown-path mediation |
| 29 | Trusted approval interface |
| 30 | Private writable profile state |
| 31 | Overlay reads and copy-up |
| 32 | Overlay mutation, whiteouts, and recovery |
| 33 | Profile management and sealing |
| 34 | Environment, PATH, and inherited file descriptors |
| 35 | Sockets and credentials |
| 36 | Integrated `profile learn` |
| 37 | Audit system |
| 38 | Landlock and process hardening |
| 39 | Remote adversarial suite |
| 40 | Local adversarial suite |
| 41 | Rclone compatibility matrix |
| 42 | Filesystem, distribution, and harness compatibility matrix |
| 43 | Packaging and service lifecycle |
| 44 | Operations and incident-response documentation |
| 45 | Optional generic MCP adapter, post-core |
| 46 | Declarative compatibility recipes, post-core |
| 47 | Restricted-user-namespace backend design, separate project phase |

For the immediate next grouped goal, this freezes the scope as:

- **Packet 25:** empty, reliable projected-home FUSE core only;
- **Packet 26:** pure profile schema and matcher, without profile lifecycle commands or sealing;
- **Packet 27:** host-backed read-only access through that matcher;
- profile management/sealing remains Packet 33;
- trusted approval remains Packet 29.

## Legacy final-architecture crosswalk

The old section-21 decomposition maps to the current implementation plan as follows:

| Legacy final-architecture packet | Current packet(s) |
|---|---|
| 19 local sandbox + pre-mounted remotes | 23 + 24 |
| 20 FUSE core | 25 |
| 21 matcher + host-backed read-only | 26 + 27 |
| 22 unknown mediation | 28 |
| 23 private writable state | 30 |
| 24 overlay read/copy-up | 31 |
| 25 overlay mutation | 32 |
| 26 approval broker | 29 |
| 27 profile schema/commands/sealing | 33 |
| 28 environment/sockets/credentials/descriptors | 34 + 35 |
| 29 integrated learner | 36 |
| 30 hardening | 38 |
| 31 remote adversarial suite | 39 |
| 32 local adversarial suite | 40 |
| 33 compatibility/filesystem matrix | 41 + 42 |
| 34 packaging/operations/documentation | 43 + 44 |
| 35 optional MCP/recipes | 45 + 46 |
| 36 restricted-userns backend | 47 |

Packet 37 (audit) is an explicit packet in the current implementation plan and precedes current Packet 38 hardening.

## Security effect

This decision prevents packet-number ambiguity from widening scope. In particular, an agent assigned Packets 25–27 cannot treat legacy final-architecture Packet 27 as permission to implement profile commands, sealing, approval authority, writable state, or later ambient-authority policy.

The final architecture remains authoritative for the semantics those later packets must eventually implement.

## Rejected choices

- **Make the old final-architecture numbering authoritative.** Rejected because Packets 23–24 have already been implemented, accepted, and handed off under the current implementation numbering; reverting numbering would invalidate existing evidence and handoffs without improving the design.
- **Renumber every historical architecture paragraph.** Rejected because it creates broad editorial churn and risks changing semantic prose merely to repair labels. The explicit authority rule and crosswalk remove the ambiguity without rewriting architectural history.
- **Allow agents to choose whichever numbering fits a task.** Rejected because packet scope is a security boundary against premature authority and feature creep.

## Tests / verification

Documentation review must verify:

- both implementation plans identify Packet 25 as FUSE core, Packet 26 as profile schema/matcher, and Packet 27 as host-backed read-only access;
- the Packet 23–24 handoff names Packet 25 as the next implementation entry point;
- future handoffs cite this ADR when legacy final-architecture packet numbers could be ambiguous.

## Reconsideration trigger

Amend this ADR only if the project deliberately adopts a new canonical packet plan. Such a change must update both implementation-plan editions and the current handoff together; it must not occur implicitly through edits to the final architecture's historical context-window schedule.
