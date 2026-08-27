# ADR-0017: Trusted terminal transition

- **Status:** Accepted
- **Scope:** Packets 28–36

## Decision

Interactive learning uses a parent-controlled PTY. Only the parent intercepts
`Ctrl-]`, suspends child input, presents the pending request, and applies a decision
to the mediator. Homed reports mediation requests over a separate private transport;
that transport cannot carry approval decisions. External decisions are enabled only
by explicit `--external` mode, bind an exact live session and request number, and are
never mounted into the sandbox.

## Security effect

Child output, a same-UID process that finds the mediation endpoint, and observer
output cannot impersonate interactive approval. Replay and wrong-session external
decisions fail closed.
