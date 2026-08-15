# Astral Project target-architecture UML

These PlantUML models summarize current Packet 15 architecture and planned local-agent features. Remote diagrams describe implemented broker/worker execution, not a bubblewrap production backend.

## Diagram set

- `01-system-components.puml` — principal components, trust boundaries, and restricted interfaces.
- `02-deployment.puml` — local host, sandbox, SSH channel, and remote host deployment.
- `03-remote-session-sequence.puml` — establishment of a capability-scoped SFTP session.
- `04-profile-learning-sequence.puml` — mediated projected-home access and trusted approval.

## Architectural reading

The system establishes two independent boundaries:

1. A signed grant enters remote `aspr-server`/broker request. Root broker authenticates peer, independently checks grant and server ceiling, resolves sources under target-user DAC, pins descriptors, seals bounded plan, and delegates private synthetic-root construction to mapped namespace/mount worker. Fixed `sftp_v1` runs after setup-authority removal.
2. An optional local sandbox hides unrelated host data. A FUSE projected home mediates every approved home-directory operation.

The local daemon owns ambient authority. Neither the agent sandbox nor `aspr-transport` receives a signing key, SSH private key, unrestricted daemon socket, generic mount authority, or general remote-login capability.

Render any source with PlantUML, for example:

```sh
plantuml -tsvg docs/architecture/uml/*.puml
```

## Sources

- `docs/architecture/plain-english/astral-project-final-architecture.md`, especially sections 4–6, 10–14, and 17–19.
- `docs/protocol.md`.
- Architecture decisions ADR-0003, ADR-0004, ADR-0007, ADR-0008, ADR-0009, ADR-0022, ADR-0023, and ADR-0024.

