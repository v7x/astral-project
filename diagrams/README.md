# Astral Project target-architecture UML

These PlantUML models summarize Revision 3 of the proposed final architecture. They describe the intended stable system, not merely the packets presently implemented.

## Diagram set

- `01-system-components.puml` — principal components, trust boundaries, and restricted interfaces.
- `02-deployment.puml` — local host, sandbox, SSH channel, and remote host deployment.
- `03-remote-session-sequence.puml` — establishment of a capability-scoped SFTP session.
- `04-profile-learning-sequence.puml` — mediated projected-home access and trusted approval.

## Architectural reading

The system establishes two independent boundaries:

1. A signed grant limits remote visibility to enumerated paths and access modes. The remote helper pins those sources before constructing an otherwise empty namespace.
2. An optional local sandbox hides unrelated host data. A FUSE projected home mediates every approved home-directory operation.

The local daemon owns ambient authority. Neither the agent sandbox nor `aspr-transport` receives a signing key, SSH private key, unrestricted daemon socket, generic mount authority, or general remote-login capability.

Render any source with PlantUML, for example:

```sh
plantuml -tsvg docs/architecture/uml/*.puml
```

## Sources

- `docs/architecture/plain-english/astral-project-final-architecture.md`, especially sections 4–6, 10–14, and 17–19.
- `docs/protocol.md`.
- Architecture decisions ADR-0003, ADR-0004, ADR-0007, ADR-0008, ADR-0009, ADR-0022, and ADR-0023.

