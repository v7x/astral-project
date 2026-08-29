# Astral Project architecture UML

These PlantUML models join the Revision 3 target architecture to the implementation presently represented by the repository. Color and notes distinguish implemented Packet-15 remote machinery from partial and future work. They are not a declaration that the complete product is operational.

## Diagram set

- `01-system-components.puml` — target components, implemented components, trust boundaries, and restricted interfaces.
- `02-deployment.puml` — present remote deployment and the future local sandbox deployment.
- `03-remote-session-sequence.puml` — implemented forced-command, broker, native-worker, and SFTP path; local transport integration remains pending.
- `04-profile-learning-sequence.puml` — future mediated projected-HOME access and trusted approval.

## Status convention

- Green — implemented in the current repository.
- Amber — partially implemented or awaiting end-to-end integration.
- Gray — target architecture not yet implemented.

“Implemented” describes code presence, not completion of the external Ubuntu security gate or full SFTP acceptance. The remote backend now uses a systemd-activated root broker and native Linux namespace/mount worker; it does not use bubblewrap. The local `rclone`, `aspr-transport`, `aspr-homed`, projected-HOME, and agent-sandbox path remains future work. Replay-ledger and broker-audit schemas exist, but no durable replay or audit sink is wired into the running broker; Landlock is presently probe metadata only.

## Security reading

The implemented remote path separates three authorities:

1. The enrolled-user forced-command entry authenticates the outer request before privileged dispatch.
2. The root broker authenticates its Unix peer, independently validates the signed grant and per-root server ceiling, pins source descriptors, seals the execution plan, and retains expiry and worker-reaping authority.
3. The native worker receives a fixed descriptor ABI, constructs a synthetic root, drops setup authority, enters the fixed AppArmor profile, and executes only the verified `sftp_v1` runtime.

The target local boundary shall add an independent projected-HOME and sandbox policy. Neither the future agent sandbox nor transport helper should receive signing keys, SSH private keys, the privileged broker socket, generic mount authority, or profile-approval power.

Render the sources with PlantUML:

```sh
plantuml -tsvg docs/architecture/uml/*.puml
```

## Implementation sources

- `src/astral_project/server/entry.py` and `server/broker_bridge.py`
- `src/astral_project/broker/`
- `src/astral_project/session/ceiling.py`
- `src/astral_project/runtime/`
- `packaging/native/aspr-mount-worker.c`
- `packaging/systemd/` and `packaging/apparmor/`
- `docs/protocol.md` and the Packet 15 handoff documents

## Target-architecture sources

- Revision 3 proposed final architecture.
- Architecture decisions ADR-0003, ADR-0004, ADR-0007, ADR-0008, ADR-0009, ADR-0022, ADR-0023, and ADR-0024.
