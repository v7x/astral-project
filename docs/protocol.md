# Remote preface protocol v1

Remote forced command accepts only `SSH_ORIGINAL_COMMAND=aspr-channel-v1`.

Before SFTP traffic, client sends one frame:

```text
uint32 big-endian payload length
canonical CBOR payload, at most 1 MiB
```

Payload exact fields:

```text
version: 1
operation: validate | open_sftp | revoke | health
nonce: bytes, 1..64 bytes
grant: canonical-CBOR SignedGrant bytes
```

Remote helper loads enrolled issuer key, verifies signed grant, then verifies host ID, SSH host-key fingerprint, remote user, validity window, and extensions. No path work may begin first.

Response uses same framing. `ready` and post-parse `error` responses echo request nonce. Diagnostics go only to stderr. Stdout contains framed binary protocol bytes only.

Readiness contract for the remote SFTP bridge:

```text
remote request authenticated
→ broker creates and registers confined worker
→ NamespaceReadyV1
→ RemoteSessionReadyV1
→ raw SFTP stream begins
→ client sends SSH_FXP_INIT
→ server returns SSH_FXP_VERSION
```

`RemoteSessionReadyV1` means the authenticated, confined SFTP byte stream is established and ready to receive client `SSH_FXP_INIT`. It does not mean SFTP VERSION exchange occurred. The bridge must not consume or synthesize client negotiation before this readiness point. Existing `revoke` framing may be validated by Packet 16D; new grant-lifecycle machinery remains later work.

Unknown version, malformed field set, oversized frame, truncated frame, unrecognized issuer, invalid signature, and wrong command fail closed.
