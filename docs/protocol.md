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

Unknown version, malformed field set, oversized frame, truncated frame, unrecognized issuer, invalid signature, and wrong command fail closed.
