# Packet 15 checkpoint remediation plan

Status: approved implementation order after `packet_15_checkpoint_review.md`. No root installation. No `aspr-test` mutation.

## Contract corrections first

1. Keep `CreateNamespaceV1` as sole broker create request. Replace stale wire output with canonical `NamespaceReadyV1 | NamespaceRejectedV1`. `WorkerResultV1` remains internal only.
2. Bind replay entries to `(issuer_key_id, grant_id, client_nonce)`. Grant-envelope nonce is not a per-session replay key.
3. Add complete typed cancellation request and result schemas. No cancellation bytes enter SFTP stream.
4. Require root-configured peer UID and primary GID. Map only those configured values.
5. Give broker I/O bounded deadlines. Timeout occurs before replay consumption or worker launch.
6. Retain `RemoteSessionRequestV1` as sole outer request. Migrate generic preface framing rather than introduce a second request model.

## Authority corrections second

1. Replace global source RW flag with non-overlapping `SourceRootCeilingV1` entries.
2. Reject grant/forbidden-root overlap in either direction.
3. Reject target/control/runtime overlap in either direction, in planner and native worker.
4. Mark display-path nested-mount findings advisory until descriptor/mount-ID topology proof exists.

## Native and runtime corrections third

1. Relocate worker inherited FDs collision-safely before installing fixed ABI positions.
2. Separate SFTP stream FD 6 from log/status FD 7. Stderr never shares SFTP stream.
3. Fix `F_GET_SEALS` error handling, explicit little-endian decode, reserved-target checks, and fixed-FD validation.
4. Replace privileged-path `ldd` discovery with non-executing ELF `PT_INTERP`/`DT_NEEDED` inspection and controlled resolution.
5. Run SFTP handshake in closure-only disposable root. Prove host library/config absence and missing-file failure.

## Enrollment and evidence corrections fourth

1. Serialize forced command from fixed absolute executable and grammar-validated transport key ID.
2. Journal newly created local private-key deletion on smoke failure.
3. Escape TOML records. Harden read-only host probe and label unstable nested-mount evidence advisory.

## Gate

Revised broker/session fixtures, canonical outer remote-session migration, adversarial local tests, native compilation, and full local checks now pass. Closure-only handshake test runs where host user-namespace policy permits; this development host returns policy denial and records skip rather than false acceptance.

Do not resume broker-to-worker integration until this remediation baseline is reviewed. AppArmor deployment, systemd packaging, SCM_RIGHTS runtime stream, root installation, and Packet 15F gate remain deferred.
