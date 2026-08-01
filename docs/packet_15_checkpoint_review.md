Review scope: assess only work reasonably expected through the current point in Packet 15. Do not treat later-packet omissions—systemd packaging, AppArmor deployment, full SFTP acceptance, rclone integration, expiry supervision, or the external Ubuntu gate—as defects yet.

Overall assessment:

The implementation is directionally strong. Canonical CBOR, exact-field decoding, signed grants, deterministic namespace planning, descriptor-slot execution plans, sealed memfds, fixed native worker interfaces, and explicit runtime-closure construction are consistent with the architecture.

Before further broker/worker integration or any root installation, address the following findings.

# Blocking findings

## 1. Fix collision-unsafe worker FD remapping

File:

```text
src/astral_project/broker/mapping.py
```

The child blindly maps synchronization pipes onto FDs 3 and 4:

```python
os.dup2(ready_write, 3)
os.dup2(continue_read, 4)
os.close(ready_write)
os.close(continue_read)
```

This fails when the source descriptors themselves are 3 or 4. For example, moving FD 4 onto FD 3 and later closing FD 4 may close a newly installed continuation descriptor.

Required correction:

* implement collision-safe FD relocation;
* move all source FDs which overlap fixed destinations to unused high-numbered descriptors first;
* then install the final fixed layout;
* use `dup3(..., O_CLOEXEC)` where appropriate;
* close only descriptors whose identity is known not to equal a required destination;
* fail closed on any relocation error.

Required tests:

* invoke the worker with FDs 3 and 4 initially free;
* invoke it with only FD 3 occupied;
* invoke it with only FD 4 occupied;
* invoke it with both occupied;
* prove the worker receives the correct two synchronization channels in every case.

## 2. Keep stderr out of the SFTP byte stream

File:

```text
packaging/native/aspr-mount-worker.c
```

The current worker duplicates the same stream FD onto stdin, stdout, and stderr while launching:

```text
sftp-server -e -l INFO
```

Because `-e` sends logs to stderr, diagnostic text can corrupt the SFTP protocol stream.

Required correction:

* FD 6 may become stdin and stdout only;
* introduce a distinct fixed supervisor/log FD, or direct stderr to a safe fixed sink;
* do not inherit the broker control socket;
* do not inject framed errors or logs into the SFTP stream after the outer `Ready`.

Recommended fixed ABI addition:

```text
FD 6: SFTP stdin/stdout stream
FD 7: supervised stderr/log pipe
```

Required test:

* start the fixed workload with logging enabled;
* complete an SFTP version handshake;
* assert that stdout contains only valid SFTP frames;
* assert that diagnostic output appears solely on the logging descriptor.

## 3. Correct the sealed-plan verification

File:

```text
packaging/native/aspr-mount-worker.c
```

The current seal check masks the return value of `fcntl(F_GET_SEALS)` directly. If `fcntl()` returns `-1`, the bitmask may appear to contain every required bit.

Required correction:

```c
int seals = fcntl(PLAN, F_GET_SEALS);
if (seals < 0) {
    die("F_GET_SEALS");
}
if ((seals & REQUIRED_SEALS) != REQUIRED_SEALS) {
    bad("plan unsealed");
}
```

Also:

* reject unsupported extra plan versions;
* decode plan integers explicitly as little-endian rather than relying on native host endianness;
* reject reserved target overlaps independently in the native worker;
* reject target ancestors of reserved runtime/control paths, not merely descendants;
* verify that every expected descriptor slot exists and has `FD_CLOEXEC` state consistent with the fixed exec design.

## 4. Correct forbidden-root overlap semantics

File:

```text
src/astral_project/session/ceiling.py
```

The current check rejects sources beneath a forbidden root but permits a broader ancestor export:

```text
allowed:   /source
forbidden: /source/secrets
grant:     /source
```

That grant exposes the forbidden subtree.

Required rule:

A grant source and a forbidden root must be rejected when either is equal to or an ancestor of the other.

Conceptually:

```python
def paths_overlap(left: str, right: str) -> bool:
    return (
        left == right
        or left.startswith(right.rstrip("/") + "/")
        or right.startswith(left.rstrip("/") + "/")
    )
```

Use canonical component-aware comparisons, not untrusted string normalization.

Required tests:

* grant equals forbidden root;
* grant below forbidden root;
* grant above forbidden root;
* sibling path does not conflict;
* `/foo` does not match `/foobar`.

## 5. Replace global RW permission with per-root access ceilings

File:

```text
src/astral_project/session/ceiling.py
```

One global `allow_read_write` value means that enabling RW for one administrator-approved root enables RW for every allowed root.

Replace:

```text
allowed_source_roots: tuple[str, ...]
allow_read_write: bool
```

with typed per-root entries such as:

```text
SourceRootCeilingV1 {
    canonical_root
    maximum_access = ro | rw
    allowed_kinds
    nested_mount_policy
}
```

Effective access must be the intersection of:

```text
signed grant
per-root administrator ceiling
global hard limits
```

Required tests:

* RW request beneath RO root is denied;
* RO request beneath RW root is allowed;
* export under one root cannot inherit another root’s RW permission;
* overlapping configured roots are rejected unless an ADR defines deterministic precedence.

## 6. Reconcile the Packet 14B broker contract completely

Files:

```text
src/astral_project/session/broker.py
src/astral_project/broker/server.py
tests/unit/test_session_contracts.py
tests/unit/test_broker_server.py
```

`CreateNamespaceV1` is now the correct broker request, but the implementation retains several older contract elements.

Required corrections:

### Replay key

Do not consume only the signed grant nonce.

Replay state must bind at least:

```text
issuer_key_id
grant_id
client_nonce
```

The grant nonce identifies the grant envelope. The client nonce identifies one attempted namespace/session creation. A valid unexpired grant may create more than one session using distinct client nonces, subject to policy.

Delete the test named:

```text
test_replay_consumes_signed_grant_nonce_not_session_nonce
```

and replace it with tests proving:

* same grant plus same client nonce is rejected;
* same grant plus different client nonce may be accepted;
* same client nonce under a different grant does not collide unless the chosen global namespace intentionally requires it;
* expiry and revocation remain terminal.

### Broker response union

The broker wire response must be:

```text
NamespaceReadyV1 | NamespaceRejectedV1
```

`WorkerResultV1` is internal worker-to-broker state and must not be emitted as the broker protocol response.

Before the real worker exists, a valid request should receive a typed `NamespaceRejectedV1` such as:

```text
stable_error_code = backend_unavailable
stage = worker_start
retryable = false
```

### Rejection schema

Include the frozen fields:

```text
request_id
session_id: optional
stable_error_code
stage
retryable
safe_message
protocol_version
```

Add canonical encoding and decoding with exact field validation.

### Cancellation

`CancelNamespaceV1` needs:

```text
request_id
session_id
reason enum
protocol_version
```

Define its complete response union:

```text
NamespaceCancelledV1
NamespaceNotFoundV1
NamespaceRejectedV1
```

### Backend identity

Replace free-form `backend_id: str` with a fixed enum. V1 should accept only the administrator-bootstrapped broker backend identifier.

## 7. Unify the remote session protocol before broker integration

Files:

```text
src/astral_project/server/protocol.py
src/astral_project/server/entry.py
src/astral_project/session/contracts.py
```

There are currently two overlapping daemon-to-remote-server request models:

```text
Preface
RemoteSessionRequestV1
```

Both carry an operation, nonce, and signed grant, but use different names and field structures.

Choose one canonical outer wire request.

Recommended resolution:

* retain `RemoteSessionRequestV1` as the outer canonical request;
* let the framing helpers read and write that schema directly;
* remove or migrate the generic `Preface` type;
* define one outer response union;
* only the outer `Ready` response transitions the SSH channel to raw SFTP bytes;
* the broker control socket never transitions to raw SFTP.

Required tests:

* one golden request fixture;
* one golden `Ready` fixture;
* one golden rejection fixture;
* exact transition test proving no framed bytes appear after `Ready`;
* malformed request is rejected before any broker call or path operation.

## 8. Bind both configured UID and configured GID

Files:

```text
src/astral_project/session/broker.py
src/astral_project/broker/server.py
```

The broker currently validates only the peer UID and then maps the observed peer GID.

Root-owned user configuration must freeze:

```text
expected_uid
expected_primary_gid
```

The broker must require both observed values to match. It must not permit the connecting process to select an alternate supplementary or effective group and thereby alter the namespace mapping.

Required changes:

* `BrokerAuthority` stores expected UID and expected GID;
* `require_expected_peer()` checks both;
* the mapping worker receives configured UID/GID, not untrusted request fields;
* supplementary groups remain unmapped in V1.

Required tests:

* matching UID/GID accepted;
* UID mismatch denied before parsing;
* GID mismatch denied before parsing;
* request cannot supply mapping identities.

## 9. Add bounded broker read/write deadlines

File:

```text
src/astral_project/broker/server.py
```

An authorized client can currently connect and stall `_read_exact()` indefinitely. Because the current server handles one request synchronously, this can deny service.

Required correction:

* set a bounded timeout immediately after `accept`;
* apply separate maximum durations for frame header, frame body, validation, and response write if appropriate;
* reject partial frames;
* close the connection on timeout;
* audit timeout using a stable stage and error code without including sensitive input.

Required tests:

* no header sent;
* partial header;
* declared body never completed;
* client stops reading response;
* timeout does not leave replay state consumed or workers running.

## 10. Harden runtime dependency discovery

File:

```text
src/astral_project/runtime/closure.py
```

The builder invokes `/usr/bin/ldd` after proving only that the input is a regular file. Running `ldd` against an insufficiently trusted executable is unsafe in a privileged or package-building path.

Preferred correction:

* use non-executing ELF inspection;
* parse `PT_INTERP`;
* parse `DT_NEEDED`;
* resolve libraries through a controlled, explicit loader search model;
* reject `RPATH`/`RUNPATH` entries outside approved system roots;
* record every resolution decision in the manifest.

A temporary pre-install-only compromise may use `ldd` only when all of the following are independently proven:

* file is root-owned;
* file and all ancestors are not group/world writable;
* file belongs to a trusted package;
* exact package digest/version is recorded;
* operation occurs in an isolated disposable build environment;
* the result is never trusted without later manifest verification.

Do not use the compromise in the root broker.

## 11. Make the runtime smoke test genuinely closure-only

Files:

```text
src/astral_project/runtime/smoke.py
tests/unit/test_runtime_closure.py
```

The current smoke test uses the explicit loader but executes while the host root remains visible. It therefore does not prove that the closure is complete.

Packet 15C acceptance requires a test inside an empty mount namespace or equivalent test root containing only:

```text
the runtime closure
minimal explicitly required devices
minimal generated identity files
```

Required assertions:

* SFTP handshake succeeds with only the closure;
* omitting each required library causes failure;
* no file is loaded from host `/lib`, `/usr`, or `/etc`;
* `LD_LIBRARY_PATH`, `LD_PRELOAD`, and related ambient variables are absent or ignored;
* generated NSS files are sufficient;
* no network access is needed.

The test may use a disposable helper or namespace harness before production AppArmor packaging exists.

## 12. Fix remote forced-command construction

File:

```text
src/astral_project/host/enrollment.py
```

The generated `authorized_keys` command currently uses a relative executable:

```text
aspr-server server ssh-entry ...
```

Use a fixed absolute enrolled path, for example:

```text
/home/<user>/.local/lib/astral-project/<digest>/bin/aspr-server
```

or the final package-owned absolute path.

Do not depend on PATH, aliases, shell initialization, or the current directory.

Also restrict `transport_key_id` to an exact grammar, for example:

```text
[A-Za-z0-9_-]{1,64}
```

Reject:

* quotes;
* backslashes;
* commas;
* control characters;
* shell metacharacters;
* whitespace;
* leading option syntax if later used as argv.

The authorized-key entry builder must be a deterministic serializer, not general string interpolation.

## 13. Roll back the generated local transport private key

File:

```text
src/astral_project/host/enrollment.py
```

The local private key is written before `remote.smoke_test()`. If the smoke test fails, remote changes are rolled back but the newly generated private key may remain.

Required correction:

* track whether the private key path was newly created;
* add deletion to the rollback journal;
* fsync the containing directory after deletion;
* never delete a pre-existing trusted key;
* fail before remote mutation if the destination already exists unexpectedly.

Required tests:

* smoke-test failure removes newly created local key;
* remote rollback failure is reported without hiding local residue;
* pre-existing key cannot be overwritten or deleted.

# Important corrections which may proceed alongside Packet 15C

## 14. Reject all reserved-path overlaps in the namespace planner

File:

```text
src/astral_project/namespace/planner.py
```

The planner rejects targets equal to or below reserved paths, but an ancestor such as:

```text
/.astral-project
```

can overlap:

```text
/.astral-project/staging
```

Reject equality, descendants, and ancestors of every reserved control/runtime path.

Also reject:

* embedded NUL;
* target longer than the execution-plan byte limit;
* path components exceeding filesystem limits where relevant;
* targets whose UTF-8 encoding exceeds the fixed native limit.

The native worker must repeat critical reserved-path checks independently.

## 15. Clarify nested-mount discovery as advisory or redesign it

File:

```text
src/astral_project/server/path_resolver.py
```

The source object is pinned by descriptor, but nested-mount discovery scans `/proc/self/mountinfo` using the display pathname. Concurrent rename or mount changes can make the report disagree with the pinned object.

Until descriptor/mount-ID-based topology validation exists:

* label nested-mount results as advisory evidence;
* reject strict grants when topology cannot be proved stable;
* do not allow the report to grant authority;
* revalidate immediately before plan creation;
* preserve the pinned source identity throughout.

## 16. Improve the host probe before relying on enrollment evidence

File:

```text
src/astral_project/host/probe.py
```

Required corrections:

* use `sshd -T -C user=...,host=...,addr=...` where possible so `Match` rules are evaluated for the actual user;
* record every effective `AuthorizedKeysFile`, not only the first token;
* distinguish relative paths resolved beneath home from absolute paths;
* search standard absolute OpenSSH SFTP locations rather than relying solely on `command -v`;
* properly JSON-escape all dynamic capability evidence;
* treat inability to determine effective paths as unsupported for automatic enrollment, not merely harmless unknown evidence;
* keep the shell probe read-only.

## 17. Escape TOML output correctly

File:

```text
src/astral_project/host/records.py
```

`HostRecord.to_toml()` interpolates remote values directly into quoted TOML strings.

Implement a proper TOML string encoder or use a deterministic reviewed TOML serializer. Test:

* quotes;
* backslashes;
* newlines;
* tabs;
* non-ASCII paths;
* capability evidence containing shell output.

# Native-worker hardening to complete before Packet 15D closes

The following need not all block the isolated Packet 15C runtime builder, but they must be resolved before the worker becomes deployable:

* add `nosuid` and `nodev` mount attributes;
* decide and enforce `noexec` per export;
* ensure detached mount trees do not unexpectedly include nested mounts;
* verify capability effective, permitted, inheritable, bounding, and ambient sets after setup;
* set securebits as required;
* use a fixed safe working directory;
* make the staging path private to each worker rather than one shared constant;
* ensure a second worker cannot interfere with another worker’s staging tree;
* handle parent death with `PR_SET_PDEATHSIG` or equivalent supervision;
* verify process identity after namespace mapping;
* close every inherited FD except the explicit allowlist;
* separate worker status, workload stream, and workload logging channels;
* return typed terminal status to the broker instead of relying only on exit codes.

# Accepted incompleteness at the present stage

Do not treat the following as current defects:

* absent systemd units;
* absent AppArmor profiles;
* no installed root broker;
* no final durable replay database;
* no complete broker-to-worker descriptor passing;
* no SCM_RIGHTS stream response;
* no complete workload supervision;
* no full SFTP operation matrix;
* no rclone production mount path;
* no expiry/revocation teardown;
* no Packet 15F Ubuntu gate;
* no local agent sandbox or projected home.

Those belong to later subpackets.

# Recommended immediate implementation order

1. Fix Packet 14B request, replay, response, cancellation, and outer remote-session contracts.
2. Fix server-ceiling overlap and per-root access rules.
3. Fix mapping-worker FD relocation.
4. Fix native worker stream separation and seal checking.
5. Fix forced-command serialization and enrollment rollback.
6. Harden runtime dependency discovery.
7. Add a genuinely empty-root runtime handshake test.
8. Complete Packet 15C.
9. Resume broker-to-worker integration only after all revised golden fixtures and adversarial tests pass.
10. Do not perform root installation on `aspr-test` until explicit approval is requested later.

Provide the next handoff with:

* exact files changed;
* contract fixtures regenerated;
* tests added;
* local test results;
* remaining root-required operations;
* unresolved security questions;
* confirmation that no remote installation occurred.

