# Packet 15F Ubuntu 26.04 evidence

Status: **passed** on 2026-08-11. This record certifies Ubuntu 26.04 amd64 only. Ubuntu 24.04 packaged gate failed and remains uncertified; see `docs/packet-15f-ubuntu-24.04-evidence.md`.

## Target and package

- OS: Ubuntu 26.04 LTS, amd64.
- Kernel: `7.0.0-29-generic`.
- Package: `astral-project 0.1.0`, status `install ok installed`.
- Final VM-built Debian SHA-256: `e2616c24388aa1d62cd8aafc23c8940cb8111bc324fb2f64b581fb0afbc19076`.
- `dpkg --purge astral-project` followed by installation of that Debian archive passed. The package `prerm` removed generated Python bytecode before dpkg's directory checks; purge reported no `/usr/lib/astral-project` residue warnings. Administrator-owned authority, ceiling, source-root policy, and runtime-digest configuration were restored, rather than treated as package payload.
- `apparmor_parser --replace /etc/apparmor.d/usr.libexec.astral-project.aspr-broker` passed. `aa-status` listed `aspr-broker`, `aspr-namespace-setup`, and `aspr-sftp-v1` in enforce mode.

## Packaged preflight and positive gate

Command:

```sh
sudo /usr/libexec/astral-project/packet15f-gate
sudo cat /var/lib/astral-project/evidence/packet15f.json
```

Result: passed. The final evidence reported AppArmor digest `02a73de275d1e5cc1fab88a040760244f51cf133999746ed96c9d5bb899bd50d`, runtime/manifest digest `d4a3a4526ecc64eb512c1dcc7cf815f02ea27a1285269d079116dacbce43f4f8`, Ubuntu 26.04, and kernel `7.0.0-29-generic`.

The installed-package SFTP driver returned `NamespaceReadyV1` and an SFTP v3 `SSH_FXP_VERSION` response while the worker label was `aspr-sftp-v1 (enforce)`.

## Mandatory adversarial phase

Each case below was repeated after the final purge/reinstall.

| Case | Result and raw evidence |
|---|---|
| Descriptor replacement after pinning | **passed** — after readiness, the source pathname was renamed and replaced; SFTP still read `gate-data` from the pinned original inode. |
| RO export write | **passed** — `SSH_FXP_OPEN` with write/create/truncate returned status packet `650000000300000004000000074661696c75726500000000`; no file appeared in the source. |
| Unregistered peer | **passed** — UID/GID 65534 with only socket traversal group reached the socket, then the broker reset the connection before request parsing. |
| UID mismatch | **passed** — UID 65534/GID 1001 was reset before request parsing. |
| GID mismatch | **passed** — UID 1001/GID 1002 was reset before request parsing. |
| Wrong remote user | **passed** — `NamespaceRejectedV1`, stage `grant_validation`; broker log: `grant remote user does not match`. |
| Expired grant | **passed** — `NamespaceRejectedV1`, stage `grant_validation`; broker log: `grant has expired`. |
| Replay | **passed** — the first fixed grant-ID/grant-nonce/client-nonce request reached SFTP v3; the second returned `NamespaceRejectedV1`, stage `grant_validation`; broker log: `namespace creation was already issued`. |
| Target-user DAC | **passed** — a request signed while accessible was rejected at `worker_start` after the source became root-owned mode 0700; broker reported target-user DAC source resolution failure. Ownership and mode were restored afterward. |
| Mount | **passed** — final-profile probe returned `errno=13`. |
| `open_tree` | **passed** — final-profile probe returned `errno=1`. |
| `mount_setattr` | **passed** — final-profile probe returned `errno=1`. |
| `move_mount` | **passed** — final-profile probe returned `errno=1`. |
| Nested user namespace | **passed** — a probe entered the same mapped `aspr-namespace-setup` state, transitioned to `aspr-sftp-v1`, then nested `unshare(CLONE_NEWUSER)` returned `errno=1`. |
| Alternate root | **passed** — final-profile `chroot` and `pivot_root` returned `errno=13` and `errno=1`; SFTP open of `/oldroot/etc/passwd` returned no-such-file status `6500000004000000020000000c4e6f20737563682066696c6500000000`. |
| Unix and network sockets | **passed** — final-profile AF_UNIX and AF_INET creation both returned `errno=13`; enforce audit records named `aspr-sftp-v1`. |
| Cancellation cleanup | **passed** — closing the SFTP stream terminated the worker; `/run/astral-project/staging` became empty. |
| Expiry cleanup | **passed** — a three-second grant reached readiness, then the supervisor closed the stream, killed/reaped the worker, and removed staging. Output: `expiry_supervisor_termination=passed`, `expiry_cleanup=passed`. |

Final-profile syscall probes were run in a private mount namespace. Detached mount operations used a pre-created clone, so a hypothetical policy failure could not alter the host mount namespace. The user-namespace probe reproduced the worker's first user namespace, parent-written UID/GID maps, setup profile, and fixed transition before attempting a nested namespace.

## Repository regression evidence

- Focused verification contract: `22 passed`.
- Final full suite after evidence and matrix edits: `252 passed, 1 skipped`.
- Packaged policy has no `allow mount,` and no broad `/proc/** rw,` allowance. It retains staging-bound mount rules, explicit final `deny userns`, `deny mount`, `deny capability`, `deny network`, and narrow broker-to-final-profile kill signaling for expiry supervision.
