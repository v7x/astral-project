# Packet 15F Handoff

## Status

Packet 15F is not complete. Do not mark matrix passed.

Latest committed source:

```text
0ac105025fe5fdbf4913627b301ff38b1a83b48e  create mapped worker staging before namespace setup
b9d0eee0f5a9fcb60e0d5f6db4ab80e4634dc447  split worker user and mount namespace creation
```

Local uncommitted work exists after `b9d0eee`; inspect `git status` and do not discard it.

VM: `aspr-test-admin`, `aspr-test`. Target user: `testuser` UID/GID `1001`. Positive driver: `/tmp/aspr-positive-driver.py` on `aspr-test`.

## Required worker order

Native worker `packaging/native/aspr-mount-worker.c` must preserve this order:

```text
unshare(CLONE_NEWUSER)
→ parent mapping handshake
→ enter usable broker-created staging directory before mapped identity loses host traversal
→ set mapped effective UID/GID
→ validate sealed plan
→ verify each source FD device/inode/broker mount ID
→ unshare(CLONE_NEWNS)
→ MS_PRIVATE propagation
→ staging tmpfs
→ open_tree/mount_setattr/move_mount source construction
→ runtime mount, pivot root, AppArmor transition, privilege removal, fixed SFTP exec
```

Source identity verification must occur before `CLONE_NEWNS`. No pathname reopen of signed sources. No ambient worker authority.

## Current exact runtime state

Earlier AppArmor mount denials were caused by deployment command failure: `pkill -f` matched SSH deployment shell and killed it before profile replacement. Use exact process matching, never broad `pkill -f` containing current remote command.

With deployed profile containing temporary `allow mount,`, private propagation and staging tmpfs no longer deny. Restore narrow rules only after positive path works:

```text
mount options=(rw rprivate) -> /,
mount fstype=tmpfs options=(rw nosuid nodev) tmpfs -> /run/astral-project/staging/**,
```

AppArmor profile: `packaging/apparmor/usr.libexec.astral-project.aspr-broker`.

Current positive failure, after source verification and namespace construction:

```text
aspr-mount-work: open_tree: Invalid argument
```

This occurs in `mount_one()`:

```c
syscall(SYS_open_tree, source, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH)
```

Source descriptor is an `O_PATH|O_NOFOLLOW` directory FD pinned by broker. Standalone privileged VM control succeeded with same `open_tree` flags against `/home/testuser/astral-gate-source`. Therefore reproduce exact worker child state before changing architecture or relaxing policy.

A simplified VM probe at `/tmp/open-tree-map.c` was not faithful: it failed at `setres*` with `EINVAL`. Do not infer worker behavior from that probe until it duplicates broker fork, file-descriptor handoff, setgroups denial, mapping, AppArmor profile, and process credentials.

One prior worker attempt reached `open_tree`, then parent cleanup failed because `/run/astral-project/staging/<pid>/project` remained after failed construction:

```text
AstralError: worker staging cleanup failed
OSError: [Errno 39] Directory not empty
```

Repair cleanup so failure after target creation cannot crash broker supervision or leave staging residue. Preserve race safety: parent creates exact PID staging directory; arbitrary recursive deletion of target-user-controlled content is forbidden.

## Staging details

`src/astral_project/broker/mapping.py` was changed to parent-create:

```text
/run/astral-project/staging/<worker-pid>
```

and chown exact leaf to target UID/GID. Staging root needs traversal semantics compatible with mapped worker and broker-owned creation. Parent must reject collisions; never accept preexisting leaf. Existing implementation currently uses `mkdir(..., exist_ok=True)` for root only and `path.mkdir()` for leaf.

Native worker changes after latest commit use `chdir(staging)` before setting mapped effective IDs, then set `staging` to `.`. This preserves current working-directory access after mapped identity can no longer traverse protected `/run/astral-project`. Audit all uses of `staging`, including pivot root and AppArmor path mediation.

## Build and VM procedure

Do not use local host `.deb` on VM: package bundles native Python extensions built for host interpreter ABI. A local CPython 3.12 build installed on VM CPython 3.14 and failed:

```text
ModuleNotFoundError: No module named 'cbor2._cbor2'
```

Build inside VM from transferred repository source, then install that VM-built artifact:

```sh
# local repository
# transfer current tracked source, excluding caches and .git, to VM build directory

ssh aspr-test-admin '
  cd /tmp/astral-project-final/src &&
  sh packaging/debian/build-deb.sh /tmp/astral-project-final/out &&
  sudo dpkg -i /tmp/astral-project-final/out/astral-project_0.1.0_amd64.deb
'
```

After install:

```sh
ssh aspr-test-admin '
  sudo systemctl daemon-reload
  sudo apparmor_parser --replace /etc/apparmor.d/usr.libexec.astral-project.aspr-broker
  sudo systemctl restart astral-project-broker.socket
'
timeout 30 ssh aspr-test 'python3 -I /tmp/aspr-positive-driver.py'
ssh aspr-test-admin 'sudo journalctl -u astral-project-broker.service -b --no-pager -n 80'
ssh aspr-test-admin 'sudo journalctl -k -b --no-pager | tail -100'
```

Build/install/retest must occur from repository artifacts before acceptance. Manual native-worker replacement is diagnostic only.

## Required next work

1. Make faithful minimal `open_tree` reproducer or instrument worker without weakening policy. Capture source FD `fstat`, `statx` mount ID, FD flags, worker UID/GID/capabilities, namespace inode IDs, and syscall errno before/after `CLONE_NEWNS`.
2. Fix descriptor mount clone failure. Do not replace descriptor mounts with paths, bind host source paths by pathname, weaken AppArmor globally, or skip mount-ID verification.
3. Add regression coverage for exact user/mount namespace ordering and mount-ID verification before `CLONE_NEWNS`. Add a privileged VM acceptance test if unit test cannot exercise namespace syscalls.
4. Repair bounded staging cleanup. Parent-created leaf must be empty or cleanup must be safe by construction.
5. Remove temporary broad AppArmor `allow mount,`; enforce exact private-propagation and tmpfs mount rules. Re-run positive path and prove no relevant AppArmor denial.
6. Continue raw SFTP handshake from `/tmp/aspr-positive-driver.py` until it receives server initialization bytes after sending:

```python
b"\x00\x00\x00\x05\x01\x00\x00\x00\x03"
```

7. Implement target-user DAC source resolution. Current `pin_grant_sources()` resolves under broker/root authority and does not meet requirement. Add regressions proving root cannot export target-user-inaccessible source.
8. Add full Packet 15F topology, descriptor-replacement, unsafe-filesystem, nested-mount, pathname-replacement, lifecycle, inspection, provenance, and clean-reinstall gates. Run gate runbook and only then update `packaging/matrix/ubuntu-26.04-amd64.json`.

## Hard constraints

- No global AppArmor or sysctl weakening.
- No ambient Python dependencies.
- No acceptance from manual VM drift.
- Signed `SourceIdentity` remains mount-namespace portable: no signed `mount_id`.
- Broker-local mount ID remains sealed execution evidence and must be checked before worker `CLONE_NEWNS`.
- Escalate only frozen architecture/security conflict, global security weakening requirement, outside credential/access requirement, or documented host primitive absence.
