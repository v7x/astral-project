# ADR-0007: rclone transport choice

## Problem

Rclone SFTP may call external SSH with an SFTP subsystem request or arbitrary remote shell command. Astral Project must permit only protocol channel setup.

## Choices

1. Direct external-SSH wrapper.
2. Daemon-owned loopback SSH/SFTP proxy.

## Chosen choice

Use direct external-SSH wrapper for Linux amd64 rclone `1.73.3` and `1.74.4`.

`tests/fixtures/rclone/candidates.toml` pins official release archive and extracted-binary SHA-256 values. `scripts/rclone_external_ssh_spike.py` verifies binary digest and version, then uses a local SFTP-only fake endpoint. It runs `lsjson`, stat, read, write, rename, mount, mounted read, and unmount.

Generated SFTP config has only:

```ini
[spike]
type = sftp
ssh = <stub external SSH wrapper>
disable_hashcheck = true
```

It does not set `shell_type = none`: rclone authoritative SFTP documentation states this is incompatible with external `ssh`. Instead, wrapper accepts exact argv `-s sftp` and rejects every other argv. Both tested versions try `echo ${ShellId}%ComSpec%` for shell-type detection; rejection does not break required operations.

## Security effect

Wrapper receives neither host nor user override. All accepted invocations are exact SFTP subsystem invocations. Shell probes are recorded and rejected. `disable_hashcheck=true` prevents checksum-command probes.

## Rejected choice

Loopback proxy adds endpoint, credential, and lifecycle authority without present need. Packet 11 remains mandatory if supported rclone behavior changes or direct wrapper ceases to meet this ADR.

## Evidence

Run for each pinned binary:

```text
uv run python scripts/rclone_external_ssh_spike.py \
  --rclone <pinned-rclone> --version <version> --output <result.json>
```

On Linux amd64, 2026-07-27, both candidates passed all required operations. Both emitted only `-s sftp` as accepted wrapper argv and one rejected shell-detection probe.

## Packet ownership

Packet 16E is compatibility evidence only: it runs ADR-0007's pinned versions against the fixed remote SFTP service and records operation patterns. It does not implement local transport authority, private per-rclone sockets, environment-bound tokens, `aspr transport`, daemon `OpenSftpStream`, or production rclone plumbing. Those belong to Packet 18. Packet 16E may use a narrow test wrapper.

ADR-0007 remains authoritative unless new rclone evidence triggers reconsideration. Packet 16 must not infer transport ownership from compatibility success.

## Reconsideration trigger

Any new supported rclone version, changed accepted argv, required shell command, host/user override, failed matrix operation, or non-Linux-amd64 target requires new evidence. If direct wrapper fails, run Packet 11.
