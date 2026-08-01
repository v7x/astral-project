# Packet 10 handoff

## Goal

Prove or reject direct rclone external-SSH transport before mount implementation.

## Decision

Direct wrapper accepted for Linux amd64 rclone `1.73.3` and `1.74.4`. ADR: `docs/architecture/adr/ADR-0007-rclone-transport-choice.md`.

Both versions passed `lsjson`, stat, read, write, rename, mount, mounted read, and unmount against SFTP-only fake endpoint. Wrapper accepted only `-s sftp`. Each version attempted shell-type detection with `echo ${ShellId}%ComSpec%`; wrapper rejected it and required operations still passed.

## Changed

- Added pinned rclone manifest with official archive and extracted-binary SHA-256 values.
- Added external-SSH spike runner and SFTP-only stub wrapper.
- Added manifest integrity test.
- Added transport ADR.

## Files

- `scripts/rclone_external_ssh_spike.py`
- `tests/fixtures/rclone/candidates.toml`
- `tests/unit/test_rclone_spike_manifest.py`
- `docs/architecture/adr/ADR-0007-rclone-transport-choice.md`

## Evidence command

```text
uv run python scripts/rclone_external_ssh_spike.py \
  --rclone <pinned-rclone> --version <version> --output <result.json>
```

Run on 2026-07-27 for 1.73.3 and 1.74.4. Both passed. Result JSON records exact wrapper argv and environment.

## Known limits

Evidence covers Linux amd64 only. Fake endpoint is `rclone serve sftp --stdio`; Packet 16 will test actual OpenSSH `sftp-server` behind remote namespace. New rclone versions or architectures require rerun and ADR review.

## Next

Packet 12 — safe remote path resolver. Packet 11 skipped: direct transport passed.

## Security assumptions

Production transport must generate `disable_hashcheck=true`, omit `shell_type=none`, and reject every external-SSH argv except exact `-s sftp`. Spike script is test-only; it grants no production authority.
