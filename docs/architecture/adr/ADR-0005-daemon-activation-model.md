# ADR-0005 — Daemon activation model

## Problem

CLI needs daemon service without unsafe implicit process spawning.

## Chosen

Use explicit foreground internal activation: `aspr __internal daemon`. Public `aspr doctor` connects only; it never starts daemon. Kernel-held `flock` on private runtime lock serializes startup. Lock release on process death permits next startup. New daemon probes existing socket; connection failure marks stale socket and repairs it while holding lock.

## Rejected

CLI auto-start through fork/detach: hidden lifecycle and process-spawn surface. Abstract socket: cannot be hidden from later sandbox. PID-file ownership: races and PID reuse.

## Security effect

No generic process API; one same-UID daemon owns main socket; stale filesystem names do not block recovery.

## Tests

Two starts race, stale socket repair, state reopen after restart, doctor ping.

## Reconsider

When systemd user-unit packaging supplies explicit audited activation.
