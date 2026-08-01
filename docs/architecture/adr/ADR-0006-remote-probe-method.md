# ADR-0006 — Remote probe method

## Chosen

Enrollment runs fixed read-only POSIX shell probe through existing OpenSSH configuration: `ssh -v -o BatchMode=yes <target> sh -s`. Script arrives on standard input; no remote path, key, state, or configuration is written. OpenSSH verbose diagnostic supplies verified host-key fingerprint. Probe output is one strict JSON report.

## Security effect

No shell interpolation. User SSH configuration remains available only during enrollment. `ssh-keyscan` is rejected: it observes unauthenticated network keys. Failures retain redacted stderr evidence only.

## Tests

Changed key, missing bwrap, disabled user namespaces, missing SFTP server, unusual authorization path, command failure redaction.

## Reconsider

Replace shell script only with an equivalently read-only signed temporary application, after compatibility proof.
