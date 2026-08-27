# ADR-0019: Environment, pathname sockets, and credentials

## Problem

A sandboxed program can bypass projected-home mediation through inherited environment
values, PATH lookup, file descriptors, pathname sockets, or credential files. These
resources must not become ambient authority merely because parent process inherited
them.

## Choices

1. Inherit the complete parent environment and descriptor table.
2. Allowlist names and exact resources, clear all other values, and bind only exact
   pathname sockets after policy approval.
3. Use a syscall observer as authorization mechanism.

## Chosen choice

Astral uses option 2. Child environment contains only documented locale and terminal
names plus fixed sandbox values. Secret-like names and reserved approval/session
control names are removed without logging values; fixed values receive the same secret
and PATH filtering. PATH entries are retained only when absolute, existing, and below
explicitly visible roots. The runner supplies those visible roots to the fixed native
launcher, which propagates only the already-sanitized environment after bubblewrap
clears its environment. Rclone and SSH subprocesses use the same boundary, retaining
only explicit daemon transport capability variables for rclone. Unlisted descriptors
are closed. Socket policy accepts exact normalized
pathname sockets only; abstract sockets and known dangerous sockets are denied by
default. Credential files require strong confirmation and audit output is redacted.
Raw socket capability is disabled by default; a profile opt-in remains denied unless
an explicit strong-confirmation path is added by a future trusted controller.
Observer data may improve prompts but never grants access.

## Security effect

Environment, descriptor, socket, and credential authority is explicit and bounded.
Changing or adding an ambient parent resource does not silently change child authority.
A failed validation denies resource exposure rather than guessing a safe substitute.

## Rejected choices

- Full environment inheritance leaks credentials and ambient execution authority.
- PATH filtering by string prefix permits nonexistent or symlinked escape paths.
- Abstract socket support has no stable pathname identity and is not auditable.
- Credential content in prompts or logs creates a second disclosure channel.
- Observer-only authorization is vulnerable to incomplete observation and races.

## Tests

- Environment policy removes secret-like names and invisible PATH entries while never
  emitting values.
- Resource policy rejects dangerous, abstract, relative, and non-socket paths; exact
  approved pathname sockets require a live socket. Raw sockets require profile opt-in
  and strong confirmation, and the public sandbox path exposes no ambient raw socket.
- Sandbox plan serializes approved sockets to the fixed native launcher, which validates
  normalized pathname and socket type before adding read-only binds. Native acceptance
  proves an allowlisted PATH survives while an invisible entry is removed.
- Packet 34–36 acceptance drivers run packaged, unprivileged tests on Ubuntu 24.04 and
  Ubuntu 26.04.

## Future reconsideration trigger

Reconsider only after a new kernel primitive or packaging target changes descriptor,
namespace, or socket binding semantics and a fresh threat review proves equal or
stronger mediation.
