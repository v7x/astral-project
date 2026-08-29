# CLI and configuration reference

Both `aspr` and `astral-project` invoke the same public CLI. There is no
implemented general `--help` command. Most commands validate an exact argument
shape, although a few handlers accept and ignore extra arguments; an ignored
argument is not a supported feature. Use `aspr version` to verify the
executable.

## Commands

| Command | Purpose |
| --- | --- |
| `version` | Human-readable package, protocol, Python, platform, and Git data |
| `version --json` | Same data as stable JSON |
| `doctor` | Query running daemon status as JSON |
| `host probe USER@HOST` | Read-only SSH capability probe |
| `host doctor --probe-file FILE` | Read existing host-record probe data |
| `profile create ID [--name NAME]` | Create profile |
| `profile list` | List active profiles as JSON |
| `profile review ID` | Print profile TOML |
| `profile edit ID` | Edit and validate profile |
| `profile diff ID CANDIDATE` | Show candidate diff |
| `profile seal\|unseal ID` | Change learning/editability state |
| `profile export ID DEST` | Export profile |
| `profile import SOURCE [ID]` | Import profile |
| `profile archive ID` | Remove profile from active list |
| `profile learn ID [options] -- PROGRAM [ARG...]` | Learn approvals while running program |
| `sandbox [options] -- PROGRAM [ARG...]` | Run one constrained local or remote command |
| `ls TARGET [options]` | List through daemon or current sandbox session |
| `grant list [--all]` | List stored grants; include revoked with `--all` |
| `grant show ID` | Show stored signed grant envelope |
| `grant import CBOR ISSUER_KEY` | Import and verify signed grant |
| `grant create CBOR ISSUER_KEY` | Current compatibility alias for import |
| `grant validate ID` | Validate signature, binding, time, and revocation |
| `grant revoke ID [--reason TEXT]` | Revoke grant |
| `session list\|open ID\|show ID\|close ID` | Manage remote sessions |
| `mount list\|show ID\|close ID` | Inspect or close remote mounts |
| `mount open PATH TARGET ro\|rw [--read-write]` | Open mount under active session |
| `audit list` | List local redacted audit events |
| `audit show EVENT_ID` | Show one local audit event |
| `audit export [--hash]` | Export local audit data |
| `audit export --remote HOST_ID [--hash]` | Export remote audit data |

`grant`, `session`, `mount`, `audit`, and remote `ls` operations require a
running broker where their implementation uses daemon state. `sandbox` without
remote grant uses local execution; remote grant use requires broker authority.

## Sandbox options

`--network inherit|none` is required. Other options are:

```text
--grant GRANT_ID
--remote GRANT:/absolute/source=/absolute/target[:ro|rw]
--approval-socket /absolute/socket
--profile /absolute/profile.toml --home-root /absolute/home
--private-root /absolute/private-root
--overlay-root /absolute/overlay-root
```

`--profile` and `--home-root` are a pair. Writable projected-home roots
require both. A remote entry may either use the selected `--grant` or prefix
itself as `GRANT_ID:/source`; when a prefix is used without `--grant`, the
sandbox infers the selected grant. All remote entries must use one signed grant.
A remote target cannot be `/` and paths cannot contain `.` or `..` components.

For `ls`, options are `--recursive`/`-R`, `--stat`, `--json`, `--raw`,
`--no-header`, `--reverse`, `--sort VALUE`, `--max-depth INTEGER`,
`--timeout NUMBER`, and repeated `--filter VALUE`.

## Profile format

Minimal profile:

```toml
version = 1
id = "agents-default"
name = "Coding agents"
unknown_learning = "prompt"
unknown_sealed = "hide"
sealed = false
raw_socket = false
revision = 1

[[home.rules]]
path = ".config/tool/settings.toml"
scope = "exact"
mode = "host-ro"
sensitivity = "configuration"
```

Home paths are relative to projected home and normalized. Rule modes are:

- `host-ro`: read access to host path;
- `host-rx`: exact host executable authorization;
- `private-rw`: writable private backing store;
- `overlay-rw`: writable overlay backing store;
- `deny`: explicit denial.

Scopes are `exact` and `subtree`. `list = true` is required to list a rule's
directory. Writable rules may not overlap. `raw_socket = true` is not a
supported profile-sandbox capability and is rejected at sandbox start.

## Paths and environment

| Name | Requirement/default | Use |
| --- | --- | --- |
| `HOME` | required, absolute | User home and default config/state roots |
| `XDG_RUNTIME_DIR` | required, absolute | Private runtime sockets and temporary state |
| `XDG_CONFIG_HOME` | optional; `$HOME/.config` | Profile root becomes `.../astral-project` |
| `XDG_STATE_HOME` | optional; `$HOME/.local/state` | State/audit root becomes `.../astral-project` |
| `EDITOR` | optional; `vi` | `profile edit` editor |
| `ASPR_APPROVAL_SOCKET` | optional absolute path | External learner approval socket |
| `ASPR_SESSION_SOCKET` and `ASPR_SESSION_ID` | managed inside sandbox | Session-scoped `aspr ls`; do not set manually |

Profiles are below `$XDG_CONFIG_HOME/astral-project/profiles`. SQLite state is
`$XDG_STATE_HOME/astral-project/state.sqlite3`; runtime files are below
`$XDG_RUNTIME_DIR/astral-project`.

## Exit status and errors

- `0`: requested command completed successfully;
- `2`: public command dispatch or a strict command-shape check rejected the
  request;
- `70`: operational, dependency, authentication, configuration, or security
  rejection, including sandbox argument validation.

Structured errors include stable `ASPR_*` code, security result, reason, and
next action. Diagnostics go to standard error. Do not parse human diagnostics
as protocol data; JSON output is intended for machine use.
