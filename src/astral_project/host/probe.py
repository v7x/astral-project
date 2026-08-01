# ruff: noqa: E501
"""Read-only enrollment probe through existing OpenSSH configuration."""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.host.records import ProbeReport

_TIMEOUT_SECONDS = 30
_FINGERPRINT = re.compile(r"Server host key: [^ ]+ (SHA256:[A-Za-z0-9+/=]+)")
_SECRET = re.compile(r"(?i)(password|token|secret)=\S+")

# Static POSIX shell program. It writes no remote files and emits probe JSON only.
# Values are deliberately conservative: a shell-only probe marks unprovable kernel
# properties unknown rather than claiming support.
REMOTE_PROBE_SCRIPT = r"""set -eu
json() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]),end="")' "$1"; }
value() { command -v "$1" 2>/dev/null || true; }
cap() { printf '{"name":'; json "$1"; printf ',"status":'; json "$2"; printf ',"reason":'; json "$3"; printf ',"evidence":'; json "$4"; printf '}'; }
user=$(id -un)
home=${HOME:-/}
os=$(uname -s)
arch=$(uname -m)
bwrap=$(value bwrap)
sftp=$(value sftp-server)
if [ -z "$sftp" ]; then for candidate in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server; do if [ -x "$candidate" ]; then sftp=$candidate; break; fi; done; fi
host=$(hostname 2>/dev/null || printf localhost)
sshd_effective=$(sshd -T -C "user=$user,host=$host,addr=127.0.0.1" 2>/dev/null || true)
resolve_paths() { field=$1; printf '%s\n' "$2" | awk -v wanted="$field" -v home="$home" '$1==wanted { for(i=2;i<=NF;i++) { p=$i; if(substr(p,1,1)!="/") p=home "/" p; printf "%s%s", sep, p; sep=";" } }'; }
keys=$(resolve_paths authorizedkeysfile "$sshd_effective")
principals=$(resolve_paths authorizedprincipalsfile "$sshd_effective")
printf '{"version":1,"os":'; json "$os"; printf ',"architecture":'; json "$arch"; printf ',"remote_user":'; json "$user"; printf ',"remote_home":'; json "$home"; printf ',"capabilities":['
if [ -n "$bwrap" ]; then cap bubblewrap supported installed "$bwrap"; else cap bubblewrap unsupported missing 'command -v bwrap'; fi
printf ','
if unshare -Ur true >/dev/null 2>&1; then cap user_namespaces supported 'unshare succeeded' 'unshare -Ur true'; else cap user_namespaces unsupported 'unshare failed' 'unshare -Ur true'; fi
printf ','
cap openat2 unknown 'shell probe cannot prove syscall' 'requires native probe'
printf ','; cap open_tree unknown 'shell probe cannot prove syscall' 'requires native probe'
printf ','; cap move_mount unknown 'shell probe cannot prove syscall' 'requires native probe'
printf ','; cap mount_setattr unknown 'shell probe cannot prove syscall' 'requires native probe'
printf ','; cap landlock unknown 'shell probe cannot prove ABI' 'requires native probe'
printf ','
if [ -n "$sftp" ]; then cap sftp_server supported found "$sftp"; else cap sftp_server unsupported missing 'command -v sftp-server'; fi
printf ','; cap loader_libraries unknown 'runtime closure not yet inspected' 'Packet 8 enrollment'
printf ','; cap filesystems unknown 'filesystem survey requires candidate roots' 'Packet 7 shell probe'
printf ','; cap mount_topology unknown 'mount topology requires candidate roots' 'Packet 7 shell probe'
printf ','
if [ -n "$keys" ]; then cap authorized_keys supported 'sshd -T -C found effective paths' "$keys"; else cap authorized_keys unsupported 'could not determine effective authorized_keys paths' 'none'; fi
printf ','
if [ -n "$principals" ]; then cap authorized_principals supported 'sshd -T -C found effective path' "$principals"; else cap authorized_principals unknown 'sshd -T -C unavailable or no path' 'none'; fi
printf ']}\n'
"""


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


RunCommand = Callable[[Sequence[str], str], CommandResult]


def _error(code: ErrorCode, message: str, detail: str | None = None) -> AstralError:
    return AstralError(
        code=code,
        message=message,
        security_result="remote host was not changed",
        unsafe_reason="enrollment probe must remain read-only and evidence must be trustworthy",
        next_action="inspect SSH connectivity and probe evidence, then retry",
        dependency_error=detail,
    )


def _redact(value: str) -> str:
    return _SECRET.sub(r"\1=<redacted>", value)


def run_ssh_probe(target: str, runner: RunCommand) -> tuple[ProbeReport, str]:
    """Run fixed remote probe through user SSH config; parse evidence and host key."""
    if not target or target.startswith("-"):
        raise _error(ErrorCode.HOST_PROBE, "SSH target is invalid")
    result = runner(("ssh", "-v", "-o", "BatchMode=yes", target, "sh", "-s"), REMOTE_PROBE_SCRIPT)
    if result.returncode != 0:
        raise _error(ErrorCode.HOST_PROBE, "remote probe command failed", _redact(result.stderr))
    match = _FINGERPRINT.search(result.stderr)
    if match is None:
        raise _error(ErrorCode.HOST_PROBE, "SSH did not report verified host key fingerprint")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise _error(ErrorCode.HOST_PROBE, "remote probe output was not JSON") from error
    if not isinstance(payload, dict):
        raise _error(ErrorCode.HOST_PROBE, "remote probe output was not object")
    return ProbeReport.from_dict(payload), match.group(1)


def subprocess_runner(arguments: Sequence[str], stdin: str) -> CommandResult:
    """Run one bounded SSH process without shell interpolation."""
    try:
        completed = subprocess.run(
            list(arguments),
            input=stdin,
            capture_output=True,
            check=False,
            text=True,
            timeout=_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise _error(
            ErrorCode.HOST_PROBE, "could not execute SSH probe", _redact(str(error))
        ) from error
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)
