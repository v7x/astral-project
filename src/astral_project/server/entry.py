"""SSH forced-command entry. It authenticates preface before any path work."""

from __future__ import annotations

import base64
import os
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, TextIO

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from astral_project.core.config import load_toml_config
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import HostId, IssuerKeyId
from astral_project.core.paths import check_private_path
from astral_project.crypto.grants import GrantVerificationContext
from astral_project.crypto.keys import public_key_from_bytes
from astral_project.server.protocol import (
    read_outer_request,
    write_outer_ready,
    write_outer_rejection,
)
from astral_project.session.contracts import (
    RemoteSessionReadyV1,
    RemoteSessionRejectedV1,
    RemoteSessionRequestV1,
)

SSH_ORIGINAL_COMMAND = "aspr-channel-v1"
_SERVER_CONFIG = Path(".config") / "astral-project" / "server.toml"


@dataclass(frozen=True, slots=True)
class ServerTrust:
    """Trusted remote identity and enrolled issuer keys."""

    host_id: HostId
    ssh_host_key_fingerprint: str
    remote_user: str
    issuer_keys: Mapping[IssuerKeyId, Ed25519PublicKey]
    transport_key_ids: frozenset[str]


def run_ssh_entry(
    transport_key_id: str,
    *,
    stdin: BinaryIO,
    stdout: BinaryIO,
    stderr: TextIO,
    environment: Mapping[str, str],
    trust: ServerTrust | None = None,
    now: int | None = None,
    after_verification: Callable[[RemoteSessionRequestV1], None] | None = None,
) -> int:
    """Serve one outer session frame; `Ready` is final frame before raw SFTP."""
    nonce: bytes | None = None
    try:
        _require_exact_command(environment)
        active_trust = trust if trust is not None else load_server_trust(transport_key_id)
        _require_transport_key(active_trust, transport_key_id)
        request = read_outer_request(stdin)
        nonce = request.session_nonce
        issuer = active_trust.issuer_keys.get(request.signed_grant.grant.issuer_key_id)
        if issuer is None:
            raise _issuer_error("grant issuer is not enrolled")
        request.signed_grant.verify(
            issuer,
            GrantVerificationContext(
                host_id=active_trust.host_id,
                ssh_host_key_fingerprint=active_trust.ssh_host_key_fingerprint,
                remote_user=active_trust.remote_user,
                now=int(time.time()) if now is None else now,
            ),
        )
        # Packet 9 ends here. Later packets dispatch only after this authentication gate.
        if after_verification is not None:
            after_verification(request)
        write_outer_ready(stdout, RemoteSessionReadyV1(request.session_id, request.session_nonce))
        return 0
    except AstralError as error:
        write_outer_rejection(stdout, RemoteSessionRejectedV1(nonce, error.code.string))
        stderr.write(f"{error.to_text()}\n")
        return 70


def load_server_trust(transport_key_id: str, *, home: Path | None = None) -> ServerTrust:
    """Load fixed remote server configuration, rejecting loose files and unknown fields."""
    if not transport_key_id or any(character.isspace() for character in transport_key_id):
        raise _command_error("transport key identifier is invalid")
    path = (Path.home() if home is None else home) / _SERVER_CONFIG
    try:
        check_private_path(path)
    except OSError as error:
        raise _command_error("server configuration is unavailable") from error
    raw = load_toml_config(
        path,
        allowed_fields={
            "host_id",
            "issuer_keys",
            "remote_user",
            "ssh_host_key_fingerprint",
            "transport_key_ids",
            "version",
        },
    )
    if raw.get("version") != 1:
        raise _command_error("server configuration version is unsupported")
    try:
        host_id = HostId(_text(raw, "host_id"))
        fingerprint = _text(raw, "ssh_host_key_fingerprint")
        remote_user = _text(raw, "remote_user")
        transport_keys = frozenset(_text_list(raw, "transport_key_ids"))
        issuers = _issuer_keys(raw)
    except (TypeError, ValueError) as error:
        raise _command_error("server configuration has invalid field types") from error
    if not fingerprint or not remote_user or not transport_keys or not issuers:
        raise _command_error("server configuration is incomplete")
    return ServerTrust(host_id, fingerprint, remote_user, issuers, transport_keys)


def _issuer_keys(raw: Mapping[str, object]) -> dict[IssuerKeyId, Ed25519PublicKey]:
    value = raw.get("issuer_keys")
    if not isinstance(value, dict) or not value:
        raise _command_error("server configuration has no issuer keys")
    result: dict[IssuerKeyId, Ed25519PublicKey] = {}
    for key_id, encoded in value.items():
        if not isinstance(key_id, str) or not isinstance(encoded, str):
            raise _command_error("issuer key entry is invalid")
        try:
            result[IssuerKeyId(key_id)] = public_key_from_bytes(
                base64.b64decode(encoded, validate=True)
            )
        except (ValueError, AstralError) as error:
            raise _command_error("issuer public key is invalid") from error
    return result


def _text(raw: Mapping[str, object], field: str) -> str:
    value = raw.get(field)
    if not isinstance(value, str):
        raise TypeError(field)
    return value


def _text_list(raw: Mapping[str, object], field: str) -> list[str]:
    value = raw.get(field)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise TypeError(field)
    return value


def _require_exact_command(environment: Mapping[str, str]) -> None:
    if environment.get("SSH_ORIGINAL_COMMAND") != SSH_ORIGINAL_COMMAND:
        raise _command_error("SSH original command is not Astral protocol marker")


def _require_transport_key(trust: ServerTrust, transport_key_id: str) -> None:
    if transport_key_id not in trust.transport_key_ids:
        raise _command_error("transport key is not enrolled")


def _command_error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PROTOCOL_COMMAND,
        message=message,
        security_result="remote SSH request was rejected",
        unsafe_reason="forced command accepts only enrolled Astral protocol traffic",
        next_action="use enrolled Astral Project transport",
    )


def _issuer_error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.PROTOCOL_ISSUER,
        message=message,
        security_result="remote protocol request was rejected",
        unsafe_reason="grant must be signed by an enrolled issuer key",
        next_action="enroll issuer key or create grant for this host",
    )


def main() -> None:
    """Standalone remote entry for fixed launcher bundles."""
    arguments = sys.argv[1:]
    if len(arguments) != 2 or arguments[0] != "--transport-key":
        raise SystemExit(70)
    raise SystemExit(
        run_ssh_entry(
            arguments[1],
            stdin=sys.stdin.buffer,
            stdout=sys.stdout.buffer,
            stderr=sys.stderr,
            environment=os.environ,
        )
    )
