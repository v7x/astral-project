"""Stable errors for trusted Astral Project code."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum


class ErrorCode(Enum):
    """Stable string and numeric error identifiers."""

    CLI_UNKNOWN_COMMAND = ("ASPR_CLI_UNKNOWN_COMMAND", 1001)
    CLI_INTERNAL_UNAVAILABLE = ("ASPR_CLI_INTERNAL_UNAVAILABLE", 1002)
    CONFIG_INVALID_ID = ("ASPR_CONFIG_INVALID_ID", 2001)
    CONFIG_INVALID_PATH = ("ASPR_CONFIG_INVALID_PATH", 2002)
    CONFIG_UNKNOWN_FIELD = ("ASPR_CONFIG_UNKNOWN_FIELD", 2003)
    CONFIG_PARSE = ("ASPR_CONFIG_PARSE", 2004)
    PATH_INVALID_NAME = ("ASPR_PATH_INVALID_NAME", 3001)
    PERMISSION_WRONG_OWNER = ("ASPR_PERMISSION_WRONG_OWNER", 4001)
    PERMISSION_INSECURE_MODE = ("ASPR_PERMISSION_INSECURE_MODE", 4002)
    PERMISSION_INVALID_TYPE = ("ASPR_PERMISSION_INVALID_TYPE", 4003)
    FILE_CREATE = ("ASPR_PERMISSION_FILE_CREATE", 4004)
    FILE_ATOMIC_WRITE = ("ASPR_PERMISSION_ATOMIC_WRITE", 4005)
    CRYPTO_SERIALIZATION = ("ASPR_CRYPTO_SERIALIZATION", 5001)
    CRYPTO_SIGNATURE = ("ASPR_CRYPTO_SIGNATURE", 5002)
    CRYPTO_CONTEXT = ("ASPR_CRYPTO_CONTEXT", 5003)
    CRYPTO_KEY_STORAGE = ("ASPR_CRYPTO_KEY_STORAGE", 5004)
    GRANT_INVALID = ("ASPR_GRANT_INVALID", 6001)
    GRANT_EXTENSION = ("ASPR_GRANT_EXTENSION", 6002)
    STATE_OPEN = ("ASPR_STATE_OPEN", 7001)
    STATE_MIGRATION = ("ASPR_STATE_MIGRATION", 7002)
    STATE_VERSION = ("ASPR_STATE_VERSION", 7003)
    STATE_CORRUPT = ("ASPR_STATE_CORRUPT", 7004)
    DAEMON_PROTOCOL = ("ASPR_DAEMON_PROTOCOL", 8001)
    DAEMON_AUTH = ("ASPR_DAEMON_AUTH", 8002)
    DAEMON_UNAVAILABLE = ("ASPR_DAEMON_UNAVAILABLE", 8003)
    DAEMON_STARTUP = ("ASPR_DAEMON_STARTUP", 8004)
    HOST_RECORD = ("ASPR_HOST_RECORD", 9001)
    HOST_PROBE = ("ASPR_HOST_PROBE", 9002)
    HOST_ENROLLMENT = ("ASPR_HOST_ENROLLMENT", 9003)
    PROTOCOL_COMMAND = ("ASPR_PROTOCOL_COMMAND", 10001)
    PROTOCOL_FRAME = ("ASPR_PROTOCOL_FRAME", 10002)
    PROTOCOL_VERSION = ("ASPR_PROTOCOL_VERSION", 10003)
    PROTOCOL_ISSUER = ("ASPR_PROTOCOL_ISSUER", 10004)
    PATH_RESOLUTION = ("ASPR_PATH_RESOLUTION", 11001)
    PATH_UNSUPPORTED = ("ASPR_PATH_UNSUPPORTED", 11002)
    PATH_AUTOFS = ("ASPR_PATH_AUTOFS", 11003)
    HARDENING_UNAVAILABLE = ("ASPR_HARDENING_UNAVAILABLE", 12001)
    HARDENING_APPLY = ("ASPR_HARDENING_APPLY", 12002)
    HARDENING_POLICY = ("ASPR_HARDENING_POLICY", 12003)

    def __init__(self, string: str, number: int) -> None:
        self.string = string
        self.number = number


@dataclass(slots=True)
class AstralError(Exception):
    """Error with user-safe text and machine-safe JSON envelopes."""

    code: ErrorCode
    message: str
    security_result: str
    unsafe_reason: str
    next_action: str
    dependency_error: str | None = None

    def __str__(self) -> str:
        return self.to_text()

    def to_dict(self) -> dict[str, object]:
        return {
            "code": self.code.string,
            "dependency_error": self.dependency_error,
            "message": self.message,
            "next_action": self.next_action,
            "number": self.code.number,
            "security_result": self.security_result,
            "unsafe_reason": self.unsafe_reason,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)

    def to_text(self) -> str:
        return "\n".join(
            (
                f"{self.code.string} [{self.code.number}]: {self.message}",
                f"Security result: {self.security_result}",
                f"Why: {self.unsafe_reason}",
                f"Fix: {self.next_action}",
            )
        )
