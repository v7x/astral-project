"""Policy checks for extensions advertised by fixed OpenSSH sftp-server."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.sftp.client import SftpExtensions

# These extensions are observational or preserve ordinary namespace semantics.
# Shell, device, and arbitrary server-control extensions are never accepted.
DEFAULT_ALLOWED_EXTENSIONS = frozenset(
    {
        b"posix-rename@openssh.com",
        b"statvfs@openssh.com",
        b"fstatvfs@openssh.com",
        b"hardlink@openssh.com",
        b"fsync@openssh.com",
        b"lsetstat@openssh.com",
        b"limits@openssh.com",
        b"expand-path@openssh.com",
        b"copy-data",
        b"check-file",
        b"supported",
        b"supported2",
        b"home-directory",
        b"users-groups-by-id@openssh.com",
    }
)


@dataclass(frozen=True, slots=True)
class SftpExtensionPolicy:
    """Explicit extension allowlist; server defaults are not policy."""

    allowed: frozenset[bytes] = DEFAULT_ALLOWED_EXTENSIONS

    def validate(self, extensions: SftpExtensions) -> frozenset[bytes]:
        unsupported = extensions.names().difference(self.allowed)
        if unsupported:
            raise AstralError(
                code=ErrorCode.PROTOCOL_VERSION,
                message="SFTP server advertised unsupported extensions",
                security_result="SFTP extension set was rejected",
                unsafe_reason="OpenSSH defaults are not Astral policy",
                next_action="pin a compatible fixed sftp-server or update extension policy",
                dependency_error=", ".join(
                    sorted(name.decode("utf-8", "replace") for name in unsupported)
                ),
            )
        return extensions.names()


def validate_extensions(
    extensions: SftpExtensions, *, allowed: Iterable[bytes] = DEFAULT_ALLOWED_EXTENSIONS
) -> frozenset[bytes]:
    """Validate one advertised extension set with a caller-independent allowlist."""
    return SftpExtensionPolicy(frozenset(allowed)).validate(extensions)
