"""Atomic active runtime closure installation and reopening."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.runtime.closure import (
    RuntimeClosureBuilder,
    RuntimeManifestV1,
    verify_runtime_closure,
)

_ACTIVE_MANIFEST = "active-manifest.cbor"


def install_active_runtime_closure(manifest: RuntimeManifestV1, runtime_root: Path) -> Path:
    """Install verified digest directory, then atomically publish its exact manifest."""
    closure = RuntimeClosureBuilder().install(manifest, runtime_root)
    if closure.name != manifest.digest():
        raise _error("runtime closure digest does not match manifest")
    _atomic_write(runtime_root / _ACTIVE_MANIFEST, manifest.canonical_bytes())
    return closure


def load_active_runtime_closure(runtime_root: Path, expected_digest: str) -> RuntimeManifestV1:
    """Require configured digest equals active manifest and verified closure directory."""
    if len(expected_digest) != 64 or any(
        character not in "0123456789abcdef" for character in expected_digest
    ):
        raise _error("configured runtime manifest digest is invalid")
    active_path = runtime_root / _ACTIVE_MANIFEST
    try:
        active_bytes = active_path.read_bytes()
    except OSError as error:
        raise _error("active runtime manifest is unavailable") from error
    manifest = RuntimeManifestV1.from_cbor(
        active_bytes, closure_root=runtime_root / expected_digest
    )
    if manifest.digest() != expected_digest:
        raise _error("active runtime manifest differs from configured digest")
    verify_runtime_closure(runtime_root / expected_digest, manifest)
    return manifest


def _atomic_write(path: Path, content: bytes) -> None:
    try:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o644)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        raise _error("could not publish active runtime manifest") from error


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.CONFIG_INVALID_PATH,
        message=message,
        security_result="active runtime closure was rejected",
        unsafe_reason="broker may execute only exact installed verified runtime closure",
        next_action="install a verified runtime closure again",
    )
