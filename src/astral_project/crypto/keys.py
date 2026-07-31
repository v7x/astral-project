"""Ed25519 key generation, private storage, and signature primitives."""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.paths import atomic_write_private, check_private_path


def _key_error(message: str, error: Exception | None = None) -> AstralError:
    return AstralError(
        code=ErrorCode.CRYPTO_KEY_STORAGE,
        message=message,
        security_result="key material was rejected",
        unsafe_reason="signing keys must remain valid private Ed25519 seeds",
        next_action="replace key using trusted key-management command",
        dependency_error=None if error is None else str(error),
    )


def zeroize(value: bytearray) -> None:
    """Clear mutable sensitive buffer in place."""
    value[:] = b"\x00" * len(value)


def generate_private_key() -> Ed25519PrivateKey:
    """Generate an Ed25519 private key through cryptography backend."""
    return Ed25519PrivateKey.generate()


def public_key_bytes(key: Ed25519PrivateKey | Ed25519PublicKey) -> bytes:
    """Return 32-byte raw public key."""
    public_key = key.public_key() if isinstance(key, Ed25519PrivateKey) else key
    return public_key.public_bytes_raw()


def store_private_key(path: Path, key: Ed25519PrivateKey) -> None:
    """Store raw private seed using Packet 2 private atomic-write boundary."""
    seed = bytearray(key.private_bytes_raw())
    try:
        atomic_write_private(path, bytes(seed))
    finally:
        zeroize(seed)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load a private seed and clear mutable copy after backend import."""
    check_private_path(path)
    seed = bytearray(path.read_bytes())
    try:
        return Ed25519PrivateKey.from_private_bytes(bytes(seed))
    except ValueError as error:
        raise _key_error("private key is not a valid Ed25519 seed", error) from error
    finally:
        zeroize(seed)


def sign(key: Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign canonical bytes."""
    return key.sign(data)


def verify(key: Ed25519PublicKey, signature: bytes, data: bytes) -> bool:
    """Verify signature without exposing backend exception to policy code."""
    try:
        key.verify(signature, data)
    except InvalidSignature:
        return False
    return True


def public_key_from_bytes(data: bytes) -> Ed25519PublicKey:
    """Parse raw 32-byte Ed25519 public key."""
    try:
        return Ed25519PublicKey.from_public_bytes(data)
    except ValueError as error:
        raise _key_error("public key is not valid Ed25519 bytes", error) from error
