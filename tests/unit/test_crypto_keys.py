"""Ed25519 key primitive tests."""

from pathlib import Path

import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.keys import (
    generate_private_key,
    load_private_key,
    public_key_bytes,
    public_key_from_bytes,
    sign,
    store_private_key,
    verify,
    zeroize,
)


def test_ed25519_sign_verify_and_public_round_trip() -> None:
    key = generate_private_key()
    data = b"canonical grant bytes"
    signature = sign(key, data)
    public = public_key_from_bytes(public_key_bytes(key))

    assert verify(public, signature, data)
    assert not verify(public, signature, b"mutated")
    assert len(signature) == 64


def test_private_key_storage_is_private_and_loadable(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "grant-signing.key"
    key = generate_private_key()

    store_private_key(path, key)
    loaded = load_private_key(path)

    assert path.stat().st_mode & 0o077 == 0
    assert public_key_bytes(loaded) == public_key_bytes(key)


def test_invalid_key_bytes_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "key"
    path.write_bytes(b"not-a-key")
    path.chmod(0o600)

    with pytest.raises(AstralError) as error:
        load_private_key(path)
    assert error.value.code is ErrorCode.CRYPTO_KEY_STORAGE

    with pytest.raises(AstralError) as error:
        public_key_from_bytes(b"bad")
    assert error.value.code is ErrorCode.CRYPTO_KEY_STORAGE


def test_zeroize_clears_mutable_buffer() -> None:
    secret = bytearray(b"secret")

    zeroize(secret)

    assert secret == b"\x00" * 6
