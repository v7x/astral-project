"""Canonical CBOR tests."""

import cbor2
import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.cbor import CborValue, _strict_loads, canonical_dumps, canonical_loads


def test_canonical_cbor_is_deterministic_across_map_order() -> None:
    first: dict[str, CborValue] = {
        "extensions": {"z": 1, "a": [True, b"bytes"]},
        "host": "cluster",
    }
    second: dict[str, CborValue] = {
        "host": "cluster",
        "extensions": {"a": [True, b"bytes"], "z": 1},
    }

    encoded = canonical_dumps(first)

    assert encoded == canonical_dumps(second)
    assert canonical_loads(encoded) == second


@pytest.mark.parametrize("value", [1.5, {1: "bad"}, ("tuple",)])
def test_canonical_cbor_rejects_unsupported_values(value: object) -> None:
    with pytest.raises(AstralError) as error:
        canonical_dumps(value)  # type: ignore[arg-type]

    assert error.value.code is ErrorCode.CRYPTO_SERIALIZATION


def test_canonical_cbor_rejects_noncanonical_bytes() -> None:
    with pytest.raises(AstralError) as error:
        canonical_loads(b"\xa2ab\x01aa\x02")

    assert error.value.code is ErrorCode.CRYPTO_SERIALIZATION


def test_canonical_cbor_wraps_encoder_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def failed_dumps(*args: object, **kwargs: object) -> bytes:
        raise cbor2.CBOREncodeError("failure")

    monkeypatch.setattr(cbor2, "dumps", failed_dumps)
    with pytest.raises(AstralError) as error:
        canonical_dumps("value")

    assert error.value.code is ErrorCode.CRYPTO_SERIALIZATION


def test_canonical_cbor_uses_strict_fallback_for_old_decoder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_loads = cbor2.loads

    def legacy_loads(data: bytes, **kwargs: object) -> object:
        if kwargs:
            raise TypeError("invalid keyword argument")
        return original_loads(data)

    monkeypatch.setattr(cbor2, "loads", legacy_loads)
    encoded = canonical_dumps({"value": [True, None]})
    assert canonical_loads(encoded) == {"value": [True, None]}
    with pytest.raises(AstralError):
        canonical_loads(b"\xa2aa\x01aa\x01")


@pytest.mark.parametrize(
    ("encoded", "expected"),
    [
        (b"\x18\x18", 24),
        (b"\x19\x01\x00", 256),
        (b"\x1a\x00\x01\x00\x00", 65536),
        (b"\x1b\x00\x00\x00\x01\x00\x00\x00\x00", 4294967296),
        (b"\x20", -1),
        (b"\x41a", b"a"),
        (b"\x61a", "a"),
        (b"\x82\x01\x02", [1, 2]),
        (b"\xf4", False),
        (b"\xf5", True),
        (b"\xf6", None),
    ],
)
def test_strict_cbor_decoder_supports_bounded_values(encoded: bytes, expected: CborValue) -> None:
    assert _strict_loads(encoded) == expected


@pytest.mark.parametrize(
    "encoded",
    [
        b"",
        b"\x18",
        b"\x1c",
        b"\x1f",
        b"\x42a",
        b"\x61\xff",
        b"\xa2aa\x01aa\x01",
        b"\xa1\x01\x01",
        b"\xf7",
        b"\xc0\x00",
        b"\x01\x00",
    ],
)
def test_strict_cbor_decoder_rejects_unsafe_values(encoded: bytes) -> None:
    with pytest.raises(AstralError) as error:
        _strict_loads(encoded)
    assert error.value.code is ErrorCode.CRYPTO_SERIALIZATION


def test_canonical_cbor_rejects_malformed_bytes() -> None:
    with pytest.raises(AstralError) as error:
        canonical_loads(b"\xa1")

    assert error.value.code is ErrorCode.CRYPTO_SERIALIZATION
