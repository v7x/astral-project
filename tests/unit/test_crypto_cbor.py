"""Canonical CBOR tests."""

import cbor2
import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.cbor import CborValue, canonical_dumps, canonical_loads


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


def test_canonical_cbor_rejects_malformed_bytes() -> None:
    with pytest.raises(AstralError) as error:
        canonical_loads(b"\xa1")

    assert error.value.code is ErrorCode.CRYPTO_SERIALIZATION
