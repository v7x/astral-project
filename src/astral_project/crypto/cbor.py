"""Canonical CBOR boundary."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import cbor2

from astral_project.core.errors import AstralError, ErrorCode

type CborScalar = str | bytes | int | bool | None
type CborValue = CborScalar | list[CborValue] | dict[str, CborValue]


def _serialization_error(message: str, dependency_error: str | None = None) -> AstralError:
    return AstralError(
        code=ErrorCode.CRYPTO_SERIALIZATION,
        message=message,
        security_result="CBOR value was rejected",
        unsafe_reason="signed bytes require one deterministic representation",
        next_action="use supported canonical CBOR value types",
        dependency_error=dependency_error,
    )


def _validate_value(value: object) -> None:
    if value is None or isinstance(value, (bool, bytes, int, str)):
        return
    if isinstance(value, list):
        for item in value:
            _validate_value(item)
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _serialization_error("CBOR map key must be text")
            _validate_value(item)
        return
    raise _serialization_error(f"unsupported CBOR value type {type(value).__name__}")


def canonical_dumps(value: CborValue) -> bytes:
    """Encode only supported values with RFC canonical map ordering."""
    _validate_value(value)
    try:
        return cbor2.dumps(value, canonical=True)
    except (TypeError, ValueError, cbor2.CBORError) as error:
        raise _serialization_error("CBOR encoding failed", str(error)) from error


def canonical_loads(data: bytes) -> CborValue:
    """Decode and require byte-for-byte canonical re-encoding."""
    try:
        decoded: object = cbor2.loads(data, allow_duplicate_keys=False, allow_indefinite=False)
    except (TypeError, ValueError, cbor2.CBORError) as error:
        raise _serialization_error("CBOR decoding failed", str(error)) from error
    _validate_value(decoded)
    value = cast(CborValue, decoded)
    if canonical_dumps(value) != data:
        raise _serialization_error("CBOR bytes are not canonical")
    return value
