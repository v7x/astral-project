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


class _StrictDecodeError(ValueError):
    """Malformed or unsupported CBOR seen by compatibility decoder."""


class _StrictDecoder:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def _byte(self) -> int:
        if self.offset >= len(self.data):
            raise _StrictDecodeError("truncated CBOR")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def _length(self, additional: int) -> int:
        if additional < 24:
            return additional
        width = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        if width is None:
            raise _StrictDecodeError("indefinite or invalid CBOR length")
        end = self.offset + width
        if end > len(self.data):
            raise _StrictDecodeError("truncated CBOR length")
        value = int.from_bytes(self.data[self.offset : end], "big")
        self.offset = end
        return value

    def value(self) -> CborValue:
        initial = self._byte()
        major = initial >> 5
        additional = initial & 0x1F
        if additional == 31:
            raise _StrictDecodeError("indefinite CBOR items are forbidden")
        if major == 0:
            return self._length(additional)
        if major == 1:
            return -1 - self._length(additional)
        if major in {2, 3}:
            length = self._length(additional)
            end = self.offset + length
            if end > len(self.data):
                raise _StrictDecodeError("truncated CBOR string")
            raw = self.data[self.offset : end]
            self.offset = end
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as error:
                raise _StrictDecodeError("invalid CBOR UTF-8") from error
        if major == 4:
            return [self.value() for _ in range(self._length(additional))]
        if major == 5:
            result: dict[str, CborValue] = {}
            for _ in range(self._length(additional)):
                key = self.value()
                if not isinstance(key, str):
                    raise _StrictDecodeError("CBOR map key must be text")
                if key in result:
                    raise _StrictDecodeError("duplicate CBOR map key")
                result[key] = self.value()
            return result
        if major == 7 and additional in {20, 21, 22}:
            return {20: False, 21: True, 22: None}[additional]
        raise _StrictDecodeError("unsupported CBOR item")

    def decode(self) -> CborValue:
        value = self.value()
        if self.offset != len(self.data):
            raise _StrictDecodeError("trailing CBOR bytes")
        return value


def _strict_loads(data: bytes) -> CborValue:
    try:
        return _StrictDecoder(data).decode()
    except _StrictDecodeError as error:
        raise _serialization_error("CBOR decoding failed", str(error)) from error


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
    except TypeError:
        # Ubuntu 24.04's cbor2 lacks strict keyword arguments. The compatibility
        # parser preserves duplicate/indefinite/trailing-byte rejection.
        value = _strict_loads(data)
    except (ValueError, cbor2.CBORError) as error:
        raise _serialization_error("CBOR decoding failed", str(error)) from error
    else:
        _validate_value(decoded)
        value = cast(CborValue, decoded)
    if canonical_dumps(value) != data:
        raise _serialization_error("CBOR bytes are not canonical")
    return value
