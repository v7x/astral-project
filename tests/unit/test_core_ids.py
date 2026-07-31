"""Typed identifier tests."""

import uuid

import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.core.ids import (
    GrantId,
    HostId,
    IssuerKeyId,
    ProfileId,
    RequestNumber,
    SessionId,
    TransportCapability,
)

UUID_TYPES = (HostId, GrantId, SessionId, ProfileId, IssuerKeyId, TransportCapability)


@pytest.mark.parametrize("identifier_type", UUID_TYPES)
def test_uuid4_ids_generate_canonical_values(identifier_type: type[HostId]) -> None:
    identifier = identifier_type.new()

    assert str(identifier) == identifier.value
    assert uuid.UUID(identifier.value).version == 4
    assert identifier_type(identifier.value) == identifier


@pytest.mark.parametrize("value", ["", "not-a-uuid", "6ba7b810-9dad-11d1-80b4-00c04fd430c8"])
def test_invalid_ids_fail_closed(value: str) -> None:
    with pytest.raises(AstralError) as error:
        HostId(value)

    assert error.value.code is ErrorCode.CONFIG_INVALID_ID


@pytest.mark.parametrize("value", [0, -1, True])
def test_invalid_request_number_fails_closed(value: int | bool) -> None:
    with pytest.raises(AstralError) as error:
        RequestNumber(value)

    assert error.value.code is ErrorCode.CONFIG_INVALID_ID


def test_request_number_is_positive() -> None:
    assert str(RequestNumber(1)) == "1"
