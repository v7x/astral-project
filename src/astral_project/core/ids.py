"""Opaque typed identifiers."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Self

from astral_project.core.errors import AstralError, ErrorCode


def _invalid_id(value: object) -> AstralError:
    return AstralError(
        code=ErrorCode.CONFIG_INVALID_ID,
        message=f"invalid identifier {value!r}",
        security_result="identifier was rejected",
        unsafe_reason="trusted records require canonical UUID4 identifiers",
        next_action="supply a canonical UUID4 value",
    )


@dataclass(frozen=True, slots=True)
class Uuid4Id:
    """Canonical UUID4 identifier base class."""

    value: str

    def __post_init__(self) -> None:
        try:
            parsed = uuid.UUID(self.value)
        except (AttributeError, ValueError) as error:
            raise _invalid_id(self.value) from error
        if parsed.version != 4 or str(parsed) != self.value:
            raise _invalid_id(self.value)

    @classmethod
    def new(cls: type[Self]) -> Self:
        return cls(str(uuid.uuid4()))

    def __str__(self) -> str:
        return self.value


class HostId(Uuid4Id):
    """Host identifier."""


class GrantId(Uuid4Id):
    """Grant identifier."""


class SessionId(Uuid4Id):
    """Session identifier."""


class ProfileId(Uuid4Id):
    """Profile identifier."""


class IssuerKeyId(Uuid4Id):
    """Grant issuer key identifier."""


class TransportCapability(Uuid4Id):
    """Private transport bearer capability identifier."""


@dataclass(frozen=True, slots=True)
class RequestNumber:
    """Positive approval request number."""

    value: int

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not isinstance(self.value, int) or self.value < 1:
            raise _invalid_id(self.value)

    def __str__(self) -> str:
        return str(self.value)
