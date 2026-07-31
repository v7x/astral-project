"""Strict TOML configuration loading."""

from __future__ import annotations

import tomllib
from collections.abc import Collection
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode


def load_toml_config(path: Path, *, allowed_fields: Collection[str]) -> dict[str, object]:
    """Load top-level TOML fields and reject every unknown field."""
    try:
        with path.open("rb") as stream:
            data: dict[str, object] = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise AstralError(
            code=ErrorCode.CONFIG_PARSE,
            message=f"could not load configuration: {path}",
            security_result="configuration was rejected",
            unsafe_reason="trusted configuration must parse exactly",
            next_action="repair configuration file and retry",
            dependency_error=str(error),
        ) from error

    unknown_fields = sorted(set(data).difference(allowed_fields))
    if unknown_fields:
        raise AstralError(
            code=ErrorCode.CONFIG_UNKNOWN_FIELD,
            message=f"unknown configuration fields: {', '.join(unknown_fields)}",
            security_result="configuration was rejected",
            unsafe_reason="unknown settings cannot silently alter trusted behavior",
            next_action="remove unknown fields or update compatible software",
        )
    return data
