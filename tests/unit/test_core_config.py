"""Strict configuration tests."""

from pathlib import Path

import pytest

from astral_project.core.config import load_toml_config
from astral_project.core.errors import AstralError, ErrorCode


def test_config_loader_accepts_only_declared_fields(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text('name = "safe"\n', encoding="utf-8")

    assert load_toml_config(path, allowed_fields={"name"}) == {"name": "safe"}


def test_config_loader_rejects_unknown_field(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_text("unknown = true\n", encoding="utf-8")

    with pytest.raises(AstralError) as error:
        load_toml_config(path, allowed_fields=set())

    assert error.value.code is ErrorCode.CONFIG_UNKNOWN_FIELD


@pytest.mark.parametrize("content", ["", "not toml", "number = ["])
def test_config_loader_rejects_missing_or_malformed_file(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.toml"
    if content:
        path.write_text(content, encoding="utf-8")
    else:
        path.unlink(missing_ok=True)

    with pytest.raises(AstralError) as error:
        load_toml_config(path, allowed_fields=set())

    assert error.value.code is ErrorCode.CONFIG_PARSE
