"""Packet 39 executable remote threat-matrix gate."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import cast

import pytest

ROOT = Path(__file__).parents[2]
MATRIX = ROOT / "docs" / "evidence" / "packet-39-40-threat-matrix.json"
_DOCUMENT = cast(dict[str, object], json.loads(MATRIX.read_text(encoding="utf-8")))
_PACKETS = cast(dict[str, object], _DOCUMENT["packets"])
_REMOTE = tuple(cast(dict[str, str], row) for row in cast(list[object], _PACKETS["39"]))


def _assert_executable(row: dict[str, str]) -> None:
    reference = row["test"]
    path_text, separator, function_name = reference.partition("::")
    target = ROOT / path_text
    assert target.is_file(), f"{row['id']} target missing: {target}"
    if not separator:
        assert target.suffix == ".py", f"{row['id']} script target must be Python: {target}"
        return
    tree = ast.parse(target.read_text(encoding="utf-8"), filename=str(target))
    functions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert function_name in functions, f"{row['id']} test target missing: {reference}"


@pytest.mark.parametrize("row", _REMOTE, ids=[row["id"] for row in _REMOTE])
def test_remote_attack_has_executable_adversarial_target(row: dict[str, str]) -> None:
    _assert_executable(row)


def test_remote_matrix_is_complete_and_marks_rootless_race() -> None:
    assert [row["id"] for row in _REMOTE] == [f"R{index:02d}" for index in range(1, 21)]
    residual = [row for row in _REMOTE if row["class"] == "residual-rootless-race"]
    assert [row["id"] for row in residual] == ["R18"]
