"""Packet 40 executable local threat-matrix gate."""

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
_LOCAL = tuple(cast(dict[str, str], row) for row in cast(list[object], _PACKETS["40"]))


def _assert_executable(row: dict[str, str]) -> None:
    reference = row["test"]
    path_text, separator, function_name = reference.partition("::")
    target = ROOT / path_text
    assert target.is_file(), f"{row['id']} target missing: {target}"
    if not separator:
        assert target.suffix == ".py", f"{row['id']} script target must be Python: {target}"
        function_name = "main"
    tree = ast.parse(target.read_text(encoding="utf-8"), filename=str(target))
    functions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert function_name in functions, f"{row['id']} test target missing: {reference}"


@pytest.mark.parametrize("row", _LOCAL, ids=[row["id"] for row in _LOCAL])
def test_local_attack_has_executable_adversarial_target(row: dict[str, str]) -> None:
    _assert_executable(row)


def test_local_matrix_is_complete() -> None:
    assert [row["id"] for row in _LOCAL] == [f"L{index:02d}" for index in range(1, 23)]
    assert sum(row["class"] == "installed" for row in _LOCAL) >= 4
