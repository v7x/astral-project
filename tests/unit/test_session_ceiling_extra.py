"""Server ceiling structural validation boundaries."""

from __future__ import annotations

import pytest

from astral_project.core.errors import AstralError
from astral_project.core.ids import IssuerKeyId
from astral_project.crypto.cbor import canonical_dumps
from astral_project.crypto.grants import AccessMode, ExportKind
from astral_project.session.ceiling import (
    ServerCeilingV1,
    SourceRootCeilingV1,
    _bytes,
    _strings,
    paths_overlap,
)

ISSUER = IssuerKeyId("00000000-0000-4000-8000-000000000001")


def _root(path: str = "/source") -> SourceRootCeilingV1:
    return SourceRootCeilingV1(path, AccessMode.READ_ONLY, (ExportKind.DIRECTORY,))


def _ceiling(**kwargs: object) -> ServerCeilingV1:
    values: dict[str, object] = {
        "source_roots": (_root(),),
        "allowed_issuers": (ISSUER,),
        "forbidden_source_roots": (),
        "max_exports": 1,
        "max_ttl_seconds": 1,
        "policy_hash": b"p" * 32,
    }
    values.update(kwargs)
    return ServerCeilingV1(**values)  # type: ignore[arg-type]


def test_root_payload_rejects_unknown_invalid_and_unsorted_values() -> None:
    with pytest.raises(AstralError):
        SourceRootCeilingV1.from_payload({})
    with pytest.raises(AstralError):
        SourceRootCeilingV1.from_payload(
            {
                "allowed_kinds": ["directory", "file"],
                "canonical_root": "/source",
                "maximum_access": "bad",
                "nested_mount_policy": "forbid",
            }
        )
    with pytest.raises(AstralError):
        SourceRootCeilingV1("relative", AccessMode.READ_ONLY, (ExportKind.DIRECTORY,))
    with pytest.raises(AstralError):
        SourceRootCeilingV1("/source", AccessMode.READ_ONLY, (), "forbid")
    with pytest.raises(AstralError):
        SourceRootCeilingV1("/source", AccessMode.READ_ONLY, (ExportKind.DIRECTORY,), "bad")


def test_server_ceiling_rejects_limits_paths_issuers_and_versions() -> None:
    cases = (
        {"version": 2},
        {"policy_hash": b"x"},
        {"max_exports": 0},
        {"max_ttl_seconds": 0},
        {"source_roots": ()},
        {"allowed_issuers": ()},
        {"forbidden_source_roots": ("relative",)},
        {"source_roots": (_root("/source/b"), _root("/source/a"))},
    )
    for change in cases:
        with pytest.raises(AstralError):
            _ceiling(**change)


def test_ceiling_payload_type_validation_and_component_overlap() -> None:
    payload = _ceiling().to_payload()
    for field, value in (("allowed_issuers", [1]), ("policy_hash", "bad"), ("max_exports", True)):
        changed = dict(payload)
        changed[field] = value  # type: ignore[assignment]
        with pytest.raises(AstralError):
            ServerCeilingV1.from_cbor(
                __import__(
                    "astral_project.crypto.cbor", fromlist=["canonical_dumps"]
                ).canonical_dumps(changed)
            )
    assert paths_overlap("/a", "/a")
    assert paths_overlap("/a/b", "/a")
    assert not paths_overlap("/a/b", "/ab")
    with pytest.raises(AstralError):
        ServerCeilingV1.from_cbor(canonical_dumps({}))
    with pytest.raises(AstralError):
        ServerCeilingV1.from_cbor(canonical_dumps({**_ceiling().to_payload(), "source_roots": [1]}))
    with pytest.raises(AstralError):
        _strings({}, "missing")
    with pytest.raises(AstralError):
        _bytes({}, "missing")
