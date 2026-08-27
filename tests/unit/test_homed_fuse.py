from __future__ import annotations

import asyncio
import importlib
import sys
import types

import pytest

import astral_project.homed.fuse as fuse
from astral_project.homed.core import InodeRecord, RequestBudget
from astral_project.homed.fuse import (
    FuseUnavailable,
    ProjectedHomeOperations,
    _attributes,
    _fuse_error,
    _host_attributes,
)
from astral_project.homed.host import BackingNode


def test_fuse_adapter_is_import_safe_without_optional_runtime() -> None:
    if fuse.__dict__["_pyfuse3"] is not None:
        pytest.skip("optional FUSE runtime installed; use packaged acceptance")
    with pytest.raises(FuseUnavailable):
        _fuse_error(OSError(5, "io"))
    with pytest.raises(FuseUnavailable):
        _attributes(InodeRecord(1, 0o40755))
    with pytest.raises(FuseUnavailable):
        _host_attributes(BackingNode(2, ".x", 0o100644, 1, 0, False))
    with pytest.raises(FuseUnavailable):
        ProjectedHomeOperations()


def test_fuse_lookup_cancellation_releases_request_lease(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Operations:
        def __init__(self) -> None:
            pass

    class FUSEError(OSError):
        pass

    fake = types.SimpleNamespace(
        Operations=Operations,
        FUSEError=FUSEError,
        EntryAttributes=type("EntryAttributes", (), {}),
        FileInfo=type("FileInfo", (), {}),
        StatvfsData=type("StatvfsData", (), {}),
        default_options=set(),
        readdir_reply=lambda *_args: True,
    )
    monkeypatch.setitem(sys.modules, "pyfuse3", fake)
    loaded = importlib.reload(fuse)
    try:
        operations = loaded.ProjectedHomeOperations()
        operations.state.budget = RequestBudget(max_requests=1, max_memory=8)

        def cancelled(_parent: int, _name: bytes) -> InodeRecord:
            raise asyncio.CancelledError

        monkeypatch.setattr(operations.state, "lookup", cancelled)
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(operations.lookup(1, b".", None))
        assert operations.state.budget.memory_used == 0
    finally:
        monkeypatch.delitem(sys.modules, "pyfuse3")
        importlib.reload(fuse)
