"""Focused source-pinning validation tests."""

from __future__ import annotations

import socket
from types import SimpleNamespace

import pytest

from astral_project.broker import sources
from astral_project.core.errors import AstralError
from astral_project.crypto.grants import AccessMode, ExportKind, SourceIdentity
from astral_project.server.path_resolver import (
    MountTopology,
    ResolvedSource,
)
from astral_project.server.path_resolver import (
    SourceIdentity as ResolvedIdentity,
)


def test_pinned_sources_rejects_plan_mismatch() -> None:
    export = SimpleNamespace(descriptor_slot=0)
    with pytest.raises(AstralError):
        sources.PinnedSources(SimpleNamespace(exports=(export,)), ())  # type: ignore[arg-type]


def test_pinned_sources_close_is_idempotent(monkeypatch: pytest.MonkeyPatch) -> None:
    export = SimpleNamespace(descriptor_slot=0)
    plan = SimpleNamespace(exports=(export,))
    pinned = sources.PinnedSources(plan, (sources.PinnedSource(55, export, 1),))  # type: ignore[arg-type]
    closed: list[int] = []
    monkeypatch.setattr("astral_project.broker.sources.os.close", closed.append)
    pinned.close()
    pinned.close()
    assert closed == [55]


def test_source_helpers_accept_valid_root_identity_and_export() -> None:
    root = SimpleNamespace(canonical_root="/root", nested_mount_policy="allow")
    ceiling = SimpleNamespace(source_roots=(root,))
    identity = SourceIdentity(1, 2, "ext4", ExportKind.FILE)
    resolved_identity = ResolvedIdentity(1, 2, 3, "ext4", ExportKind.FILE)
    source = ResolvedSource("/root/file", 3, resolved_identity, (), False)
    sources._require_safe_broker_topology(source, "/root", ceiling)  # type: ignore[arg-type]
    sources._require_signed_identity(
        source,
        SimpleNamespace(canonical_source="/root/file", source_identity=identity),  # type: ignore[arg-type]
    )
    planned = SimpleNamespace(
        virtual_target="/target",
        access_mode=AccessMode.READ_ONLY,
        kind="file",
        identity=identity,
    )
    exported = SimpleNamespace(
        virtual_target="/target",
        access_mode=AccessMode.READ_ONLY,
        kind=ExportKind.FILE,
        source_identity=identity,
    )
    result = sources._grant_export_for_plan_export(
        SimpleNamespace(exports=(exported,)),  # type: ignore[arg-type]
        planned,  # type: ignore[arg-type]
    )
    assert result.virtual_target == "/target"
    assert sources._root_for_source("/root/file", ceiling) == "/root"  # type: ignore[arg-type]


def test_source_validation_rejects_wrong_root_filesystem_and_identity() -> None:
    root = SimpleNamespace(canonical_root="/root", nested_mount_policy="forbid")
    ceiling = SimpleNamespace(source_roots=(root,))
    identity = ResolvedIdentity(1, 2, 3, "xfs", ExportKind.FILE)
    source = ResolvedSource("/root/file", 3, identity, (), False)
    with pytest.raises(AstralError):
        sources._require_safe_broker_topology(source, "/root", ceiling)  # type: ignore[arg-type]
    identity = ResolvedIdentity(1, 2, 3, "ext4", ExportKind.FILE)
    source = ResolvedSource("/root/file", 3, identity, (MountTopology(1, 0, "/", "ext4"),), False)
    with pytest.raises(AstralError):
        sources._require_safe_broker_topology(source, "/root", ceiling)  # type: ignore[arg-type]
    export = SimpleNamespace(
        canonical_source="/root/other",
        source_identity=SourceIdentity(1, 2, "ext4", ExportKind.FILE),
    )
    with pytest.raises(AstralError):
        sources._require_signed_identity(source, export)  # type: ignore[arg-type]
    with pytest.raises(AstralError):
        sources._grant_export_for_plan_export(
            SimpleNamespace(exports=()),  # type: ignore[arg-type]
            SimpleNamespace(  # type: ignore[arg-type]
                virtual_target="/missing",
                access_mode=ExportKind.FILE,
                kind="file",
                identity=identity,
            ),
        )


def test_target_source_handoff_child_sends_pinned_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Exit0(BaseException):
        pass

    class Exit1(BaseException):
        pass

    class Endpoint:
        def __init__(self) -> None:
            self.sent = False

        def close(self) -> None:
            return None

        def sendmsg(self, *_args: object) -> None:
            self.sent = True

        def send(self, _data: bytes) -> None:
            self.sent = True

    parent, child = Endpoint(), Endpoint()
    pinned = SimpleNamespace(
        sources=(SimpleNamespace(descriptor=7),),
        close=lambda: None,
    )
    exits: list[int] = []
    monkeypatch.setattr(
        "astral_project.broker.sources.socket.socketpair", lambda *_args: (parent, child)
    )
    monkeypatch.setattr("astral_project.broker.sources.os.fork", lambda: 0)
    monkeypatch.setattr("astral_project.broker.sources.os.setgroups", lambda _groups: None)
    monkeypatch.setattr("astral_project.broker.sources.os.setresgid", lambda *_args: None)
    monkeypatch.setattr("astral_project.broker.sources.os.setresuid", lambda *_args: None)
    monkeypatch.setattr(sources, "_pin_grant_sources", lambda *_args, **_kwargs: pinned)

    def exit_process(code: int) -> None:
        exits.append(code)
        raise Exit0 if code == 0 else Exit1

    monkeypatch.setattr("astral_project.broker.sources.os._exit", exit_process)
    with pytest.raises(Exit1):
        sources._pin_grant_sources_as_target(
            SimpleNamespace(exports=(object(),)),  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            1,
            1,
        )
    assert exits == [0, 1]
    assert child.sent


def test_target_source_handoff_rejects_malformed_rights(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Endpoint:
        def close(self) -> None:
            return None

    parent, child = Endpoint(), Endpoint()
    monkeypatch.setattr(
        "astral_project.broker.sources.socket.socketpair", lambda *_args: (parent, child)
    )
    monkeypatch.setattr("astral_project.broker.sources.os.fork", lambda: 123)
    monkeypatch.setattr("astral_project.broker.sources.os.waitpid", lambda *_args: (123, 0))
    monkeypatch.setattr(
        parent,
        "recvmsg",
        lambda *_args: (b"O", [(socket.SOL_SOCKET, socket.SCM_RIGHTS, b"x")], 0, None),
        raising=False,
    )
    with pytest.raises(AstralError):
        sources._pin_grant_sources_as_target(
            SimpleNamespace(exports=(object(),)),  # type: ignore[arg-type]
            SimpleNamespace(),  # type: ignore[arg-type]
            1,
            1,
        )


def test_source_helpers_require_unique_root_and_dac(monkeypatch: pytest.MonkeyPatch) -> None:
    ceiling = SimpleNamespace(
        source_roots=(
            SimpleNamespace(canonical_root="/root", nested_mount_policy="allow"),
            SimpleNamespace(canonical_root="/root/sub", nested_mount_policy="allow"),
        )
    )
    with pytest.raises(AstralError):
        sources._root_for_source("/elsewhere", ceiling)  # type: ignore[arg-type]
    with pytest.raises(AstralError):
        sources._root_for_source("/root/sub/file", ceiling)  # type: ignore[arg-type]
    with pytest.raises(AstralError):
        sources._pin_from_descriptors(SimpleNamespace(exports=()), ceiling, [1])  # type: ignore[arg-type]
    identity = SimpleNamespace(device=1, inode=2, filesystem_type="ext4", kind=ExportKind.DIRECTORY)
    source = ResolvedSource("/root/dir", 3, identity, ())  # type: ignore[arg-type]
    monkeypatch.setattr("astral_project.broker.sources.os.open", lambda *_args: 55)
    closed: list[int] = []
    monkeypatch.setattr("astral_project.broker.sources.os.close", closed.append)
    sources._require_target_dac_access(source)
    assert closed == [55]
    monkeypatch.setattr(
        "astral_project.broker.sources.os.open", lambda *_args: (_ for _ in ()).throw(OSError())
    )
    with pytest.raises(AstralError):
        sources._require_target_dac_access(source)
