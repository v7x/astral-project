from __future__ import annotations

import errno
import os
import stat
import threading
from pathlib import Path

import pytest

from astral_project.homed.host import HostAccessError, HostReadonlyView
from astral_project.homed.mediation import MediationDecision, UnknownPathMediator
from astral_project.profile import CredentialRule, Profile, Rule, RuleMode, RuleScope, Sensitivity


def _profile() -> Profile:
    return Profile.from_toml(
        """
        version = 1
        id = "fixture"
        name = "fixture"
        [[home.rules]]
        path = ".codex/config.toml"
        scope = "exact"
        mode = "host-ro"
        sensitivity = "configuration"
        [[home.rules]]
        path = ".codex"
        scope = "subtree"
        mode = "host-ro"
        sensitivity = "configuration"
        list = true
        """
    )


def test_backend_inode_cache_releases_forgotten_paths(tmp_path: Path) -> None:
    root = tmp_path / "home"
    root.mkdir()
    profile = Profile(
        1,
        "bounded",
        "bounded",
        rules=(Rule("cache", RuleScope.SUBTREE, RuleMode.HOST_RO, list_allowed=True),),
    )
    (root / "cache").mkdir()
    for index in range(32):
        (root / "cache" / f"file-{index}").write_text("x", encoding="utf-8")
    with HostReadonlyView(root, profile) as view:
        baseline = view.inode_count
        nodes = [view.lookup(f"cache/file-{index}") for index in range(32)]
        assert view.inode_count == baseline + len(nodes)
        view.lookup("cache/file-0")
        view.forget(nodes[0].inode, 1)
        assert view.node_path(nodes[0].inode) == "cache/file-0"
        view.forget(1, 1)
        view.forget(999, 1)
        view.forget(nodes[1].inode, -1)
        for node in nodes:
            view.forget(node.inode, 1)
        assert view.inode_count == baseline
        with pytest.raises(HostAccessError) as error:
            view.node_path(nodes[0].inode)
        assert error.value.errno == errno.ENOENT


def test_sealed_opaque_ancestor_traverses_without_listing(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".config" / "tool").mkdir(parents=True)
    (root / ".config" / "tool" / "config.toml").write_text("ok", encoding="utf-8")
    profile = Profile(
        1,
        "sealed",
        "sealed",
        sealed=True,
        rules=(Rule(".config/tool/config.toml", RuleScope.EXACT, RuleMode.HOST_RO),),
    )
    with HostReadonlyView(root, profile) as view:
        assert view.lookup(".config").is_directory
        assert view.stat(".config/tool").is_directory
        with pytest.raises(HostAccessError) as error:
            view.listdir(".config")
        assert error.value.errno == errno.EACCES


def test_credential_host_rule_requires_mediated_strong_confirmation(tmp_path: Path) -> None:
    root = tmp_path / "home"
    root.mkdir()
    (root / "token").write_text("secret", encoding="utf-8")
    profile = Profile(
        1,
        "credential",
        "credential",
        rules=(Rule("token", RuleScope.EXACT, RuleMode.HOST_RO, Sensitivity.CREDENTIAL),),
    )
    with HostReadonlyView(root, profile) as view, pytest.raises(HostAccessError, match="strong"):
        view.read("token")

    mediator = UnknownPathMediator(timeout=1)
    view = HostReadonlyView(root, profile, mediator=mediator, session_id="credential-session")
    result: list[bytes] = []
    thread = threading.Thread(target=lambda: result.append(view.read("token")))
    thread.start()
    while not mediator.pending():
        pass
    assert mediator.decide(
        session_id="credential-session", request_number=1, decision=MediationDecision.ALLOW_ONCE
    )
    thread.join(timeout=1)
    assert result == [b"secret"]
    repeat_result: list[bytes] = []
    repeat_thread = threading.Thread(target=lambda: repeat_result.append(view.read("token")))
    repeat_thread.start()
    while len(mediator.pending()) != 1:
        pass
    assert mediator.decide(
        session_id="credential-session", request_number=2, decision=MediationDecision.ALLOW_ONCE
    )
    repeat_thread.join(timeout=1)
    view.close()
    assert repeat_result == [b"secret"]

    for decision, message in (
        (MediationDecision.HIDE, "hidden credential"),
        (MediationDecision.DENY, "credential confirmation denied"),
    ):
        denied_mediator = UnknownPathMediator(timeout=1)
        denied_view = HostReadonlyView(
            root, profile, mediator=denied_mediator, session_id=f"credential-{decision}"
        )
        errors: list[HostAccessError] = []
        denied_thread = threading.Thread(
            target=_capture_host_error, args=(errors, denied_view, "token")
        )
        denied_thread.start()
        while not denied_mediator.pending():
            pass
        assert denied_mediator.decide(
            session_id=f"credential-{decision}",
            request_number=1,
            decision=decision,
        )
        denied_thread.join(timeout=1)
        denied_view.close()
        assert errors and message in str(errors[0])


def test_explicit_credential_rule_requires_strong_unknown_confirmation(tmp_path: Path) -> None:
    root = tmp_path / "home"
    root.mkdir()
    (root / "secret.txt").write_text("secret", encoding="utf-8")
    profile = Profile(
        1, "credential-unknown", "credential-unknown", credentials=(CredentialRule("secret.txt"),)
    )
    mediator = UnknownPathMediator(timeout=1)
    view = HostReadonlyView(root, profile, mediator=mediator, session_id="credential-unknown")
    result: list[bytes] = []
    thread = threading.Thread(target=lambda: result.append(view.read("secret.txt")))
    thread.start()
    while not mediator.pending():
        pass
    pending = mediator.pending()[0]
    assert pending.sensitivity is Sensitivity.CREDENTIAL
    assert mediator.decide(
        session_id="credential-unknown",
        request_number=pending.request_number,
        decision=MediationDecision.ALLOW_ONCE,
    )
    thread.join(timeout=1)
    view.close()
    assert result == [b"secret"]


def _capture_host_error(errors: list[HostAccessError], view: HostReadonlyView, path: str) -> None:
    try:
        view.read(path)
    except HostAccessError as error:
        errors.append(error)


def test_exact_and_subtree_read_with_sibling_isolation(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)
    (root / ".codex/config.toml").write_text("one", encoding="utf-8")
    (root / ".codex/sibling.txt").write_text("two", encoding="utf-8")
    (root / "secret.txt").write_text("secret", encoding="utf-8")
    with HostReadonlyView(root, _profile()) as view:
        assert view.read(".codex/config.toml") == b"one"
        assert view.lookup(".codex/config.toml") == view.lookup(".codex/config.toml")
        assert view.listdir(".codex") == ("config.toml", "sibling.txt")
        with pytest.raises(HostAccessError):
            view.read("secret.txt")


def test_exact_profile_denies_listing_but_allows_stat_and_offset_read(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)
    path = root / ".codex/config.toml"
    path.write_text("abcdef", encoding="utf-8")
    profile = Profile.from_toml(
        """
        version = 1
        id = "fixture"
        name = "fixture"
        [[home.rules]]
        path = ".codex/config.toml"
        mode = "host-ro"
        """
    )
    with HostReadonlyView(root, profile) as view:
        assert view.stat(".codex/config.toml").size == 6
        assert view.read(".codex/config.toml", offset=2, size=2) == b"cd"
        with pytest.raises(HostAccessError) as error:
            view.listdir(".codex")
        assert error.value.errno == errno.EACCES


def test_host_projection_clears_setid_bits(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)
    path = root / ".codex/config.toml"
    path.write_text("config", encoding="utf-8")
    os.chmod(path, 0o4755)
    with HostReadonlyView(root, _profile()) as view:
        assert view.stat(".codex/config.toml").mode == stat.S_IFREG | 0o755


def test_live_change_is_visible_and_writes_denied(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)
    path = root / ".codex/config.toml"
    path.write_text("one", encoding="utf-8")
    with HostReadonlyView(root, _profile()) as view:
        path.write_text("two", encoding="utf-8")
        assert view.read(".codex/config.toml") == b"two"
        with pytest.raises(HostAccessError) as error:
            view.write(".codex/config.toml", b"no")
        assert error.value.errno == errno.EROFS


def test_symlink_escape_and_absolute_symlink_fail(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    os.symlink(outside, root / ".codex/config.toml")
    with HostReadonlyView(root, _profile()) as view:
        with pytest.raises(HostAccessError):
            view.lookup(".codex/config.toml")
        with pytest.raises(HostAccessError):
            view.read(".codex/config.toml")


def test_close_rejects_future_access_and_directory_read_is_denied(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)
    profile = _profile()
    view = HostReadonlyView(root, profile)
    view.close()
    view.close()
    with pytest.raises(HostAccessError) as error:
        view.stat(".codex")
    assert error.value.errno == errno.ESTALE
    with pytest.raises(HostAccessError) as error:
        view.stat(".")
    assert error.value.errno == errno.ESTALE


def test_host_view_rejects_bad_offsets_unknown_inodes_and_non_host_rules(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)
    (root / ".codex/config.toml").write_text("config", encoding="utf-8")
    with HostReadonlyView(root, _profile()) as view:
        assert view.root_fd >= 0
        assert view.stat(".").inode == 1
        with pytest.raises(HostAccessError):
            view.lookup(".codex/missing.toml")
        with pytest.raises(ValueError):
            view.read(".codex/config.toml", offset=-1)
        with pytest.raises(HostAccessError) as error:
            view.node_path(999)
        assert error.value.errno == errno.ENOENT
        with pytest.raises(HostAccessError) as error:
            view.read(".codex")
        assert error.value.errno == errno.EISDIR
        with pytest.raises(HostAccessError) as error:
            view.listdir(".")
        assert error.value.errno == errno.EACCES

    private = Profile.from_toml(
        """
        version = 1
        id = "p"
        name = "p"
        [[home.rules]]
        path = ".x"
        mode = "private-rw"
        """
    )
    with HostReadonlyView(root, private) as view:
        with pytest.raises(HostAccessError) as error:
            view.lookup(".x")
        assert error.value.errno == errno.EACCES


def test_directory_listing_os_error_is_wrapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)

    def fail(_fd: int) -> list[str]:
        raise OSError(errno.EIO, "broken listing")

    monkeypatch.setattr(os, "listdir", fail)
    with HostReadonlyView(root, _profile()) as view, pytest.raises(HostAccessError) as error:
        view.listdir(".codex")
    assert error.value.errno == errno.EIO


def test_directory_listing_is_bounded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)
    monkeypatch.setattr(os, "listdir", lambda _fd: ["entry"] * 4097)
    with HostReadonlyView(root, _profile()) as view, pytest.raises(HostAccessError) as error:
        view.listdir(".codex")
    assert error.value.errno == errno.EOVERFLOW


def test_magic_link_is_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "home"
    (root / ".codex").mkdir(parents=True)
    os.symlink("/proc/self/environ", root / ".codex/config.toml")
    with HostReadonlyView(root, _profile()) as view, pytest.raises(HostAccessError):
        view.read(".codex/config.toml")
