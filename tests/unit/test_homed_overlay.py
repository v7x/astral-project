from __future__ import annotations

import errno
import json
import os
import random
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from astral_project.homed.overlay import (
    WHITEOUT_PREFIX,
    OverlayBackend,
    OverlayFeatures,
    OverlayStateError,
)
from astral_project.overlay import OverlayBackend as PublicOverlayBackend
from astral_project.profile import Profile


def test_public_overlay_api_is_exported() -> None:
    assert PublicOverlayBackend is OverlayBackend


def _profile() -> Profile:
    return Profile.from_toml(
        """
        version = 1
        id = "overlay-profile"
        name = "overlay"
        [[home.rules]]
        path = "cfg"
        scope = "subtree"
        mode = "overlay-rw"
        list = true
        [[home.rules]]
        path = "one"
        scope = "exact"
        mode = "overlay-rw"
        """
    )


def test_overlay_inode_cache_forget_is_bounded(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    upper = tmp_path / "upper"
    lower.mkdir()
    (lower / "a").write_text("lower", encoding="utf-8")
    with OverlayBackend(lower, upper) as backend:
        node = backend.lookup("a")
        assert backend.inode_count == 2
        backend.lookup("a")
        backend.forget(node.inode, 1)
        assert backend.node_path(node.inode) == "a"
        backend.forget(node.inode, 1)
        assert backend.inode_count == 1
        with pytest.raises(OverlayStateError):
            backend.node_path(node.inode)
        backend.forget(1, 1)
        backend.forget(999, 1)
        backend.forget(node.inode, -1)


def test_overlay_reads_lower_and_copies_regular_file_without_lower_mutation(
    tmp_path: Path,
) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "config").write_bytes(b"lower")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        assert backend.read("config") == b"lower"
        handle = backend.open("config", os.O_RDWR)
        backend.write(handle, b"upper", 0)
        backend.release(handle)
        assert backend.read("config") == b"upper"
    assert (lower / "config").read_bytes() == b"lower"
    assert (tmp_path / "upper" / "config").read_bytes() == b"upper"


def test_overlay_lower_update_visible_until_shadowed_and_merged_list(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "one").write_bytes(b"1")
    (lower / "directory").mkdir()
    (lower / "directory" / "lower").write_bytes(b"x")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        (lower / "one").write_bytes(b"updated")
        assert backend.read("one") == b"updated"
        backend.create("upper")
        assert backend.listdir() == ("directory", "one", "upper")
        assert backend.listdir("directory") == ("lower",)
        handle = backend.open("one", os.O_RDWR)
        try:
            assert backend.read("one") == b"updated"
        finally:
            backend.release(handle)


def test_overlay_whiteout_survives_restart_and_create_clears_it(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "gone").write_bytes(b"x")
    backend = OverlayBackend(lower, tmp_path / "upper")
    backend.unlink("gone")
    backend.close()
    assert (tmp_path / "upper" / f"{WHITEOUT_PREFIX}gone").exists()
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        with pytest.raises(OverlayStateError) as error:
            backend.lookup("gone")
        assert error.value.errno == errno.ENOENT
        backend.create("gone")
        assert backend.read("gone") == b""


def test_overlay_rename_lower_directory_preserves_children(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    (lower / "source" / "child").mkdir(parents=True)
    (lower / "source" / "child" / "value").write_bytes(b"value")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        backend.rename("source", "destination")
        assert backend.listdir("destination/child") == ("value",)
        assert backend.read("destination/child/value") == b"value"


@pytest.mark.parametrize("profile_id", ["../outside", "/absolute"])
def test_overlay_rejects_unsafe_profile_id_before_scoping(tmp_path: Path, profile_id: str) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    unsafe = object.__new__(Profile)
    object.__setattr__(unsafe, "profile_id", profile_id)
    with pytest.raises(ValueError, match="one path component"):
        OverlayBackend(lower, tmp_path / "upper", unsafe)
    assert not (tmp_path / "outside").exists()


def test_overlay_profile_scopes_upper_root_and_rejects_false_features(tmp_path: Path) -> None:
    profile = Profile.from_toml(
        """
        version = 1
        id = "one"
        name = "one"
        [[home.rules]]
        path = "file"
        mode = "overlay-rw"
        """
    )
    second = Profile.from_toml(
        """
        version = 1
        id = "two"
        name = "two"
        [[home.rules]]
        path = "file"
        mode = "overlay-rw"
        """
    )
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    with OverlayBackend(lower, upper, profile) as first:
        first.create("file")
        assert (upper / "one").is_dir()
    with OverlayBackend(lower, upper, second) as isolated:
        with pytest.raises(OverlayStateError) as error:
            isolated.lookup("file")
        assert error.value.errno == errno.ENOENT
    with pytest.raises(ValueError):
        OverlayBackend(lower, tmp_path / "unsupported", features=OverlayFeatures(mmap=True))
    with pytest.raises(ValueError):
        OverlayBackend(lower, tmp_path / "unsupported-locks", features=OverlayFeatures(locks=True))


def test_overlay_rename_lower_source_and_cross_rule_exdev(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "one").write_bytes(b"1")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        backend.rename("one", "renamed")
        assert backend.read("renamed") == b"1"
        with pytest.raises(OverlayStateError) as error:
            backend.lookup("one")
        assert error.value.errno == errno.ENOENT

    profile = _profile()
    (lower / "cfg").mkdir()
    (lower / "cfg" / "a").write_bytes(b"a")
    with OverlayBackend(lower, tmp_path / "upper2", profile) as backend:
        with pytest.raises(OverlayStateError) as error:
            backend.rename("cfg/a", "one")
        assert error.value.errno == errno.EXDEV


def test_overlay_rename_checks_merged_destination_types(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "file").write_bytes(b"file")
    (lower / "directory").mkdir()
    (lower / "directory" / "child").write_bytes(b"child")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        with pytest.raises(OverlayStateError) as error:
            backend.rename("file", "directory")
        assert error.value.errno == errno.EISDIR
        with pytest.raises(OverlayStateError) as error:
            backend.rename("directory", "file")
        assert error.value.errno == errno.ENOTDIR


def test_overlay_randomized_model_sequence_and_lower_immutability(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    original = {"a": b"a", "b": b"b"}
    for name, value in original.items():
        (lower / name).write_bytes(value)
    model = dict(original)
    names = ("a", "b", "c", "d", "e")
    rng = random.Random(31)
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        for _ in range(80):
            operation = rng.choice(("create", "unlink", "rename", "write"))
            name = rng.choice(names)
            if operation == "create":
                if name not in model:
                    backend.create(name)
                    model[name] = b""
            elif operation == "unlink":
                if name in model:
                    backend.unlink(name)
                    del model[name]
            elif operation == "write":
                if name in model:
                    value = bytes([rng.randrange(65, 91)])
                    backend.write(name, value, 0)
                    model[name] = value
            else:
                source = rng.choice(names)
                destination = rng.choice(names)
                if source in model and source != destination:
                    backend.rename(source, destination)
                    model[destination] = model.pop(source)
            assert backend.listdir() == tuple(sorted(model))
            for current, expected in model.items():
                assert backend.read(current) == expected
    assert {name: (lower / name).read_bytes() for name in original} == original


def test_overlay_sqlite_wal_and_incomplete_whiteout_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "recover").write_bytes(b"lower")
    upper = tmp_path / "upper"
    backend = OverlayBackend(lower, upper)
    assert (upper / ".aspr-overlay.sqlite3").exists()
    with backend._exclusive():
        database = backend._db
        assert database is not None
        mode = database.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"
        temp = ".aspr-overlay-tmp-orphan"
        backend._journal_begin("unlink", "recover", lower=True, temp=temp)
        (upper / temp).write_bytes(b"orphan")
        (lower / "whiteout-recover").write_bytes(b"lower")
        backend._journal_begin("whiteout", "whiteout-recover", lower=True)
        (lower / "rmdir-recover").mkdir()
        (upper / "rmdir-recover").mkdir()
        backend._journal_begin("rmdir", "rmdir-recover", lower=True)
        (upper / "unlink-recover").write_bytes(b"upper")
        backend._journal_begin("unlink", "unlink-recover", lower=False)
        backend._journal_begin("whiteout", "upper-only-whiteout", lower=False)
        backend._journal_begin("create", "create-recover", temp=".aspr-overlay-tmp-create-recover")
        (upper / ".aspr-overlay-tmp-create-recover").write_bytes(b"orphan")
        (lower / "rmdir-race").mkdir()
        (upper / "rmdir-race").mkdir()
        backend._journal_begin("rmdir", "rmdir-race", lower=True)
        (lower / "rename-source").write_bytes(b"lower-rename")
        (upper / "rename-source").write_bytes(b"rename")
        backend._journal_begin(
            "rename", "rename-source", destination="rename-dest", source_lower=True
        )
        (lower / "rename-done").write_bytes(b"lower-done")
        (upper / "rename-done-dest").write_bytes(b"done")
        backend._journal_begin(
            "rename", "rename-done", destination="rename-done-dest", source_lower=True
        )
        (upper / "rename-upper").write_bytes(b"upper")
        backend._journal_begin(
            "rename", "rename-upper", destination="rename-upper-dest", source_lower=False
        )
        (upper / "nested").mkdir()
        (upper / "nested/child").write_bytes(b"child")
        backend._journal_begin("copy-up-dir", "nested")
        backend._journal_begin("copy-up-dir", "nested/child")
        backend._journal_begin("create", "missing/created")
    backend.close()
    real_rmdir = os.rmdir

    def race_once(name: str, *, dir_fd: int | None = None) -> None:
        real_rmdir(name, dir_fd=dir_fd)
        if name == "rmdir-race":
            raise FileNotFoundError(errno.ENOENT, "rmdir raced recovery")

    monkeypatch.setattr(os, "rmdir", race_once)
    with OverlayBackend(lower, upper) as recovered:
        with pytest.raises(OverlayStateError) as error:
            recovered.lookup("recover")
        assert error.value.errno == errno.ENOENT
        assert not (upper / temp).exists()
        assert (upper / f"{WHITEOUT_PREFIX}recover").exists()
        assert (upper / f"{WHITEOUT_PREFIX}whiteout-recover").exists()
        assert (upper / f"{WHITEOUT_PREFIX}rmdir-recover").exists()
        assert not (upper / "unlink-recover").exists()
        assert not (upper / f"{WHITEOUT_PREFIX}upper-only-whiteout").exists()
        assert not (upper / "rmdir-race").exists()
        assert (upper / f"{WHITEOUT_PREFIX}rmdir-race").exists()
        assert (upper / "rename-dest").read_bytes() == b"rename"
        assert (upper / f"{WHITEOUT_PREFIX}rename-source").exists()
        assert (upper / "rename-done-dest").read_bytes() == b"done"
        assert (upper / f"{WHITEOUT_PREFIX}rename-done").exists()
        assert (upper / "rename-upper-dest").read_bytes() == b"upper"
        assert not (upper / f"{WHITEOUT_PREFIX}rename-upper").exists()
        assert not (upper / "nested").exists()
        with pytest.raises(OverlayStateError):
            recovered.lookup("whiteout-recover")
        with pytest.raises(OverlayStateError):
            recovered.lookup("rmdir-recover")


@pytest.mark.parametrize(
    ("operation", "phase"),
    [
        (operation, phase)
        for operation in ("whiteout", "rmdir", "rename", "copy-up", "create", "mkdir")
        for phase in ("begin", "commit")
    ],
)
def test_overlay_recovers_after_each_mutation_phase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str, phase: str
) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    if operation == "whiteout":
        (lower / "file").write_bytes(b"file")
    elif operation == "rmdir":
        (lower / "directory").mkdir()
    elif operation == "rename":
        (lower / "source").write_bytes(b"source")
    elif operation == "copy-up":
        (lower / "file").write_bytes(b"file")
    with OverlayBackend(lower, upper) as backend:
        if operation in {"rmdir", "rename"}:
            backend._copy_up("directory" if operation == "rmdir" else "source")
        original = getattr(backend, f"_journal_{phase}")

        def crash(*args: object, **kwargs: object) -> None:
            if phase == "begin":
                original(*args, **kwargs)
            raise RuntimeError("simulated daemon crash")

        monkeypatch.setattr(backend, f"_journal_{phase}", crash)
        with pytest.raises(RuntimeError):
            if operation == "whiteout":
                backend.unlink("file")
            elif operation == "rmdir":
                backend.rmdir("directory")
            elif operation == "rename":
                backend.rename("source", "destination")
            elif operation == "copy-up":
                backend.open("file", os.O_RDWR)
            elif operation == "create":
                backend.create("created")
            else:
                backend.mkdir("created-dir")
    with OverlayBackend(lower, upper) as recovered:
        if operation == "whiteout":
            with pytest.raises(OverlayStateError):
                recovered.lookup("file")
        elif operation == "rmdir":
            with pytest.raises(OverlayStateError):
                recovered.lookup("directory")
        elif operation == "rename":
            assert recovered.read("destination") == b"source"
            with pytest.raises(OverlayStateError):
                recovered.lookup("source")
        elif operation == "copy-up":
            assert recovered.read("file") == b"file"
        elif operation == "create":
            with pytest.raises(OverlayStateError):
                recovered.lookup("created")
        else:
            with pytest.raises(OverlayStateError):
                recovered.lookup("created-dir")


def test_overlay_rejects_unknown_journal_records(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    with OverlayBackend(lower, upper) as backend:
        database = backend._db
        assert database is not None
        database.execute(
            "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
            ("mystery", "unlink", "bad", "{}"),
        )
    with pytest.raises(OverlayStateError) as error:
        OverlayBackend(lower, upper)
    assert error.value.errno == errno.EIO


def test_overlay_rejects_malformed_rename_journals(tmp_path: Path) -> None:
    cases = ("mismatch", "row-path", "missing-destination", "invalid-destination")
    for case in cases:
        lower = tmp_path / f"lower-{case}"
        lower.mkdir()
        upper = tmp_path / f"upper-{case}"
        with OverlayBackend(lower, upper) as backend:
            database = backend._db
            assert database is not None
            if case == "mismatch":
                kind = "unlink"
                payload = {"phase": "begin", "kind": "whiteout", "path": "bad"}
            elif case == "row-path":
                kind = "unlink"
                payload = {"phase": "begin", "kind": "unlink", "path": "payload"}
            elif case == "missing-destination":
                kind = "rename"
                (upper / "source").write_bytes(b"source")
                payload = {"phase": "begin", "kind": "rename", "path": "source"}
            elif case == "invalid-destination":
                kind = "rename"
                (upper / "source").write_bytes(b"source")
                payload = {
                    "phase": "begin",
                    "kind": "rename",
                    "path": "source",
                    "destination": "../outside",
                }
            else:
                raise AssertionError(f"unhandled journal case: {case}")
            database.execute(
                "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                (
                    "begin",
                    kind,
                    "row" if case == "row-path" else payload["path"],
                    json.dumps(payload),
                ),
            )
        with pytest.raises(OverlayStateError) as error:
            OverlayBackend(lower, upper)
        assert error.value.errno == errno.EIO


def test_overlay_rejects_stray_or_malformed_commit_records(tmp_path: Path) -> None:
    records: tuple[object, ...] = (
        {},
        {"phase": "commit", "kind": "unlink", "path": "bad"},
        "not-json",
    )
    for index, payload in enumerate(records):
        lower = tmp_path / f"lower-{index}"
        lower.mkdir()
        upper = tmp_path / f"upper-{index}"
        with OverlayBackend(lower, upper) as backend:
            database = backend._db
            assert database is not None
            database.execute(
                "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                (
                    "commit",
                    "unlink",
                    "bad",
                    payload if isinstance(payload, str) else json.dumps(payload),
                ),
            )
        with pytest.raises(OverlayStateError) as error:
            OverlayBackend(lower, upper)
        assert error.value.errno == errno.EIO


def test_overlay_rejects_commit_mismatches_and_rename_conflicts(tmp_path: Path) -> None:
    cases = ("kind", "path", "destination", "unmatched", "type", "nonempty")
    for case in cases:
        lower = tmp_path / f"lower-{case}"
        lower.mkdir()
        upper = tmp_path / f"upper-{case}"
        with OverlayBackend(lower, upper) as backend:
            database = backend._db
            assert database is not None
            if case == "kind":
                database.execute(
                    "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                    (
                        "commit",
                        "unlink",
                        "bad",
                        json.dumps({"phase": "commit", "kind": "whiteout", "path": "bad"}),
                    ),
                )
            elif case == "path":
                database.execute(
                    "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                    (
                        "commit",
                        "unlink",
                        "../bad",
                        json.dumps({"phase": "commit", "kind": "unlink", "path": "../bad"}),
                    ),
                )
            elif case == "destination":
                database.execute(
                    "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                    (
                        "begin",
                        "rename",
                        "source",
                        json.dumps(
                            {
                                "phase": "begin",
                                "kind": "rename",
                                "path": "source",
                                "destination": "one",
                            }
                        ),
                    ),
                )
                database.execute(
                    "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                    (
                        "commit",
                        "rename",
                        "source",
                        json.dumps(
                            {
                                "phase": "commit",
                                "kind": "rename",
                                "path": "source",
                                "destination": "two",
                            }
                        ),
                    ),
                )
            elif case == "unmatched":
                begin = {"phase": "begin", "kind": "unlink", "path": "prior"}
                commit = {"phase": "commit", "kind": "unlink", "path": "other"}
                database.execute(
                    "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                    ("begin", "unlink", "prior", json.dumps(begin)),
                )
                database.execute(
                    "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                    ("commit", "unlink", "other", json.dumps(commit)),
                )
            else:
                (upper / "source").mkdir()
                if case == "type":
                    (upper / "destination").write_bytes(b"file")
                else:
                    (upper / "destination").mkdir()
                    (upper / "destination/child").write_bytes(b"child")
                database.execute(
                    "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
                    (
                        "begin",
                        "rename",
                        "source",
                        json.dumps(
                            {
                                "phase": "begin",
                                "kind": "rename",
                                "path": "source",
                                "destination": "destination",
                            }
                        ),
                    ),
                )
        with pytest.raises(OverlayStateError) as error:
            OverlayBackend(lower, upper)
        assert error.value.errno == errno.EIO


def test_overlay_failed_remove_aborts_journal(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    with OverlayBackend(lower, upper) as backend:
        backend.mkdir("directory")
        backend.create("directory/file")
        with pytest.raises(OverlayStateError) as error:
            backend.rmdir("directory")
        assert error.value.errno == errno.ENOTEMPTY
    with OverlayBackend(lower, upper) as recovered:
        assert recovered.read("directory/file") == b""


def test_overlay_rename_recovery_replaces_existing_upper_destination(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "source").write_bytes(b"source")
    upper = tmp_path / "upper"
    with OverlayBackend(lower, upper) as backend:
        backend._copy_up("source")
        backend.create("destination")
        original = backend._journal_begin

        def crash(kind: str, path: str, **extra: str | bool) -> None:
            original(kind, path, **extra)
            raise RuntimeError("crash before rename")

        monkeypatch.setattr(backend, "_journal_begin", crash)
        with pytest.raises(RuntimeError):
            backend.rename("source", "destination")
    with OverlayBackend(lower, upper) as recovered:
        assert recovered.read("destination") == b"source"
        with pytest.raises(OverlayStateError):
            recovered.lookup("source")


def test_overlay_failed_rename_does_not_poison_recovery(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    with OverlayBackend(lower, upper) as backend:
        backend.mkdir("source")
        backend.mkdir("destination")
        backend.create("destination/child")
        with pytest.raises(OverlayStateError) as error:
            backend.rename("source", "destination")
        assert error.value.errno == errno.ENOTEMPTY
        backend.mkdir("source-empty")
        backend.mkdir("destination-empty")
        backend.rename("source-empty", "destination-empty")
    with OverlayBackend(lower, upper) as recovered:
        assert recovered.read("destination/child") == b""


def test_overlay_nested_mkdir_commit_failure_recovers_cleanly(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    with OverlayBackend(lower, upper) as backend:
        backend.mkdir("a")
        original = backend._journal_commit

        def fail(kind: str, path: str, **extra: str | bool) -> None:
            if kind == "mkdir" and path == "a/b":
                raise OverlayStateError(errno.EINVAL, "simulated commit failure")
            original(kind, path, **extra)

        monkeypatch.setattr(backend, "_journal_commit", fail)
        with pytest.raises(OverlayStateError):
            backend.mkdir("a/b")
    with OverlayBackend(lower, upper) as recovered:
        assert recovered.lookup("a").is_directory
        assert recovered.listdir("a") == ()
        with pytest.raises(OverlayStateError):
            recovered.lookup("a/b")


def test_overlay_nested_mkdir_cleanup_failure_is_recovered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    backend = OverlayBackend(lower, upper)
    try:
        backend.mkdir("a")
        original_rmdir = os.rmdir
        fail_cleanup = True

        def rmdir(name: str, *, dir_fd: int | None = None) -> None:
            if fail_cleanup and name == "b":
                raise OSError(errno.EIO, "simulated cleanup failure")
            original_rmdir(name, dir_fd=dir_fd)

        monkeypatch.setattr(os, "rmdir", rmdir)
        original_commit = backend._journal_commit

        def fail(kind: str, path: str, **extra: str | bool) -> None:
            if kind == "mkdir" and path == "a/b":
                raise OverlayStateError(errno.EINVAL, "simulated commit failure")
            original_commit(kind, path, **extra)

        monkeypatch.setattr(backend, "_journal_commit", fail)
        with pytest.raises(OverlayStateError):
            backend.mkdir("a/b")
        fail_cleanup = False
    finally:
        backend.close()
    with OverlayBackend(lower, upper) as recovered, pytest.raises(OverlayStateError):
        recovered.lookup("a/b")


def test_overlay_mkdir_commit_record_is_not_rolled_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    with OverlayBackend(lower, upper) as backend:
        original = backend._journal_commit

        def fail_after_commit(kind: str, path: str, **extra: str | bool) -> None:
            original(kind, path, **extra)
            if kind == "mkdir":
                raise OverlayStateError(errno.EINVAL, "reported after durable commit")

        monkeypatch.setattr(backend, "_journal_commit", fail_after_commit)
        with pytest.raises(OverlayStateError):
            backend.mkdir("created")
    with OverlayBackend(lower, upper) as recovered:
        assert recovered.lookup("created").is_directory


def test_overlay_commit_lookup_checks_all_matching_records(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        backend._journal_begin("rename", "source", destination="wrong")
        backend._journal_commit("rename", "source", destination="wrong")
        backend._journal_begin("rename", "source", destination="right")
        backend._journal_commit("rename", "source", destination="right")
        assert backend._journal_has_commit("rename", "source", destination="right")


def test_overlay_rename_commit_failure_records_abort_for_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    with OverlayBackend(lower, upper) as backend:
        backend.create("source")
        destination = backend.create("destination")
        handle = backend.open(destination.path, os.O_RDWR)
        backend.write(handle, b"destination")
        backend.release(handle)
        original = backend._journal_commit

        def fail(kind: str, path: str, **extra: str | bool) -> None:
            if kind == "rename":
                raise OverlayStateError(errno.EINVAL, "simulated commit failure")
            original(kind, path, **extra)

        monkeypatch.setattr(backend, "_journal_commit", fail)
        with pytest.raises(OverlayStateError):
            backend.rename("source", "destination")
    with OverlayBackend(lower, upper) as recovered:
        assert recovered.read("destination") == b""
        with pytest.raises(OverlayStateError):
            recovered.lookup("source")


def test_overlay_rename_recovery_replaces_empty_upper_directory(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    with OverlayBackend(lower, upper) as backend:
        (upper / "source").mkdir()
        (upper / "destination").mkdir()
        backend._journal_begin("rename", "source", destination="destination", source_lower=False)
    with OverlayBackend(lower, upper) as recovered:
        assert recovered.lookup("destination").is_directory
        with pytest.raises(OverlayStateError):
            recovered.lookup("source")


def test_overlay_metadata_and_common_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lower = tmp_path / "lower"
    (lower / "directory").mkdir(parents=True)
    (lower / "directory" / "lower-file").write_bytes(b"lower")
    (lower / "file").write_bytes(b"file")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        assert backend.root_fd >= 0
        assert backend.lower_root_fd >= 0
        assert backend.stat("file").size == 4
        with pytest.raises(OverlayStateError) as error:
            backend.stat("missing")
        assert error.value.errno == errno.ENOENT
        assert backend.lookup(".").is_directory
        assert backend.node_path(backend.lookup("file").inode) == "file"
        with pytest.raises(OverlayStateError):
            backend.node_path(999)
        backend.mkdir("newdir")
        backend.mkdir("newdir/nested")
        assert backend.listdir("newdir") == ("nested",)
        monkeypatch.setattr("astral_project.homed.overlay._MAX_DIRECTORY_ENTRIES", 0)
        with pytest.raises(OverlayStateError) as error:
            backend.listdir("newdir")
        assert error.value.errno == errno.EOVERFLOW
        monkeypatch.setattr("astral_project.homed.overlay._MAX_DIRECTORY_ENTRIES", 4096)
        backend.create("newdir/new")
        handle = backend.open("newdir/new", os.O_RDWR)
        assert backend.write(handle, b"abc") == 3
        backend.truncate(handle, 2)
        backend.fsync(handle)
        backend.chmod(handle, 0o4777)
        backend.release(handle)
        assert backend.read("newdir/new") == b"ab"
        backend.rename("newdir/new", "newdir/renamed")
        backend.unlink("newdir/renamed")
        backend.rmdir("newdir/nested")
        backend.rmdir("newdir")
        with pytest.raises(OverlayStateError) as error:
            backend.open("directory", os.O_RDONLY)
        assert error.value.errno == errno.EISDIR
        with pytest.raises(OverlayStateError) as error:
            backend.open("directory", os.O_RDWR | os.O_TRUNC)
        assert error.value.errno == errno.EISDIR
        with pytest.raises(OverlayStateError) as error:
            backend.open("missing", os.O_RDONLY)
        assert error.value.errno == errno.ENOENT
        with pytest.raises(OverlayStateError) as error:
            backend.open("missing", os.O_RDWR)
        assert error.value.errno == errno.ENOENT
        created = backend.open("missing", os.O_RDONLY | os.O_CREAT)
        backend.release(created)
        backend.release(99999)
        created_rw = backend.open("missing-rw", os.O_RDWR | os.O_CREAT)
        with pytest.raises(TypeError):
            backend.write(created_rw, "bad")  # type: ignore[arg-type]
        with pytest.raises(OverlayStateError):
            backend.read(created_rw, -1)
        backend.release(created_rw)
        backend.unlink("missing")
        backend.unlink("missing-rw")
        lower_handle = backend.open("directory/lower-file", os.O_RDWR | os.O_TRUNC)
        backend.release(lower_handle)
        assert backend.read("directory/lower-file") == b""
        with pytest.raises(OverlayStateError) as error:
            backend.open("file", os.O_CREAT | os.O_EXCL)
        assert error.value.errno == errno.EEXIST
        with pytest.raises(OverlayStateError) as error:
            backend.create("file")
        assert error.value.errno == errno.EEXIST
        with pytest.raises(OverlayStateError) as error:
            backend.mkdir("directory")
        assert error.value.errno == errno.EEXIST
        with pytest.raises(OverlayStateError) as error:
            backend.unlink("missing")
        assert error.value.errno == errno.ENOENT
        with pytest.raises(OverlayStateError) as error:
            backend.unlink("directory")
        assert error.value.errno == errno.EISDIR
        with pytest.raises(OverlayStateError) as error:
            backend.unlink("file", directory=True)
        assert error.value.errno == errno.ENOTDIR
        backend.rename("file", "file")


def test_overlay_operation_edges_and_stable_errors(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    (lower / "directory").mkdir(parents=True)
    (lower / "directory" / "file").write_bytes(b"x")
    (lower / "file").write_bytes(b"x")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        lower_handle = backend.open("file")
        original_mode = (lower / "file").stat().st_mode
        with pytest.raises(OverlayStateError) as error:
            backend.chmod(lower_handle, 0o600)
        assert error.value.errno == errno.EACCES
        assert (lower / "file").stat().st_mode == original_mode
        backend.release(lower_handle)
        with pytest.raises(OverlayStateError) as error:
            backend.listdir("file")
        assert error.value.errno == errno.ENOTDIR
        with pytest.raises(OverlayStateError) as error:
            backend.listdir("missing")
        assert error.value.errno == errno.ENOENT
        handle = backend.open("file", os.O_RDWR | os.O_APPEND)
        assert backend.write(handle, b"y") == 1
        assert backend.write(handle, b"z", 0) == 1
        backend.truncate(handle, 1)
        backend.truncate("file", 1)
        backend.fsync(handle)
        backend.chmod(handle, 0o4777)
        backend.release(handle)
        backend.fsync("file")
        backend.chmod("file", 0o4777)
        with pytest.raises(OverlayStateError) as error:
            backend.chmod("missing", 0o600)
        assert error.value.errno == errno.ENOENT
        with pytest.raises(OverlayStateError) as error:
            backend.read(99999)
        assert error.value.errno == errno.EBADF
        with pytest.raises(OverlayStateError) as error:
            backend.write("file", b"z", -1)
        assert error.value.errno == errno.EINVAL
        with pytest.raises(OverlayStateError) as error:
            backend.truncate("file", -1)
        assert error.value.errno == errno.EINVAL
        with pytest.raises(OverlayStateError) as error:
            backend.link("file", "link")
        assert error.value.errno == errno.EOPNOTSUPP
        with pytest.raises(OverlayStateError) as error:
            backend.symlink("file", "link")
        assert error.value.errno == errno.EOPNOTSUPP
        with pytest.raises(OverlayStateError) as error:
            backend.mknod("device", stat.S_IFCHR)
        assert error.value.errno == errno.EPERM
        with pytest.raises(OverlayStateError) as error:
            backend.setxattr("file", b"n", b"v")
        assert error.value.errno == errno.ENOTSUP
        with pytest.raises(OverlayStateError) as error:
            backend.mmap()
        assert error.value.errno == errno.ENOTSUP
        with pytest.raises(OverlayStateError) as error:
            backend.lock()
        assert error.value.errno == errno.ENOTSUP
        backend.unlink("directory", directory=True)
        with pytest.raises(OverlayStateError) as error:
            backend.lookup("directory")
        assert error.value.errno == errno.ENOENT


def test_overlay_sanitizes_setid_and_rejects_upper_hardlinks(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    upper.mkdir(mode=0o700)
    (upper / "setid").write_bytes(b"x")
    os.chmod(upper / "setid", 0o4700)
    (upper / "setid-dir").mkdir()
    os.chmod(upper / "setid-dir", 0o2700)
    with OverlayBackend(lower, upper) as backend:
        assert backend.lookup("setid").mode == stat.S_IFREG | 0o700
        assert backend.lookup("setid-dir").mode == stat.S_IFDIR | 0o700
        assert stat.S_IMODE(os.stat(upper / "setid-dir").st_mode) == 0o700
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    os.link(outside, upper / "alias")
    with pytest.raises(OSError) as error:
        OverlayBackend(lower, upper)
    assert error.value.errno == errno.EACCES


def test_overlay_rejects_overlapping_roots_and_filters_profile_listing(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "allowed").write_bytes(b"allowed")
    (lower / "secret").write_bytes(b"secret")
    upper = lower / "upper"
    with pytest.raises(OSError) as error:
        OverlayBackend(lower, upper)
    assert error.value.errno == errno.EINVAL
    same_root = tmp_path / "same-root"
    same_root.mkdir(mode=0o700)
    with pytest.raises(OSError) as error:
        OverlayBackend(same_root, same_root)
    assert error.value.errno == errno.EINVAL
    profile = Profile.from_toml(
        """
        version = 1
        id = "filter"
        name = "filter"
        [[home.rules]]
        path = "allowed"
        mode = "overlay-rw"
        """
    )
    with OverlayBackend(lower, tmp_path / "separate-upper", profile) as backend:
        assert backend.listdir() == ("allowed",)


def test_overlay_recovery_helpers_clean_nested_temporary_state(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    upper = tmp_path / "upper"
    upper.mkdir(mode=0o700)
    nested = upper / "nested"
    nested.mkdir(mode=0o700)
    temporary = nested / ".aspr-overlay-tmp-orphan"
    temporary.write_bytes(b"orphan")
    with OverlayBackend(lower, upper) as backend:
        assert not temporary.exists()
        backend._remove_upper_tree("missing")
        backend._remove_orphan_temps(backend._upper)


def test_overlay_directory_copy_up_rolls_back_on_child_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lower = tmp_path / "lower"
    (lower / "directory").mkdir(parents=True)
    (lower / "directory" / "child").write_bytes(b"child")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        original_pread = os.pread
        monkeypatch.setattr(
            os,
            "pread",
            lambda *_args: (_ for _ in ()).throw(OSError(errno.EIO, "copy failure")),
        )
        with pytest.raises(OverlayStateError) as error:
            backend._copy_up("directory")
        assert error.value.errno == errno.EIO
        assert not (tmp_path / "upper" / "directory").exists()
        monkeypatch.setattr(os, "pread", original_pread)


def test_overlay_rejects_unsafe_metadata_files(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    upper = tmp_path / "upper"
    upper.mkdir(mode=0o700)
    os.symlink(outside, upper / ".aspr-overlay.sqlite3")
    with pytest.raises(OSError) as error:
        OverlayBackend(lower, upper)
    assert error.value.errno == errno.EACCES
    (upper / ".aspr-overlay.sqlite3").unlink()
    os.link(outside, upper / ".aspr-overlay.sqlite3")
    with pytest.raises(OSError) as error:
        OverlayBackend(lower, upper)
    assert error.value.errno == errno.EACCES


def test_overlay_rejects_invalid_configuration_and_metadata_paths(tmp_path: Path) -> None:
    lower_file = tmp_path / "lower-file"
    lower_file.write_bytes(b"x")
    with pytest.raises(OSError) as error:
        OverlayBackend(lower_file, tmp_path / "upper")
    assert error.value.errno == errno.ENOTDIR
    lower = tmp_path / "lower"
    lower.mkdir()
    upper_link = tmp_path / "upper-link"
    os.symlink(tmp_path, upper_link)
    with pytest.raises(OSError) as error:
        OverlayBackend(lower, upper_link)
    assert error.value.errno == errno.EACCES
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        for path in (".wh.secret", ".aspr-overlay-lock", ".aspr-overlay.sqlite3"):
            with pytest.raises(OverlayStateError) as path_error:
                backend.lookup(path)
            assert path_error.value.errno == errno.EINVAL
        with pytest.raises(OverlayStateError) as error:
            backend.mkdir("missing/child")
        assert error.value.errno == errno.ENOENT
        with pytest.raises(OverlayStateError) as error:
            backend.rename("missing", "new")
        assert error.value.errno == errno.ENOENT


def test_overlay_internal_boundaries_reject_unsafe_nodes(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "regular").write_bytes(b"x")
    os.mkfifo(lower / "lower-fifo")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        os.mkfifo(tmp_path / "upper" / "upper-fifo")
        with pytest.raises(OverlayStateError) as error:
            backend.lookup("lower-fifo")
        assert error.value.errno == errno.EACCES
        with pytest.raises(OverlayStateError) as error:
            backend.lookup("upper-fifo")
        assert error.value.errno == errno.EACCES
        with pytest.raises(OverlayStateError) as error:
            backend.open("lower-fifo")
        assert error.value.errno == errno.EISDIR
        with pytest.raises(OverlayStateError) as error:
            backend.open("upper-fifo")
        assert error.value.errno == errno.EACCES
        with pytest.raises(OverlayStateError) as error:
            backend._upper_parent(".")
        assert error.value.errno == errno.EBUSY
        with pytest.raises(OverlayStateError) as error:
            backend._open_lower("missing", os.O_RDONLY)
        assert error.value.errno == errno.ENOENT
        backend._copy_up("regular")
        backend._copy_up("regular")
        backend.unlink("regular")
        with pytest.raises(OverlayStateError) as error:
            backend._copy_up("regular")
        assert error.value.errno == errno.ENOENT
        backend._clear_whiteout(".")
        backend._clear_whiteout("missing/child")
        with backend._exclusive():
            parent = os.dup(backend._upper)
            try:
                with pytest.raises(OverlayStateError):
                    backend._journaled_mkdir(parent, "upper-fifo", 0o700)
                with pytest.raises(OverlayStateError):
                    backend._journaled_remove(parent, "missing", False, "missing", False)
            finally:
                os.close(parent)
        mapped = backend._database_error(sqlite3.OperationalError("database is locked"))
        assert mapped.errno == errno.EAGAIN
        assert (
            backend._database_error(sqlite3.OperationalError("database full")).errno == errno.ENOSPC
        )
        assert backend._database_error(sqlite3.OperationalError("other")).errno == errno.EIO
        os.unlink(tmp_path / "upper" / "upper-fifo")
        database = backend._db
        assert database is not None
        database.execute(
            "INSERT INTO mutations (phase, kind, path, payload) VALUES (?, ?, ?, ?)",
            ("begin", "whiteout", "recover", "not-json"),
        )
        backend.close()
        backend.close()
        with pytest.raises(OverlayStateError) as error:
            backend.lookup("regular")
        assert error.value.errno == errno.ESTALE
    with pytest.raises(OverlayStateError) as error:
        OverlayBackend(lower, tmp_path / "upper")
    assert error.value.errno == errno.EIO


def test_overlay_rejects_unowned_descriptors_and_lower_symlinks(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "safe").write_bytes(b"safe")
    outside = tmp_path / "outside"
    outside.write_bytes(b"outside")
    os.symlink(outside, lower / "escape")
    with OverlayBackend(lower, tmp_path / "upper") as backend:
        descriptor = os.open(outside, os.O_RDONLY)
        try:
            with pytest.raises(OverlayStateError) as error:
                backend.read(descriptor)
            assert error.value.errno == errno.EBADF
        finally:
            os.close(descriptor)
        with pytest.raises(OverlayStateError) as error:
            backend.lookup("escape")
        assert error.value.errno == errno.EACCES


def test_overlay_copy_up_concurrent_and_unsupported_features(tmp_path: Path) -> None:
    lower = tmp_path / "lower"
    lower.mkdir()
    (lower / "same").write_bytes(b"payload")
    with OverlayBackend(lower, tmp_path / "upper") as backend:

        def copy() -> bytes:
            handle = backend.open("same", os.O_RDWR)
            try:
                return backend.read(handle)
            finally:
                backend.release(handle)

        with ThreadPoolExecutor(max_workers=8) as pool:
            assert list(pool.map(lambda _: copy(), range(16))) == [b"payload"] * 16
        assert backend.supports_mmap is False
        assert backend.supports_locks is False
        with pytest.raises(OverlayStateError) as error:
            backend.mmap()
        assert error.value.errno == errno.ENOTSUP
        with pytest.raises(OverlayStateError) as error:
            backend.link("same", "link")
        assert error.value.errno == errno.EOPNOTSUPP
