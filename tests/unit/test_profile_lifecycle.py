from __future__ import annotations

import os
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from io import StringIO
from pathlib import Path
from typing import cast

import pytest

from astral_project import cli
from astral_project.homed.mediation import (
    MediationDecision,
    PendingRequest,
    UnknownPathMediator,
)
from astral_project.learner import LearnerError, ProfileLearner, learner_environment
from astral_project.profile import (
    ApprovalProvenance,
    CredentialRule,
    Operation,
    Profile,
    ProfileError,
    Rule,
    RuleMode,
    RuleScope,
    Sensitivity,
    SocketRule,
    WarningLevel,
)
from astral_project.profile_lifecycle import ProfileLifecycleError, ProfileStore


def _rule(path: str = "config.toml") -> Rule:
    return Rule(path, RuleScope.EXACT, RuleMode.HOST_RO)


def test_profile_store_lifecycle_round_trip_and_archive(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "config")
    created = store.create("agents-default", name="Agents")
    assert created.revision == 1
    provenance = ApprovalProvenance("trusted-ui", "session-1", "digest-1", 10)
    learned = store.commit_learning("agents-default", (_rule(),), provenance=provenance)
    assert learned.revision == 2
    assert store.load("agents-default").provenance == (provenance,)
    assert store.seal("agents-default").sealed
    assert store.unseal("agents-default").sealed is False
    assert store.list()[0].profile_id == "agents-default"

    exported = tmp_path / "export.toml"
    store.export("agents-default", exported)
    imported_store = ProfileStore(tmp_path / "other-config")
    imported = imported_store.import_profile(exported)
    assert imported == store.load("agents-default")
    with pytest.raises(ProfileLifecycleError, match="must be absolute"):
        ProfileStore(tmp_path / "relative-config").import_profile(Path("export.toml"))
    symlink = tmp_path / "export-link.toml"
    symlink.symlink_to(exported)
    with pytest.raises(ProfileLifecycleError, match="must not be a symlink"):
        ProfileStore(tmp_path / "symlink-config").import_profile(symlink)
    with pytest.raises(ProfileLifecycleError, match="import is invalid"):
        ProfileStore(tmp_path / "missing-config").import_profile(tmp_path / "missing.toml")
    target_directory = tmp_path / "target-directory"
    target_directory.mkdir()
    ancestor = tmp_path / "linked-directory"
    ancestor.symlink_to(target_directory, target_is_directory=True)
    with pytest.raises(ProfileLifecycleError, match="must not be a symlink"):
        ProfileStore(tmp_path / "ancestor-config").import_profile(ancestor / "export.toml")
    candidate = tmp_path / "candidate.toml"
    candidate.write_text(
        store.review("agents-default").replace('name = "Agents"', 'name = "Changed"')
    )
    assert 'name = "Changed"' in store.diff("agents-default", candidate)
    archived = store.archive_profile("agents-default")
    assert archived.exists()
    with pytest.raises(ProfileLifecycleError):
        store.load("agents-default")


def test_profile_store_edit_is_safe_and_failed_edit_preserves_revision(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "config")
    store.create("p")

    def edit_file(command: list[str], *, check: bool) -> subprocess.CompletedProcess[bytes]:
        Path(command[-1]).write_text(
            Path(command[-1]).read_text().replace('name = "p"', 'name = "edited"')
        )
        return subprocess.CompletedProcess(command, 0)

    edited = store.edit("p", editor="true", run=edit_file)
    assert edited.name == "edited"
    assert edited.revision == 2

    def fail_editor(_command: list[str], *, check: bool) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 3)

    with pytest.raises(ProfileLifecycleError):
        store.edit("p", editor="false", run=fail_editor)
    assert store.load("p").name == "edited"
    with pytest.raises(ProfileLifecycleError):
        store.edit("p", editor=" ")


def test_profile_resource_fields_round_trip() -> None:
    profile = Profile(
        1,
        "p",
        "p",
        sockets=(SocketRule("/run/example.sock", Sensitivity.OTHER, WarningLevel.INFO),),
        credentials=(CredentialRule(".config/token"),),
        environment_allow=("LANG", "PATH"),
        environment_unset=("TERM",),
    )
    restored = Profile.from_toml(profile.to_toml())
    assert restored.sockets == profile.sockets
    assert restored.credentials == profile.credentials
    assert restored.environment_allow == profile.environment_allow
    assert restored.environment_unset == profile.environment_unset


def test_control_characters_round_trip_through_lifecycle(tmp_path: Path) -> None:
    controls = '\\"' + "".join(chr(codepoint) for codepoint in range(0x20)) + "\x7f\x80\x9f"
    path_controls = controls.replace("\x00", "").replace("\\", "").replace('"', "")
    profile = Profile(
        1,
        "p",
        "name " + controls,
        rules=(Rule("rule" + path_controls, RuleScope.EXACT, RuleMode.HOST_RO),),
        provenance=(
            ApprovalProvenance(
                "source " + controls,
                "session " + controls,
                "digest " + controls,
                0,
            ),
        ),
        sockets=(SocketRule("/run/socket" + path_controls),),
        credentials=(CredentialRule(".credential" + path_controls),),
        environment_allow=("ALLOW" + path_controls,),
        environment_unset=("UNSET" + path_controls,),
    )
    serialized = profile.to_toml()
    assert 'name = "name \\\\\\"\\u0000\\u0001' in serialized
    assert "\\u007F\\u0080\\u009F" in serialized
    assert Profile.from_toml(serialized) == profile

    store = ProfileStore(tmp_path / "config")
    store.create("p")
    store.save(profile, expected_revision=1)
    reviewed = store.review("p")
    assert Profile.from_toml(reviewed) == profile
    exported = tmp_path / "export.toml"
    store.export("p", exported)
    imported = ProfileStore(tmp_path / "imported").import_profile(exported)
    assert imported == profile


def test_profile_parser_rejects_invalid_metadata_shapes() -> None:
    with pytest.raises(ProfileError, match="approval provenance"):
        ApprovalProvenance("", "s", "d", 0)
    with pytest.raises(ProfileError, match="approval provenance"):
        ApprovalProvenance("source", "session", "digest", -1)
    with pytest.raises(ProfileError, match="credential access"):
        CredentialRule("token", WarningLevel.INFO)
    with pytest.raises(ProfileError, match="socket path"):
        SocketRule("relative")
    with pytest.raises(ProfileError, match="revision"):
        Profile(1, "p", "p", revision=0)
    invalid_sources = (
        'version = 1\nid = "p"\nname = "p"\nprovenance = "bad"',
        'version = 1\nid = "p"\nname = "p"\nprovenance = [{}]',
        'version = 1\nid = "p"\nname = "p"\nsockets = "bad"',
        'version = 1\nid = "p"\nname = "p"\nsockets = [{}]',
        'version = 1\nid = "p"\nname = "p"\ncredentials = "bad"',
        'version = 1\nid = "p"\nname = "p"\ncredentials = [{}]',
        'version = 1\nid = "p"\nname = "p"\n[environment]\nother = []',
        'version = 1\nid = "p"\nname = "p"\n[home]\nother = []',
    )
    for source in invalid_sources:
        with pytest.raises(ProfileError):
            Profile.from_toml(source)
    invalid_metadata_sources: tuple[str, ...] = (
        'version = 1\nid = "p"\nname = "p"\n'
        'provenance = [{source = "", session_id = "s", request_digest = "d", decided_at = 1}]',
        'version = 1\nid = "p"\nname = "p"\n'
        'provenance = [{source = "source", session_id = "session", '
        'request_digest = "digest", decided_at = -1}]',
        'version = 1\nid = "p"\nname = "p"\nsockets = [{future = true}]',
        'version = 1\nid = "p"\nname = "p"\ncredentials = [{future = true}]',
        'version = 1\nid = "p"\nname = "p"\n[environment]\nallow = [1]',
        'version = 1\nid = "p"\nname = "p"\nrevision = 0',
    )
    for source in invalid_metadata_sources:
        with pytest.raises(ProfileError):
            Profile.from_toml(source)
    with pytest.raises(ProfileError):
        Profile.from_toml('version = 1\nid = "p"\nname = "p"\n[environment]\nallow = ["A", "A"]')


def test_profile_lock_rejects_unsafe_permissions(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "config")
    profile = store.create("p")
    store.save(profile)
    os.chmod(store.profiles / ".p.lock", 0o640)
    with pytest.raises(ProfileLifecycleError, match="transaction lock is unsafe"):
        store.save(profile)


def test_profile_learning_transactions_serialize(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "config")
    store.create("p")
    barrier = threading.Barrier(3)
    errors: list[BaseException] = []

    def commit(index: int) -> None:
        try:
            barrier.wait(timeout=5)
            store.commit_learning(
                "p",
                (_rule(f"learned-{index}"),),
                provenance=ApprovalProvenance(
                    "test", f"session-{index}", f"digest-{index}", index + 1
                ),
            )
        except BaseException as error:
            errors.append(error)

    threads = [threading.Thread(target=commit, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    barrier.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=5)
    assert errors == []
    profile = store.load("p")
    assert {rule.path for rule in profile.rules} == {"learned-0", "learned-1"}
    assert {entry.session_id for entry in profile.provenance} == {"session-0", "session-1"}
    assert profile.revision == 3


def test_profile_parser_rejects_unknown_fields_and_future_versions() -> None:
    with pytest.raises(ProfileError, match="unsupported profile fields"):
        Profile.from_toml('version = 1\nid = "p"\nname = "p"\nfuture = true')
    with pytest.raises(ProfileError, match="unsupported profile version"):
        Profile.from_toml('version = 2\nid = "p"\nname = "p"')
    with pytest.raises(ProfileError, match="unsupported rule fields"):
        Profile.from_toml(
            'version = 1\nid = "p"\nname = "p"\n[[home.rules]]\n'
            'path = "x"\nmode = "host-ro"\nfuture = true'
        )


def test_profile_store_rejects_conflicts_and_invalid_imports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ProfileStore(tmp_path / "config")
    store.create("p")
    mismatch_store = ProfileStore(tmp_path / "mismatch")
    mismatch_store.create("p")
    mismatch_store.path("p").write_bytes(Profile(1, "q", "q").to_toml().encode())
    with pytest.raises(ProfileLifecycleError, match="identifier"):
        mismatch_store.load("p")
    with pytest.raises(ProfileLifecycleError):
        store.create("p")
    with pytest.raises(ProfileLifecycleError, match="changed"):
        store.save(store.load("p"), expected_revision=99)
    with pytest.raises(ProfileLifecycleError, match="absolute"):
        store.export("p", Path("relative.toml"))
    export_target = tmp_path / "export-target.toml"
    export_target.write_text("do not replace", encoding="utf-8")
    export_link = tmp_path / "export-link.toml"
    export_link.symlink_to(export_target)
    with pytest.raises(ProfileLifecycleError, match="symlink"):
        store.export("p", export_link)
    export_directory = tmp_path / "export-directory"
    export_directory.mkdir()
    export_parent = tmp_path / "export-parent"
    export_parent.symlink_to(export_directory, target_is_directory=True)
    with pytest.raises(ProfileLifecycleError, match="symlink"):
        store.export("p", export_parent / "nested.toml")
    candidate = tmp_path / "candidate.toml"
    with pytest.raises(ProfileLifecycleError):
        store.diff("p", candidate)
    sealed = store.seal("p")
    with pytest.raises(ProfileLifecycleError):
        store.commit_learning("p", (Rule("x", RuleScope.EXACT, RuleMode.HOST_RO),))
    assert store.seal("p") == sealed
    assert store.unseal("p").sealed is False
    assert store.unseal("p").sealed is False

    exported = tmp_path / "export.toml"
    with monkeypatch.context() as patch:
        patch.setattr(
            "astral_project.profile_lifecycle.atomic_write_private",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("export")),
        )
        with pytest.raises(ProfileLifecycleError, match="export"):
            store.export("p", tmp_path / "export-fail.toml")
    store.export("p", exported)
    other_store = ProfileStore(tmp_path / "other")
    with pytest.raises(ProfileLifecycleError, match="does not match"):
        other_store.import_profile(exported, profile_id="other")
    other_store.import_profile(exported)
    with pytest.raises(ProfileLifecycleError, match="already exists"):
        other_store.import_profile(exported)
    link = tmp_path / "link.toml"
    link.symlink_to(exported)
    with pytest.raises(ProfileLifecycleError):
        ProfileStore(tmp_path / "linked").import_profile(link)
    with pytest.raises(ProfileLifecycleError):
        store.save_new(store.load("p"))
    with monkeypatch.context() as patch:
        patch.setattr(
            "astral_project.profile_lifecycle.os.replace",
            lambda *_args: (_ for _ in ()).throw(OSError("archive")),
        )
        with pytest.raises(ProfileLifecycleError, match="archive"):
            store.archive_profile("p")
    with monkeypatch.context() as patch:
        patch.setattr(
            "astral_project.profile_lifecycle.atomic_write_private",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("disk")),
        )
        with pytest.raises(ProfileLifecycleError, match="saved"):
            store.save(store.load("p"))


def test_profile_store_edit_rejects_sealed_and_bad_candidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ProfileStore(tmp_path / "config")
    store.create("p")
    store.seal("p")
    with pytest.raises(ProfileLifecycleError, match="sealed"):
        store.edit("p", editor="true")
    store.unseal("p")

    def wrong_id(command: list[str], *, check: bool) -> subprocess.CompletedProcess[bytes]:
        Path(command[-1]).write_text('version = 1\nid = "q"\nname = "q"')
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(ProfileLifecycleError, match="identifier"):
        store.edit("p", editor="true", run=wrong_id)

    def invalid(command: list[str], *, check: bool) -> subprocess.CompletedProcess[bytes]:
        Path(command[-1]).write_text("not toml")
        return subprocess.CompletedProcess(command, 0)

    with pytest.raises(ProfileLifecycleError, match="invalid"):
        store.edit("p", editor="true", run=invalid)
    with monkeypatch.context() as patch:
        patch.setattr(
            "astral_project.profile_lifecycle.os.write",
            lambda *_args: 0,
        )
        with pytest.raises(ProfileLifecycleError, match="invalid"):
            store.edit("p", editor="true")


def test_profile_learner_rejects_bad_commands_and_selects_writable_backends(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "config")
    store.create("p")
    captured: list[list[str]] = []

    def runner(arguments: list[str], **kwargs: object) -> int:
        captured.append(arguments)
        request = cast(Callable[..., object], kwargs["daemon_request"])
        request("noop")
        return 0

    learner = ProfileLearner(store, state_root=tmp_path / "state", sandbox_runner=runner)
    with pytest.raises(LearnerError):
        learner.run("p", (), runtime=tmp_path / "run")
    with pytest.raises(LearnerError):
        learner.run("p", ("bad\x00",), runtime=tmp_path / "run")
    with pytest.raises(LearnerError, match="--grant"):
        learner.run("p", ("/bin/true",), runtime=tmp_path / "run", remotes=("remote",))
    with pytest.raises(LearnerError, match="--remote"):
        learner.run("p", ("/bin/true",), runtime=tmp_path / "run", grant_id="grant")
    with pytest.raises(LearnerError, match="daemon"):
        learner.run(
            "p", ("/bin/true",), runtime=tmp_path / "run", grant_id="grant", remotes=("remote",)
        )
    private = Profile(
        1, "private", "private", rules=(Rule("data", RuleScope.SUBTREE, RuleMode.PRIVATE_RW),)
    )
    overlay = Profile(
        1, "overlay", "overlay", rules=(Rule("data", RuleScope.SUBTREE, RuleMode.OVERLAY_RW),)
    )
    mixed = Profile(
        1,
        "mixed",
        "mixed",
        rules=(
            Rule("private", RuleScope.SUBTREE, RuleMode.PRIVATE_RW),
            Rule("overlay", RuleScope.SUBTREE, RuleMode.OVERLAY_RW),
        ),
    )
    store.save_new(private)
    store.save_new(overlay)
    store.save_new(mixed)
    learner.run("private", ("/bin/true",), runtime=tmp_path / "run")
    learner.run("p", ("/bin/true",), runtime=tmp_path / "run", external_only=True)

    def daemon_request(
        _operation: str, _payload: Mapping[str, object] | None = None
    ) -> dict[str, object]:
        return {}

    learner.run(
        "p",
        ("/bin/true",),
        runtime=tmp_path / "run",
        grant_id="grant-id",
        remotes=("grant-id:/source=/remote:ro",),
        daemon_request=daemon_request,
    )
    assert "--private-root" in captured[0]
    assert captured[2][captured[2].index("--grant") : captured[2].index("--profile")] == [
        "--grant",
        "grant-id",
        "--remote",
        "grant-id:/source=/remote:ro",
    ]
    learner.run(
        "overlay",
        ("/bin/true",),
        runtime=tmp_path / "run",
        external_only=True,
        approval_socket=tmp_path / "approval" / "socket",
    )
    assert "--overlay-root" in captured[-1]
    assert "--approval-socket" in captured[-1]
    learner.run("mixed", ("/bin/true",), runtime=tmp_path / "run")
    assert "--private-root" in captured[-1]
    assert "--overlay-root" in captured[-1]
    assert isinstance(learner_environment(), dict)


def test_profile_learner_stages_approval_provenance(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "config")
    store.create("p")
    learner = ProfileLearner(
        store, state_root=tmp_path / "state", sandbox_runner=lambda *_a, **_k: 0
    )
    request = PendingRequest("s", 1, Operation.EXECUTE, "tool", False, Sensitivity.EXECUTABLES, 1.0)
    draft: list[tuple[Rule, ApprovalProvenance]] = []
    callback = learner._decision_observer("p", draft)
    callback(request, "bin/tool", MediationDecision.DENY)
    assert store.load("p").rules == ()
    callback(request, "bin/tool", MediationDecision.ALLOW_ONCE)
    assert store.load("p").rules == ()
    assert draft[0][0].mode is RuleMode.HOST_RX
    store.commit_learning_batch("p", tuple(draft))
    assert store.load("p").rules[0].mode is RuleMode.HOST_RX


def test_profile_learner_discards_failed_learning(tmp_path: Path) -> None:
    store = ProfileStore(tmp_path / "config")
    store.create("p")

    def failed_runner(_arguments: list[str], **kwargs: object) -> int:
        mediator = cast(UnknownPathMediator, kwargs["approval_mediator"])
        result: list[object] = []

        def request_path() -> None:
            result.append(
                mediator.request(
                    session_id="failed",
                    path="secret.txt",
                    path_component="secret.txt",
                    operation=Operation.READ,
                    sensitivity=Sensitivity.CONFIGURATION,
                )
            )

        thread = threading.Thread(target=request_path)
        thread.start()
        pending: tuple[PendingRequest, ...] = ()
        for _ in range(1000):
            pending = mediator.pending()
            if pending:
                break
            time.sleep(0.001)
        assert pending
        request = pending[0]
        assert mediator.decide(
            session_id=request.session_id,
            request_number=request.request_number,
            decision=MediationDecision.ALLOW_ONCE,
        )
        thread.join(timeout=2)
        assert result
        return 17

    learner = ProfileLearner(store, state_root=tmp_path / "state", sandbox_runner=failed_runner)
    assert learner.run("p", ("/bin/false",), runtime=tmp_path / "run") == 17
    profile = store.load("p")
    assert profile.rules == ()
    assert profile.provenance == ()
    assert profile.revision == 1


@pytest.mark.parametrize(
    ("failure", "label"),
    [
        (RuntimeError("runner failed"), "exception"),
        (KeyboardInterrupt(), "cancellation"),
        (RuntimeError("teardown failed"), "teardown"),
    ],
    ids=("exception", "cancellation", "teardown"),
)
def test_profile_learner_discards_exception_and_teardown_drafts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
    label: str,
) -> None:
    store = ProfileStore(tmp_path / "config")
    store.create("p")
    commit_calls: list[tuple[str, tuple[tuple[Rule, ApprovalProvenance], ...]]] = []
    original_commit = store.commit_learning_batch

    def record_commit(
        profile_id: str, approvals: tuple[tuple[Rule, ApprovalProvenance], ...]
    ) -> Profile:
        commit_calls.append((profile_id, approvals))
        return original_commit(profile_id, approvals)

    monkeypatch.setattr(store, "commit_learning_batch", record_commit)

    def failing_runner(_arguments: list[str], **kwargs: object) -> int:
        mediator = cast(UnknownPathMediator, kwargs["approval_mediator"])
        result: list[object] = []

        def request_path() -> None:
            result.append(
                mediator.request(
                    session_id=f"failed-{label}",
                    path="secret.txt",
                    path_component="secret.txt",
                    operation=Operation.READ,
                    sensitivity=Sensitivity.CONFIGURATION,
                )
            )

        thread = threading.Thread(target=request_path)
        thread.start()
        pending: tuple[PendingRequest, ...] = ()
        for _ in range(1000):
            pending = mediator.pending()
            if pending:
                break
            time.sleep(0.001)
        assert pending
        request = pending[0]
        assert mediator.decide(
            session_id=request.session_id,
            request_number=request.request_number,
            decision=MediationDecision.ALLOW_ONCE,
        )
        thread.join(timeout=2)
        assert result
        raise failure

    learner = ProfileLearner(store, state_root=tmp_path / "state", sandbox_runner=failing_runner)
    with pytest.raises(type(failure)):
        learner.run("p", ("/bin/false",), runtime=tmp_path / "run")
    profile = store.load("p")
    assert profile.rules == ()
    assert profile.provenance == ()
    assert profile.revision == 1
    assert commit_calls == []


def test_profile_cli_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    output = StringIO()
    error = StringIO()
    assert cli.run(["profile"], stdout=output, stderr=error) == 2
    assert cli.run(["profile", "learn", "p"], stdout=output, stderr=error) == 2
    assert cli.run(["profile", "learn", "p", "--", "/bin/true"], stdout=output, stderr=error) == 70
    assert cli.run(["profile", "create", "p"], stdout=output, stderr=error) == 0
    assert cli.run(["profile", "create", "q", "--name", "Q"], stdout=output, stderr=error) == 0
    assert cli.run(["profile", "create", "bad", "--wrong", "x"], stdout=output, stderr=error) == 2
    assert cli.run(["profile", "seal", "p"], stdout=StringIO(), stderr=error) == 0
    assert cli.run(["profile", "review", "p"], stdout=StringIO(), stderr=error) == 0
    with monkeypatch.context() as patch:
        patch.setattr(
            "astral_project.profile_lifecycle.ProfileStore.review",
            lambda _self, _profile_id: "review",
        )
        reviewed = StringIO()
        assert cli.run(["profile", "review", "p"], stdout=reviewed, stderr=error) == 0
        assert reviewed.getvalue() == "review\n"
    assert cli.run(["profile", "list"], stdout=StringIO(), stderr=error) == 0
    archive_output = StringIO()
    assert cli.run(["profile", "archive", "q"], stdout=archive_output, stderr=error) == 0
    assert cli.run(["profile", "create", "../bad"], stdout=StringIO(), stderr=error) == 70
    assert "path component" in error.getvalue()
    export = tmp_path / "p-export.toml"
    assert cli.run(["profile", "export", "p", str(export)], stdout=StringIO(), stderr=error) == 0
    assert cli.run(["profile", "archive", "p"], stdout=StringIO(), stderr=error) == 0
    assert cli.run(["profile", "import", str(export)], stdout=StringIO(), stderr=error) == 0
    assert cli.run(["profile", "diff", "p", str(export)], stdout=StringIO(), stderr=error) == 0
    monkeypatch.setattr(
        "astral_project.profile_lifecycle.ProfileStore.edit",
        lambda self, _profile_id: self.load("p"),
    )
    assert cli.run(["profile", "edit", "p"], stdout=StringIO(), stderr=error) == 0
    learner_calls: list[dict[str, object]] = []

    class FakeLearner:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def run(self, *_args: object, **kwargs: object) -> int:
            learner_calls.append(kwargs)
            return 7

    monkeypatch.setattr(cli, "ProfileLearner", FakeLearner)
    assert (
        cli.run(["profile", "learn", "p", "--", "/bin/true"], stdout=StringIO(), stderr=error) == 7
    )
    assert (
        cli.run(
            ["profile", "learn", "p", "--remote", "remote", "--", "/bin/true"],
            stdout=StringIO(),
            stderr=error,
        )
        == 2
    )
    assert (
        cli.run(
            [
                "profile",
                "learn",
                "p",
                "--external",
                "--grant",
                "g",
                "--remote",
                "g:/source=/remote:ro",
                "--",
                "/bin/true",
            ],
            stdout=StringIO(),
            stderr=error,
        )
        == 7
    )
    assert learner_calls[-1]["grant_id"] == "g"
    assert learner_calls[-1]["remotes"] == ["g:/source=/remote:ro"]
    assert (
        cli.run(
            ["profile", "learn", "p", "--bad", "--", "/bin/true"], stdout=StringIO(), stderr=error
        )
        == 2
    )
    assert cli.run(["profile", "bogus"], stdout=StringIO(), stderr=error) == 2


def test_profile_learner_persists_allow_once_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ProfileStore(tmp_path / "config")
    store.create("p")
    captured: dict[str, object] = {}

    def fake_runner(arguments: list[str], **kwargs: object) -> int:
        mediator = cast(UnknownPathMediator, kwargs["approval_mediator"])
        captured["arguments"] = arguments
        result: list[object] = []

        def wait_for_request() -> None:
            result.append(
                mediator.request(
                    session_id="s",
                    path=".config/settings.toml",
                    path_component="settings.toml",
                    operation=Operation.READ,
                    sensitivity=Sensitivity.CONFIGURATION,
                )
            )

        thread = threading.Thread(target=wait_for_request)
        thread.start()
        while not mediator.pending():
            pass
        request = mediator.pending()[0]
        assert isinstance(request, PendingRequest)
        assert mediator.decide(
            session_id=request.session_id,
            request_number=request.request_number,
            decision=MediationDecision.ALLOW_ONCE,
        )
        thread.join(timeout=2)
        assert result
        return 0

    commit_calls: list[tuple[str, tuple[tuple[Rule, ApprovalProvenance], ...]]] = []
    original_commit = store.commit_learning_batch

    def record_commit(
        profile_id: str, approvals: tuple[tuple[Rule, ApprovalProvenance], ...]
    ) -> Profile:
        commit_calls.append((profile_id, approvals))
        return original_commit(profile_id, approvals)

    monkeypatch.setattr(store, "commit_learning_batch", record_commit)
    learner = ProfileLearner(
        store,
        state_root=tmp_path / "state",
        home_root=tmp_path / "home",
        sandbox_runner=fake_runner,
    )
    assert learner.run("p", ("/bin/true",), runtime=tmp_path / "run") == 0
    assert len(commit_calls) == 1
    assert commit_calls[0][0] == "p"
    assert len(commit_calls[0][1]) == 1
    assert store.load("p").rules[0].path == ".config/settings.toml"
    assert "--profile" in cast(list[str], captured["arguments"])
    store.seal("p")
    with pytest.raises(LearnerError):
        learner.run("p", ("/bin/true",), runtime=tmp_path / "run")
