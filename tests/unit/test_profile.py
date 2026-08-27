from __future__ import annotations

import pytest

from astral_project.profile import (
    Operation,
    Profile,
    ProfileError,
    RuleMode,
    RuleScope,
    host_path,
    normalize_home_path,
    validate_profile_id,
)

PROFILE = """
version = 1
id = "p1"
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

[[home.rules]]
path = ".local/bin"
scope = "subtree"
mode = "host-rx"
sensitivity = "executables"
list = true

[[home.rules]]
path = ".secret"
scope = "exact"
mode = "deny"
"""


def test_profile_round_trip_preserves_rules() -> None:
    profile = Profile.from_toml(PROFILE)
    loaded = Profile.from_toml(profile.to_toml())
    assert loaded == profile


def test_exact_wins_over_subtree() -> None:
    profile = Profile.from_toml(PROFILE)
    decision = profile.decision(".codex/config.toml", Operation.READ)
    assert decision.allowed
    assert decision.rule is not None
    assert decision.rule.scope is RuleScope.EXACT


def test_subtree_listing_requires_explicit_permission() -> None:
    profile = Profile.from_toml(PROFILE.replace("list = true\n", ""))
    assert not profile.decision(".codex", Operation.LIST).allowed


def test_deny_wins_at_equal_specificity() -> None:
    profile = Profile.from_toml(
        PROFILE
        + '\n[[home.rules]]\npath = ".blocked"\nscope = "exact"\nmode = "host-ro"\n'
        + '\n[[home.rules]]\npath = ".blocked"\nscope = "exact"\nmode = "deny"\n'
    )
    assert not profile.decision(".blocked", Operation.READ).allowed


def test_equal_non_deny_conflict_fails() -> None:
    with pytest.raises(ProfileError, match="equal-specificity"):
        Profile.from_toml(
            PROFILE
            + '\n[[home.rules]]\npath = ".same"\nscope = "exact"\nmode = "host-ro"\n'
            + '\n[[home.rules]]\npath = ".same"\nscope = "exact"\nmode = "host-rx"\n'
        )


@pytest.mark.parametrize("path", ["", "/absolute", "a/../b", "a//b", "a/./b", "a\\b", "../x"])
def test_path_escape_and_non_normalized_paths_rejected(path: str) -> None:
    with pytest.raises(ProfileError):
        normalize_home_path(path)


@pytest.mark.parametrize("profile_id", ["", ".", "..", "../outside", "/absolute", "a/b", "a\\b"])
def test_profile_id_must_be_one_safe_path_component(profile_id: str) -> None:
    with pytest.raises(ProfileError, match="one path component"):
        validate_profile_id(profile_id)
        Profile(1, profile_id, "fixture")


def test_profile_constructor_rejects_unsafe_id() -> None:
    with pytest.raises(ProfileError, match="one path component"):
        Profile(1, "../outside", "fixture")


def test_ancestor_lookup_is_opaque_but_listing_is_not_granted() -> None:
    profile = Profile.from_toml(
        PROFILE.split("[[home.rules]]")[0]
        + '[[home.rules]]\npath = ".codex/config.toml"\nscope = "exact"\nmode = "host-ro"\n'
    )
    ancestor = profile.decision(".codex", Operation.LOOKUP)
    assert not ancestor.allowed
    assert ancestor.reason == "opaque ancestor traversal"
    assert not profile.decision(".codex", Operation.LIST).allowed


def test_writable_root_overlap_fails() -> None:
    with pytest.raises(ProfileError, match="overlapping writable"):
        Profile.from_toml(
            """
            version = 1
            id = "p"
            name = "p"
            [[home.rules]]
            path = ".cache"
            scope = "subtree"
            mode = "private-rw"
            [[home.rules]]
            path = ".cache/nested"
            scope = "exact"
            mode = "overlay-rw"
            """
        )


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ("not toml =", "invalid profile TOML"),
        ('version = 2\nid = "p"\nname = "p"', "unsupported profile version"),
        (
            'version = 1\nid = "p"\nname = "p"\nunknown_learning = "bad"',
            "unknown_learning",
        ),
    ],
)
def test_invalid_profile_fields_fail(source: str, message: str) -> None:
    with pytest.raises(ProfileError, match=message):
        Profile.from_toml(source)


def test_invalid_rule_and_root_types_fail() -> None:
    with pytest.raises(ProfileError):
        Profile.from_toml('version = 1\nid = "p"\nname = "p"\n[home]\nrules = {}')
    with pytest.raises(ProfileError):
        Profile.from_toml(
            """
            version = 1
            id = "p"
            name = "p"
            [[home.rules]]
            path = ".x"
            mode = "host-ro"
            list = true
            """
        )
    with pytest.raises(ProfileError):
        Profile.from_toml(
            """
            version = 1
            id = "p"
            name = "p"
            [[home.rules]]
            path = ".x"
            mode = "not-a-mode"
            """
        )


def test_exact_rule_cannot_grant_listing_and_host_path_is_relative() -> None:
    with pytest.raises(ProfileError):
        Profile.from_toml(
            """
            version = 1
            id = "p"
            name = "p"
            [[home.rules]]
            path = ".x"
            mode = "host-ro"
            list = true
            """
        )
    assert host_path(12, ".x") == "/proc/self/fd/12/.x"


def test_unknown_paths_and_invalid_scalar_fields_fail() -> None:
    profile = Profile.from_toml(PROFILE)
    assert not profile.decision(".missing", Operation.LOOKUP).allowed
    with pytest.raises(ProfileError, match="unknown_sealed"):
        Profile.from_toml('version = 1\nid = "p"\nname = "p"\nunknown_sealed = "bad"')
    with pytest.raises(ProfileError, match="id must"):
        Profile.from_toml('version = 1\nid = 1\nname = "p"')
    with pytest.raises(ProfileError, match="version must"):
        Profile.from_toml('version = "1"\nid = "p"\nname = "p"')
    with pytest.raises(ProfileError, match="sealed must"):
        Profile.from_toml('version = 1\nid = "p"\nname = "p"\nsealed = "yes"')
    with pytest.raises(ProfileError, match="each home rule"):
        Profile.from_toml('version = 1\nid = "p"\nname = "p"\n[home]\nrules = ["bad"]')
    with pytest.raises(ProfileError, match="home must be a table"):
        Profile.from_toml('version = 1\nid = "p"\nname = "p"\nhome = "bad"')
    with pytest.raises(ProfileError, match="rule list must be boolean"):
        Profile.from_toml(
            'version = 1\nid = "p"\nname = "p"\n[[home.rules]]\n'
            'path = ".x"\nmode = "host-ro"\nlist = "false"'
        )
    with pytest.raises(ProfileError, match="rule path must be string"):
        Profile.from_toml(
            'version = 1\nid = "p"\nname = "p"\n[[home.rules]]\npath = 1\nmode = "host-ro"'
        )
    with pytest.raises(ProfileError, match="rule mode is required"):
        Profile.from_toml('version = 1\nid = "p"\nname = "p"\n[[home.rules]]\npath = ".x"')


def test_non_overlapping_writable_rules_validate() -> None:
    profile = Profile.from_toml(
        """
        version = 1
        id = "p"
        name = "p"
        [[home.rules]]
        path = ".cache"
        mode = "private-rw"
        [[home.rules]]
        path = ".state"
        mode = "overlay-rw"
        """
    )
    assert len(profile.rules) == 2


def test_host_rx_only_exposes_execute_class() -> None:
    profile = Profile.from_toml(PROFILE)
    assert profile.decision(".local/bin/tool", Operation.EXECUTE).allowed
    assert not profile.decision(".local/bin/tool", Operation.WRITE).allowed
    assert RuleMode.HOST_RX.value == "host-rx"
