"""Source-root AppArmor include generation stays narrow and deterministic."""

from __future__ import annotations

import pytest

from astral_project.broker.apparmor import render_source_roots


def test_render_source_roots_is_sorted_and_deterministic() -> None:
    assert render_source_roots(("/scratch/two", "/home/test/project", "/scratch/two")) == (
        "/home/test/project/ r,\n/home/test/project/** r,\n/scratch/two/ r,\n/scratch/two/** r,\n"
    )


def test_render_source_roots_escapes_exact_path_characters() -> None:
    assert (
        render_source_roots(("/home/test/a b",)) == "/home/test/a\\ b/ r,\n/home/test/a\\ b/** r,\n"
    )


@pytest.mark.parametrize(
    "root",
    ("relative", "/", "/a/../b", "/a/./b", "/a\x00b", "/a\nb"),
)
def test_render_source_roots_rejects_unsafe_roots(root: str) -> None:
    with pytest.raises(ValueError):
        render_source_roots((root,))


def test_render_source_roots_rejects_empty_roots() -> None:
    with pytest.raises(ValueError):
        render_source_roots(())
