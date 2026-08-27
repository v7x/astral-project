"""Fail-closed environment and inherited-descriptor boundary for local sandboxes."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

_SECRET_NAME = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API[_.-]?KEY|AUTH|CREDENTIAL|PRIVATE[_.-]?KEY)", re.I
)
_DEFAULT_ALLOWED = frozenset({"LANG", "LC_ALL", "LC_CTYPE", "TERM"})
_SUBPROCESS_ALLOWED = _DEFAULT_ALLOWED | {"PATH"}
_RESERVED_CONTROL_NAMES = frozenset(
    {
        "ASPR_APPROVAL_SOCKET",
        "ASPR_HOMED_APPROVAL_SOCKET",
        "ASPR_SESSION_ID",
        "ASPR_SESSION_SOCKET",
    }
)
_TRANSPORT_CAPABILITY_NAMES = frozenset({"ASPR_TRANSPORT_SOCKET", "ASPR_TRANSPORT_TOKEN"})


@dataclass(frozen=True, slots=True)
class SanitizedEnvironment:
    """Values safe to pass to a child plus non-secret diagnostic names."""

    values: dict[str, str]
    removed_names: tuple[str, ...]
    removed_path_entries: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EnvironmentPolicy:
    """Explicit inherited environment policy; child receives no ambient default."""

    allowed_names: frozenset[str] = _DEFAULT_ALLOWED
    unset_names: frozenset[str] = frozenset()
    fixed_values: tuple[tuple[str, str], ...] = ()

    def sanitize(
        self,
        environment: Mapping[str, str],
        *,
        visible_paths: Iterable[Path] = (),
    ) -> SanitizedEnvironment:
        visible = tuple(_safe_visible_path(path) for path in visible_paths)
        values: dict[str, str] = {}
        removed: list[str] = []
        removed_path: list[str] = []
        for name, value in environment.items():
            if (
                name in self.unset_names
                or name not in self.allowed_names
                or name in _RESERVED_CONTROL_NAMES
                or _SECRET_NAME.search(name)
            ):
                removed.append(name)
                continue
            if name == "PATH":
                kept, discarded = _visible_path(value, visible)
                if kept:
                    values[name] = os.pathsep.join(kept)
                removed_path.extend(discarded)
                continue
            values[name] = value
        for name, value in self.fixed_values:
            if not name or "\x00" in name or "\x00" in value:
                raise ValueError("fixed environment entry contains NUL")
            if (
                name in self.unset_names
                or name in _RESERVED_CONTROL_NAMES
                or _SECRET_NAME.search(name)
            ):
                removed.append(name)
                continue
            if name == "PATH":
                kept, discarded = _visible_path(value, visible)
                if kept:
                    values[name] = os.pathsep.join(kept)
                removed_path.extend(discarded)
                continue
            values[name] = value
        return SanitizedEnvironment(
            values=values,
            removed_names=tuple(sorted(removed)),
            removed_path_entries=tuple(removed_path),
        )

    def diagnostics(self, sanitized: SanitizedEnvironment) -> dict[str, tuple[str, ...]]:
        """Return names only; never include environment values or PATH contents."""
        return {
            "removed_names": sanitized.removed_names,
            "removed_path_entries": tuple("<hidden>" for _ in sanitized.removed_path_entries),
        }


def sanitize_subprocess_environment(
    environment: Mapping[str, str],
    *,
    visible_paths: Iterable[Path] = (),
    capability_environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Build a safe subprocess environment with only explicit transport capabilities."""
    clean = (
        EnvironmentPolicy(allowed_names=_SUBPROCESS_ALLOWED)
        .sanitize(environment, visible_paths=visible_paths)
        .values
    )
    if capability_environment is None:
        return clean
    if set(capability_environment) - _TRANSPORT_CAPABILITY_NAMES:
        raise ValueError("unsupported transport capability environment")
    for name, value in capability_environment.items():
        if not value or "\x00" in value:
            raise ValueError("transport capability environment is invalid")
        clean[name] = value
    return clean


def inherited_fd_inventory(*, allowed: Iterable[int] = (0, 1, 2)) -> tuple[int, ...]:
    """Enumerate inherited descriptors without reading descriptor targets."""
    allowed_set = set(allowed)
    try:
        descriptors = (int(value) for value in os.listdir("/proc/self/fd"))
    except OSError:
        return ()
    return tuple(sorted(fd for fd in descriptors if fd not in allowed_set))


def close_unlisted_fds(*, allowed: Iterable[int] = (0, 1, 2)) -> None:
    """Close every descriptor not in documented allowlist before child execution."""
    allowed_set = set(allowed)
    for fd in inherited_fd_inventory(allowed=allowed_set):
        try:
            os.close(fd)
        except OSError:
            continue


def _safe_visible_path(path: Path) -> Path:
    if not path.is_absolute() or "\x00" in os.fspath(path):
        raise ValueError("visible PATH root must be absolute and NUL-free")
    return path.resolve(strict=False)


def _visible_path(value: str, visible: tuple[Path, ...]) -> tuple[list[str], list[str]]:
    kept: list[str] = []
    discarded: list[str] = []
    for entry in value.split(os.pathsep):
        if not entry:
            discarded.append(entry)
            continue
        candidate = Path(entry)
        if not candidate.is_absolute() or not candidate.is_dir():
            discarded.append(entry)
            continue
        resolved = candidate.resolve(strict=False)
        if any(resolved == root or root in resolved.parents for root in visible):
            kept.append(entry)
        else:
            discarded.append(entry)
    return kept, discarded
