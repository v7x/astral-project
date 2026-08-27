"""Explicit pathname socket and credential policy for sandbox construction."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from astral_project.profile import Profile, Sensitivity, WarningLevel


@dataclass(frozen=True, slots=True)
class ResourceDecision:
    allowed: bool
    reason: str
    warning: WarningLevel
    display_path: str


class ResourcePolicy:
    """Resolve exact approved resources; no discovery or abstract socket support."""

    def __init__(self, profile: Profile) -> None:
        self.profile = profile

    def socket(self, path: Path, *, strong_confirmation: bool = False) -> ResourceDecision:
        if not path.is_absolute() or not _canonical(path):
            return ResourceDecision(
                False,
                "socket path must be exact absolute pathname",
                WarningLevel.STRONG,
                "<redacted>",
            )
        rule = next((item for item in self.profile.sockets if item.path == str(path)), None)
        if rule is None:
            return ResourceDecision(
                False, "socket is not explicitly approved", WarningLevel.STRONG, "<redacted>"
            )
        if (
            rule.dangerous or rule.sensitivity is Sensitivity.CREDENTIAL
        ) and not strong_confirmation:
            reason = (
                "dangerous socket requires strong confirmation"
                if rule.dangerous
                else "credential-sensitive socket requires strong confirmation"
            )
            return ResourceDecision(False, reason, WarningLevel.STRONG, "<redacted>")
        try:
            mode = path.lstat().st_mode
        except OSError:
            return ResourceDecision(
                False, "approved socket is unavailable", rule.warning, "<redacted>"
            )
        if not stat.S_ISSOCK(mode):
            return ResourceDecision(
                False, "approved path is not a pathname socket", rule.warning, "<redacted>"
            )
        return ResourceDecision(True, "exact approved pathname socket", rule.warning, "<socket>")

    def raw_socket(self, *, strong_confirmation: bool = False) -> ResourceDecision:
        """Require an explicit profile opt-in and strong confirmation for raw sockets."""
        if not self.profile.raw_socket:
            return ResourceDecision(
                False, "raw socket access is disabled by profile", WarningLevel.STRONG, "<redacted>"
            )
        if not strong_confirmation:
            return ResourceDecision(
                False,
                "raw socket access requires strong confirmation",
                WarningLevel.STRONG,
                "<redacted>",
            )
        return ResourceDecision(
            True, "raw socket explicitly approved", WarningLevel.STRONG, "<raw-socket>"
        )

    def credential(self, path: str, *, strong_confirmation: bool = False) -> ResourceDecision:
        rule = next((item for item in self.profile.credentials if item.path == path), None)
        if rule is None:
            return ResourceDecision(
                False, "credential is not explicitly approved", WarningLevel.STRONG, "<redacted>"
            )
        return ResourceDecision(
            strong_confirmation,
            "strong confirmation required"
            if not strong_confirmation
            else "exact credential approved",
            rule.warning,
            "<credential>",
        )

    def approved_sockets(self, *, strong_confirmation: bool = False) -> tuple[Path, ...]:
        return tuple(
            path
            for rule in self.profile.sockets
            for path in (Path(rule.path),)
            if self.socket(path, strong_confirmation=strong_confirmation).allowed
        )


def validate_socket_path(path: str) -> None:
    """Reject abstract, relative, normalized-path, and NUL-containing socket names."""
    if not path.startswith("/") or path.startswith("@") or not _canonical(Path(path)):
        raise ValueError("socket must be exact absolute pathname")


def socket_kind(path: Path) -> str:
    """Classify existing path without exposing its content."""
    try:
        mode = path.lstat().st_mode
    except OSError:
        return "missing"
    if stat.S_ISSOCK(mode):
        return "pathname-socket"
    return "other"


def _canonical(path: Path) -> bool:
    value = os.fspath(path)
    return "\x00" not in value and str(path) == value and ".." not in path.parts and path.name != ""
