"""Narrow session-visible listing capability; no host or grant selection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.rclone.listing import ListingOptions, listing_options_from_payload


@dataclass(frozen=True, slots=True)
class SessionListingScope:
    """One already-bound grant and its virtual export roots."""

    grant_name: str
    allowed_paths: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.grant_name or any(
            not path.startswith("/")
            or "\x00" in path
            or any(part in {".", ".."} for part in path.split("/"))
            for path in self.allowed_paths
        ):
            raise _error("session listing scope is invalid")

    def authorize(self, target: str) -> str:
        """Return target only when it names this grant and an allowed virtual path."""
        prefix, separator, path = target.partition(":")
        if not separator or prefix != self.grant_name or not path.startswith("/"):
            raise _error("listing target selects another grant or host")
        return self.authorize_path(path)

    def authorize_path(self, path: str) -> str:
        """Return one already-bound virtual path without accepting host selectors."""
        if not path.startswith("/"):
            raise _error("listing path must be absolute")
        if "\x00" in path or any(part in {".", ".."} for part in path.split("/")):
            raise _error("listing target contains traversal")
        if not any(
            path == root or path.startswith(root.rstrip("/") + "/") for root in self.allowed_paths
        ):
            raise _error("listing target is outside bound export")
        return "aspr-session:" + path


def constrain_session_listing_payload(
    payload: Mapping[str, object], scope: SessionListingScope
) -> tuple[str, ListingOptions]:
    """Decode a sandbox path and bind it to the already-selected grant."""
    target, options = listing_options_from_payload(payload)
    return scope.authorize_path(target), options


def constrain_listing_payload(
    payload: Mapping[str, object], scope: SessionListingScope
) -> tuple[str, ListingOptions]:
    """Decode listing request after applying session grant/path authority."""
    target, options = listing_options_from_payload(payload)
    return scope.authorize(target), options


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.DAEMON_AUTH,
        message=message,
        security_result="session listing request was rejected",
        unsafe_reason="sandbox listing has no host, user, or grant selection authority",
        next_action="use path within the already-bound session grant",
    )
