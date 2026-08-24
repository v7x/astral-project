from __future__ import annotations

import pytest

from astral_project.core.errors import AstralError
from astral_project.session.listing import (
    SessionListingScope,
    constrain_listing_payload,
    constrain_session_listing_payload,
)


def payload(target: str) -> dict[str, object]:
    return {
        "filters": [],
        "json_output": False,
        "max_depth": None,
        "no_header": False,
        "raw_output": False,
        "recursive": False,
        "reverse": False,
        "sort": "path",
        "stat": False,
        "target": target,
        "timeout_seconds": None,
    }


def test_session_scope_binds_grant_and_export_path() -> None:
    scope = SessionListingScope("grant-1", ("/project", "/data/reference"))
    target, _ = constrain_listing_payload(payload("grant-1:/project/src"), scope)
    assert target == "aspr-session:/project/src"
    with pytest.raises(AstralError):
        scope.authorize("other:/project")
    with pytest.raises(AstralError):
        scope.authorize("grant-1:/project/../secret")
    with pytest.raises(AstralError):
        scope.authorize("grant-1:/hidden")
    target, _ = constrain_session_listing_payload(payload("/project/src"), scope)
    assert target == "aspr-session:/project/src"
    with pytest.raises(AstralError):
        scope.authorize_path("relative")


def test_session_scope_rejects_invalid_root() -> None:
    with pytest.raises(AstralError):
        SessionListingScope("grant", ("relative",))
