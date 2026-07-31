"""Stable error-envelope tests."""

from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode

FIXTURE = Path(__file__).parents[1] / "fixtures" / "errors" / "path-invalid-name.json"


def test_error_json_matches_golden_fixture() -> None:
    error = AstralError(
        code=ErrorCode.PATH_INVALID_NAME,
        message="invalid path component '../key'",
        security_result="path component was rejected",
        unsafe_reason="path traversal can redirect trusted state",
        next_action="use one non-empty filename component",
    )

    assert error.to_json() == FIXTURE.read_text(encoding="utf-8").strip()
    assert str(error) == (
        "ASPR_PATH_INVALID_NAME [3001]: invalid path component '../key'\n"
        "Security result: path component was rejected\n"
        "Why: path traversal can redirect trusted state\n"
        "Fix: use one non-empty filename component"
    )


def test_error_code_has_stable_string_and_number() -> None:
    assert ErrorCode.PERMISSION_WRONG_OWNER.string == "ASPR_PERMISSION_WRONG_OWNER"
    assert ErrorCode.PERMISSION_WRONG_OWNER.number == 4001
