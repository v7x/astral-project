from __future__ import annotations

import pytest

from astral_project.core.errors import AstralError
from astral_project.sftp.client import SftpExtensions
from astral_project.sftp.policy import SftpExtensionPolicy, validate_extensions


def test_extension_policy_accepts_fixed_safe_set() -> None:
    extensions = SftpExtensions({b"supported2": b"", b"fsync@openssh.com": b"1"})
    assert validate_extensions(extensions) == {b"supported2", b"fsync@openssh.com"}


def test_extension_policy_rejects_unknown_extension() -> None:
    with pytest.raises(AstralError) as error:
        SftpExtensionPolicy(frozenset({b"safe"})).validate(SftpExtensions({b"unsafe": b""}))
    assert "unsupported extensions" in error.value.message
