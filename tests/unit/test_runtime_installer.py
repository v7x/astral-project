"""Active runtime publication cannot drift from configured closure digest."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock

import pytest

import astral_project.runtime.installer as installer
from astral_project.core.errors import AstralError
from astral_project.runtime.closure import (
    RuntimeInput,
    RuntimeManifestV1,
    generated_identity_inputs,
)
from astral_project.runtime.installer import (
    install_active_runtime_closure,
    load_active_runtime_closure,
)


def _manifest(tmp_path: Path) -> RuntimeManifestV1:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for name, content, mode in (("ld.so", b"loader", 0o755), ("sftp-server", b"server", 0o755)):
        path = inputs / name
        path.write_bytes(content)
        path.chmod(mode)
    files = [
        RuntimeInput("ld.so", inputs / "ld.so"),
        RuntimeInput("sftp-server", inputs / "sftp-server"),
        *generated_identity_inputs(inputs / "identity"),
    ]
    return RuntimeManifestV1(
        "x86_64", "glibc", tuple(sorted(files, key=lambda item: item.destination))
    )


def test_active_installer_publishes_and_reopens_exact_verified_closure(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    runtime_root = tmp_path / "runtime"

    closure = install_active_runtime_closure(manifest, runtime_root)
    loaded = load_active_runtime_closure(runtime_root, manifest.digest())

    assert closure.name == manifest.digest()
    assert closure.stat().st_mode & 0o777 == 0o755
    assert loaded.canonical_bytes() == manifest.canonical_bytes()


def test_active_installer_rejects_digest_or_closure_drift(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    runtime_root = tmp_path / "runtime"
    closure = install_active_runtime_closure(manifest, runtime_root)

    with pytest.raises(AstralError):
        load_active_runtime_closure(runtime_root, "0" * 64)
    (closure / "sftp-server").write_bytes(b"tampered")
    with pytest.raises(AstralError):
        load_active_runtime_closure(runtime_root, manifest.digest())


def test_active_loader_rejects_invalid_digest_and_missing_manifest(tmp_path: Path) -> None:
    with pytest.raises(AstralError):
        load_active_runtime_closure(tmp_path, "not-a-digest")
    with pytest.raises(AstralError):
        load_active_runtime_closure(tmp_path, "a" * 64)


def test_install_rejects_builder_digest_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    manifest = _manifest(tmp_path)
    builder = Mock()
    builder.install.return_value = tmp_path / "wrong"
    monkeypatch.setattr(installer, "RuntimeClosureBuilder", lambda: builder)
    with pytest.raises(AstralError):
        install_active_runtime_closure(manifest, tmp_path / "runtime")


def test_atomic_write_translates_os_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "astral_project.runtime.installer.tempfile.mkstemp", Mock(side_effect=OSError("no temp"))
    )
    with pytest.raises(AstralError):
        installer._atomic_write(tmp_path / "manifest", b"data")
