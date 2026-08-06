"""Active runtime publication cannot drift from configured closure digest."""

from __future__ import annotations

from pathlib import Path

import pytest

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
