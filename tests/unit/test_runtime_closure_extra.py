"""Runtime closure validation edge cases."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from astral_project.core.errors import AstralError
from astral_project.crypto.cbor import canonical_dumps
from astral_project.runtime import closure


def _manifest(tmp_path: Path) -> closure.RuntimeManifestV1:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    files = []
    for name in ("ld.so", "sftp-server"):
        path = inputs / name
        path.write_bytes(name.encode())
        files.append(closure.RuntimeInput(name, path))
    files.extend(closure.generated_identity_inputs(inputs / "identity"))
    return closure.RuntimeManifestV1(
        "x86_64", "glibc", tuple(sorted(files, key=lambda item: item.destination))
    )


def test_runtime_metadata_rejects_invalid_digest_mode_resolution(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"x")
    for kwargs in (
        {"sha256": b"short"},
        {"mode": "bad"},
        {"mode": True},
        {"resolution": "relative"},
    ):
        with pytest.raises(AstralError):
            closure.RuntimeInput("file", source, **kwargs)


def test_runtime_manifest_rejects_missing_required_file(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"x")
    files = tuple(closure.RuntimeInput(name, source) for name in ("ld.so", "sftp-server"))
    with pytest.raises(AstralError):
        closure.RuntimeManifestV1("x86_64", "glibc", files)


def test_runtime_manifest_rejects_bad_cbor_entries(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    payload = manifest.payload()
    payload["version"] = 2
    with pytest.raises(AstralError):
        closure.RuntimeManifestV1.from_cbor(canonical_dumps(payload), closure_root=tmp_path)
    payload = manifest.payload()
    payload["files"] = ["bad"]
    with pytest.raises(AstralError):
        closure.RuntimeManifestV1.from_cbor(canonical_dumps(payload), closure_root=tmp_path)
    payload = manifest.payload()
    payload["files"][0]["destination"] = "../escape"  # type: ignore[index, call-overload]
    with pytest.raises(AstralError):
        closure.RuntimeManifestV1.from_cbor(canonical_dumps(payload), closure_root=tmp_path)


def test_runtime_multiarch_and_dependency_root_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "astral_project.runtime.closure.subprocess.run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("dpkg")),
    )
    with pytest.raises(AstralError):
        closure.ubuntu_library_roots()
    monkeypatch.setattr(
        "astral_project.runtime.closure.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="bad/path\n"),
    )
    with pytest.raises(AstralError):
        closure.ubuntu_library_roots()
    monkeypatch.setattr(
        "astral_project.runtime.closure.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="x86_64-linux-gnu\n"),
    )
    assert closure.ubuntu_library_roots() == (
        Path("/lib/x86_64-linux-gnu"),
        Path("/usr/lib/x86_64-linux-gnu"),
        Path("/lib64"),
    )
    with pytest.raises(AstralError):
        closure._resolve_needed_libraries(("missing.so",), ())


def test_runtime_dependency_and_elf_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "astral_project.runtime.closure.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout="x (NEEDED) malformed"),
    )
    with pytest.raises(AstralError):
        closure._read_elf_metadata(tmp_path / "source")
    monkeypatch.setattr(
        "astral_project.runtime.closure.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=""),
    )
    with pytest.raises(AstralError):
        closure._read_elf_metadata(tmp_path / "source")
    source = tmp_path / "source"
    source.write_bytes(b"x")
    monkeypatch.setattr(
        "astral_project.runtime.closure.subprocess.run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=""),
    )
    with pytest.raises(AstralError):
        closure.discover_sftp_runtime(
            source, generated_directory=tmp_path / "identity", library_roots=(tmp_path,)
        )
    with pytest.raises(AstralError):
        closure._resolve_needed_libraries(("missing.so",), (tmp_path,))
    with pytest.raises(AstralError):
        closure._trusted_regular_file(tmp_path, "directory")


def test_runtime_root_validation_rejects_unsafe_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    details = SimpleNamespace(st_mode=0o40755, st_uid=1)
    monkeypatch.setattr(Path, "lstat", lambda _path: details)
    with pytest.raises(AstralError):
        closure._require_root_owned_directory(tmp_path, "root")
    details = SimpleNamespace(st_mode=0o40755 | 0o002, st_uid=0)
    with pytest.raises(AstralError):
        closure._require_root_owned_directory(tmp_path, "root")


def test_runtime_copy_and_root_validation_errors(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"source")
    item = closure.RuntimeInput("file", source, sha256=b"x" * 32)
    with pytest.raises(AstralError):
        closure._copy_verified(item, tmp_path / "target")
    with pytest.raises(AstralError):
        closure._require_root_owned_directory(tmp_path / "missing", "root")
    manifest = _manifest(tmp_path)
    with pytest.raises(AstralError):
        closure.open_verified_runtime_closure(tmp_path / "missing", manifest)
