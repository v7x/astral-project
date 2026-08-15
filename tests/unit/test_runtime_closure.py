"""Packet 15C deterministic fixed runtime closure tests."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from astral_project.core.errors import AstralError
from astral_project.runtime.closure import (
    RuntimeClosureBuilder,
    RuntimeInput,
    RuntimeManifestV1,
    discover_sftp_runtime,
    generated_identity_inputs,
    open_verified_runtime_closure,
    verify_runtime_closure,
)
from astral_project.runtime.smoke import run_closure_only_sftp_handshake, run_sftp_handshake


def _manifest(tmp_path: Path) -> RuntimeManifestV1:
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    for name, content, mode in (
        ("ld.so", b"loader", 0o755),
        ("sftp-server", b"server", 0o755),
        ("libc.so.6", b"libc", 0o644),
    ):
        path = inputs / name
        path.write_bytes(content)
        path.chmod(mode)
    files = [
        RuntimeInput("ld.so", inputs / "ld.so"),
        RuntimeInput("sftp-server", inputs / "sftp-server"),
        RuntimeInput("lib/libc.so.6", inputs / "libc.so.6"),
        *generated_identity_inputs(inputs / "identity"),
    ]
    return RuntimeManifestV1(
        "x86_64", "glibc-2.39", tuple(sorted(files, key=lambda item: item.destination))
    )


def test_runtime_closure_is_deterministic_verified_and_content_addressed(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    root = RuntimeClosureBuilder().install(manifest, tmp_path / "runtime")

    assert root.name == manifest.digest()
    assert (root / "ld.so").read_bytes() == b"loader"
    assert (root / "manifest.toml").read_bytes() == manifest.toml_bytes()
    assert (root / "etc/passwd").read_text(encoding="ascii").startswith("aspr:")
    assert RuntimeClosureBuilder().install(manifest, tmp_path / "runtime") == root


def test_runtime_open_returns_descriptor_for_verified_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _manifest(tmp_path)
    root = RuntimeClosureBuilder().install(manifest, tmp_path / "runtime")
    monkeypatch.setattr(
        "astral_project.runtime.closure._require_root_owned_directory", lambda *_: None
    )

    descriptor = open_verified_runtime_closure(root.parent, manifest)
    try:
        assert os.fstat(descriptor).st_ino == root.stat().st_ino
    finally:
        os.close(descriptor)


def test_runtime_open_translates_open_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _manifest(tmp_path)
    root = RuntimeClosureBuilder().install(manifest, tmp_path / "runtime")
    monkeypatch.setattr(
        "astral_project.runtime.closure._require_root_owned_directory", lambda *_: None
    )
    monkeypatch.setattr(
        "astral_project.runtime.closure.os.open",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("open")),
    )
    with pytest.raises(AstralError):
        open_verified_runtime_closure(root.parent, manifest)


def test_runtime_discovery_uses_fixed_system_tools_and_explicit_dependencies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    server, loader, library = source / "sftp-server", source / "ld.so", source / "libc.so.6"
    for path in (server, loader, library):
        path.write_bytes(path.name.encode("ascii"))

    def run(arguments: list[str], **_: object) -> object:
        assert arguments[:4] == ["/usr/bin/readelf", "--wide", "--program-headers", "--dynamic"]
        return type(
            "Result",
            (),
            {
                "stdout": (
                    f"      [Requesting program interpreter: {loader}]\n"
                    " 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]\n"
                )
            },
        )()

    monkeypatch.setattr("astral_project.runtime.closure.subprocess.run", run)
    manifest = discover_sftp_runtime(
        server,
        generated_directory=tmp_path / "identity",
        architecture="x86_64",
        libc="2.39",
        library_roots=(source,),
    )

    assert [item.destination for item in manifest.files] == [
        "etc/group",
        "etc/nsswitch.conf",
        "etc/passwd",
        "ld.so",
        "lib/libc.so.6",
        "sftp-server",
    ]


def test_fixed_loader_reaches_sftp_handshake_with_installed_ubuntu_runtime(tmp_path: Path) -> None:
    server = Path("/usr/lib/openssh/sftp-server")
    if not server.exists():
        pytest.skip("Ubuntu sftp-server is not installed")
    manifest = discover_sftp_runtime(server, generated_directory=tmp_path / "identity")
    runtime = RuntimeClosureBuilder().install(manifest, tmp_path / "runtime")

    assert run_sftp_handshake(runtime) >= 3


def test_closure_only_handshake_when_user_namespaces_are_available(tmp_path: Path) -> None:
    server = Path("/usr/lib/openssh/sftp-server")
    if not server.exists():
        pytest.skip("Ubuntu sftp-server is not installed")
    capability = subprocess.run(
        ["/usr/bin/unshare", "--user", "--map-root-user", "--fork", "true"],
        check=False,
        capture_output=True,
    )
    if capability.returncode != 0:
        pytest.skip("host policy denies disposable user namespace")
    manifest = discover_sftp_runtime(server, generated_directory=tmp_path / "identity")
    runtime = RuntimeClosureBuilder().install(manifest, tmp_path / "runtime")

    assert run_closure_only_sftp_handshake(runtime) >= 3


def test_runtime_input_and_manifest_reject_invalid_metadata(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"data")
    with pytest.raises(AstralError):
        RuntimeInput("../escape", source)
    valid = _manifest(tmp_path)
    with pytest.raises(AstralError):
        RuntimeManifestV1("", "glibc", valid.files)
    with pytest.raises(AstralError):
        RuntimeManifestV1("x86_64", "glibc", tuple(reversed(valid.files)))
    with pytest.raises(AstralError):
        RuntimeManifestV1.from_cbor(b"bad", closure_root=tmp_path)


def test_runtime_discovery_rejects_malformed_elf_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"data")
    monkeypatch.setattr(
        "astral_project.runtime.closure.subprocess.run",
        lambda *_args, **_kwargs: type("Result", (), {"stdout": "(RPATH) bad"})(),
    )
    with pytest.raises(AstralError):
        discover_sftp_runtime(
            source, generated_directory=tmp_path / "identity", library_roots=(tmp_path,)
        )


def test_runtime_library_resolution_and_ubuntu_probe_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import astral_project.runtime.closure as closure

    with pytest.raises(AstralError):
        closure._resolve_needed_libraries(("lib.so",), ())
    monkeypatch.setattr(
        "astral_project.runtime.closure.subprocess.run",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError()),
    )
    with pytest.raises(AstralError):
        closure.ubuntu_library_roots()


def test_runtime_closure_rejects_corrupt_manifests_and_copy_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    manifest = _manifest(tmp_path)
    root = RuntimeClosureBuilder().install(manifest, tmp_path / "runtime")
    cbor = root / "manifest.cbor"
    original = cbor.read_bytes()
    cbor.write_bytes(b"bad")
    with pytest.raises(AstralError):
        verify_runtime_closure(root, manifest)
    cbor.write_bytes(original)
    toml = root / "manifest.toml"
    original_toml = toml.read_bytes()
    toml.write_bytes(b"bad")
    with pytest.raises(AstralError):
        verify_runtime_closure(root, manifest)
    toml.write_bytes(original_toml)
    monkeypatch.setattr(
        "astral_project.runtime.closure._copy_verified",
        lambda *_args: (_ for _ in ()).throw(OSError("copy")),
    )
    with pytest.raises(OSError):
        RuntimeClosureBuilder().install(manifest, tmp_path / "other-runtime")


def test_runtime_closure_rejects_unexplained_or_modified_file(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    root = RuntimeClosureBuilder().install(manifest, tmp_path / "runtime")
    (root / "extra").write_text("bad", encoding="ascii")

    with pytest.raises(AstralError):
        verify_runtime_closure(root, manifest)
