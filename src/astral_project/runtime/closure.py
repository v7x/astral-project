"""Deterministic content-addressed runtime closure for fixed `sftp_v1`."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.crypto.cbor import CborValue, canonical_dumps

WORKLOAD_ID = "sftp_v1"
RUNTIME_TARGET = "/.astral-project-runtime"
DEFAULT_LIBRARY_ROOTS = (
    Path("/lib/x86_64-linux-gnu"),
    Path("/usr/lib/x86_64-linux-gnu"),
    Path("/lib64"),
)


@dataclass(frozen=True, slots=True)
class RuntimeInput:
    """Trusted build-time file mapped into fixed runtime destination."""

    destination: str
    source: Path
    generated: bool = False
    sha256: bytes | None = None
    mode: int | None = None
    resolution: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.destination
            or self.destination.startswith("/")
            or "\x00" in self.destination
            or any(part in {"", ".", ".."} for part in self.destination.split("/"))
        ):
            raise _error("runtime destination is invalid")
        object.__setattr__(
            self, "sha256", _digest(self.source) if self.sha256 is None else self.sha256
        )
        object.__setattr__(self, "mode", _mode(self.source) if self.mode is None else self.mode)
        object.__setattr__(
            self,
            "resolution",
            str(self.source.resolve(strict=True)) if self.resolution is None else self.resolution,
        )
        if (
            not isinstance(self.sha256, bytes)
            or len(self.sha256) != 32
            or not isinstance(self.mode, int)
            or not isinstance(self.resolution, str)
            or not self.resolution.startswith("/")
        ):
            raise _error("runtime input digest or mode is invalid")


@dataclass(frozen=True, slots=True)
class RuntimeManifestV1:
    architecture: str
    libc: str
    files: tuple[RuntimeInput, ...]

    def __post_init__(self) -> None:
        if not self.architecture or not self.libc or not self.files:
            raise _error("runtime manifest is incomplete")
        destinations = tuple(item.destination for item in self.files)
        if destinations != tuple(sorted(destinations, key=str.encode)) or len(
            set(destinations)
        ) != len(destinations):
            raise _error("runtime manifest destinations must be unique sorted")
        required = {"ld.so", "sftp-server", "etc/passwd", "etc/group", "etc/nsswitch.conf"}
        if not required.issubset(destinations):
            raise _error("runtime manifest lacks required fixed files")

    def payload(self) -> dict[str, CborValue]:
        return {
            "architecture": self.architecture,
            "files": [
                {
                    "destination": item.destination,
                    "generated": item.generated,
                    "mode": item.mode,
                    "resolution": item.resolution,
                    "sha256": item.sha256,
                }
                for item in self.files
            ],
            "libc": self.libc,
            "runtime_target": RUNTIME_TARGET,
            "version": 1,
            "workload_id": WORKLOAD_ID,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_dumps(self.payload())

    def toml_bytes(self) -> bytes:
        lines = [
            'architecture = "' + _toml_string(self.architecture) + '"',
            'libc = "' + _toml_string(self.libc) + '"',
            'runtime_target = "' + RUNTIME_TARGET + '"',
            "version = 1",
            'workload_id = "' + WORKLOAD_ID + '"',
        ]
        for item in self.files:
            assert item.sha256 is not None
            lines.extend(
                [
                    "",
                    "[[files]]",
                    'destination = "' + _toml_string(item.destination) + '"',
                    f"generated = {str(item.generated).lower()}",
                    f"mode = {item.mode}",
                    'resolution = "' + _toml_string(item.resolution or "") + '"',
                    'sha256 = "' + item.sha256.hex() + '"',
                ]
            )
        return ("\n".join(lines) + "\n").encode("utf-8")

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def discover_sftp_runtime(
    sftp_server: Path,
    *,
    generated_directory: Path,
    architecture: str | None = None,
    libc: str | None = None,
    library_roots: tuple[Path, ...] = DEFAULT_LIBRARY_ROOTS,
) -> RuntimeManifestV1:
    """Inspect ELF metadata without executing any runtime input."""
    server = _trusted_regular_file(sftp_server, "sftp-server")
    loader, needed = _read_elf_metadata(server)
    libraries = _resolve_needed_libraries(needed, library_roots)
    inputs = [RuntimeInput("ld.so", loader), RuntimeInput("sftp-server", server)]
    names: set[str] = set()
    for library in libraries:
        resolved = _trusted_regular_file(library, "shared library")
        if resolved == loader:
            continue
        destination = f"lib/{resolved.name}"
        if destination in names:
            raise _error("runtime library basename collision")
        names.add(destination)
        inputs.append(RuntimeInput(destination, resolved))
    inputs.extend(generated_identity_inputs(generated_directory))
    return RuntimeManifestV1(
        architecture=platform.machine() if architecture is None else architecture,
        libc=platform.libc_ver()[1] if libc is None else libc,
        files=tuple(sorted(inputs, key=lambda item: item.destination)),
    )


class RuntimeClosureBuilder:
    """Copy only explicit verified inputs into immutable content-addressed closure."""

    def install(self, manifest: RuntimeManifestV1, runtime_root: Path) -> Path:
        digest = manifest.digest()
        destination = runtime_root / digest
        if destination.exists():
            verify_runtime_closure(destination, manifest)
            return destination
        runtime_root.mkdir(mode=0o755, parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f".{digest}.", dir=runtime_root))
        try:
            for item in manifest.files:
                target = temporary / item.destination
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                _copy_verified(item, target)
            (temporary / "manifest.cbor").write_bytes(manifest.canonical_bytes())
            (temporary / "manifest.toml").write_bytes(manifest.toml_bytes())
            _fsync_tree(temporary)
            os.replace(temporary, destination)
            _fsync_directory(runtime_root)
        except Exception:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        verify_runtime_closure(destination, manifest)
        return destination


def verify_runtime_closure(root: Path, manifest: RuntimeManifestV1) -> None:
    expected = {"manifest.cbor", "manifest.toml", *(item.destination for item in manifest.files)}
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if actual != expected:
        raise _error("runtime closure has missing or unexplained files")
    if (root / "manifest.cbor").read_bytes() != manifest.canonical_bytes():
        raise _error("runtime closure CBOR manifest bytes differ")
    if (root / "manifest.toml").read_bytes() != manifest.toml_bytes():
        raise _error("runtime closure TOML manifest bytes differ")
    for item in manifest.files:
        target = root / item.destination
        if _digest(target) != item.sha256 or _mode(target) != item.mode:
            raise _error("runtime closure file digest or mode differs")


def generated_identity_inputs(directory: Path) -> tuple[RuntimeInput, ...]:
    """Generate only files needed by fixed workload; never copy host `/etc`."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = {
        "passwd": b"aspr:x:0:0:Astral Project SFTP:/:/usr/sbin/nologin\n",
        "group": b"aspr:x:0:\n",
        "nsswitch.conf": b"passwd: files\ngroup: files\nshadow: files\n",
    }
    result: list[RuntimeInput] = []
    for name, content in files.items():
        path = directory / name
        path.write_bytes(content)
        os.chmod(path, 0o444)
        result.append(RuntimeInput(f"etc/{name}", path, generated=True))
    return tuple(result)


def _read_elf_metadata(sftp_server: Path) -> tuple[Path, tuple[str, ...]]:
    """Read PT_INTERP and DT_NEEDED with `readelf`; no inspected ELF runs."""
    result = subprocess.run(
        ["/usr/bin/readelf", "--wide", "--program-headers", "--dynamic", str(sftp_server)],
        check=True,
        capture_output=True,
        text=True,
    )
    loader: Path | None = None
    needed: list[str] = []
    marker = "Requesting program interpreter: "
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if marker in line and stripped.endswith("]"):
            loader = _trusted_regular_file(Path(line.split(marker, 1)[1].strip()[:-1]), "loader")
        if "(RPATH)" in stripped or "(RUNPATH)" in stripped:
            raise _error("runtime ELF RPATH or RUNPATH is forbidden")
        if "(NEEDED)" in stripped:
            _, separator, suffix = stripped.partition("Shared library: [")
            if not separator or not suffix.endswith("]"):
                raise _error("readelf emitted malformed DT_NEEDED record")
            name = suffix[:-1]
            if not name or "/" in name or "\x00" in name:
                raise _error("runtime ELF DT_NEEDED name is invalid")
            needed.append(name)
    if loader is None:
        raise _error("sftp-server has no dynamic loader")
    if not needed:
        raise _error("sftp-server has no DT_NEEDED entries")
    return loader, tuple(sorted(set(needed), key=str.encode))


def _resolve_needed_libraries(names: tuple[str, ...], roots: tuple[Path, ...]) -> tuple[Path, ...]:
    if not roots:
        raise _error("runtime library root list is empty")
    resolved: list[Path] = []
    approved = tuple(root.resolve(strict=True) for root in roots)
    for name in names:
        candidate = next((root / name for root in approved if (root / name).is_file()), None)
        if candidate is None:
            raise _error("runtime ELF dependency is unresolved in approved roots")
        library = _trusted_regular_file(candidate, "shared library")
        if not any(library == root or root in library.parents for root in approved):
            raise _error("runtime library resolves outside approved roots")
        resolved.append(library)
    return tuple(resolved)


def _trusted_regular_file(path: Path, name: str) -> Path:
    resolved = path.resolve(strict=True)
    if not stat.S_ISREG(resolved.stat().st_mode):
        raise _error(f"{name} is not regular file")
    return resolved


def _toml_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _copy_verified(item: RuntimeInput, target: Path) -> None:
    source = item.source
    details = source.lstat()
    if not stat.S_ISREG(details.st_mode):
        raise _error("runtime input is not regular file")
    with source.open("rb") as reader, target.open("xb") as writer:
        shutil.copyfileobj(reader, writer)
        writer.flush()
        os.fsync(writer.fileno())
    os.chmod(target, stat.S_IMODE(details.st_mode))
    if _digest(target) != item.sha256 or _mode(target) != item.mode:
        raise _error("runtime input changed while copied")


def _digest(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.digest()


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def _fsync_tree(root: Path) -> None:
    for path in sorted(root.rglob("*"), reverse=True):
        if path.is_file():
            descriptor = os.open(path, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    _fsync_directory(root)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _error(message: str) -> AstralError:
    return AstralError(
        code=ErrorCode.CONFIG_INVALID_PATH,
        message=message,
        security_result="runtime closure was rejected",
        unsafe_reason="fixed workload may use only verified explicit runtime files",
        next_action="rebuild trusted runtime closure",
    )
