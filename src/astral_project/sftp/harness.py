"""Reusable direct packaged-path SFTP acceptance harness."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from astral_project.sftp.client import SftpAttrs, SftpEntry, SftpExtensions
from astral_project.sftp.policy import validate_extensions


@dataclass(frozen=True, slots=True)
class SftpAcceptanceReport:
    """Bounded evidence from one direct SFTP session."""

    version: int
    extensions: frozenset[bytes]
    root: bytes
    root_entries: tuple[SftpEntry, ...]
    operations: tuple[str, ...]


class SftpClientLike(Protocol):
    extensions: SftpExtensions

    def connect(self) -> int: ...

    def realpath(self, root: str | bytes) -> bytes: ...

    def stat(self, root: str | bytes, *, follow_symlinks: bool = True) -> SftpAttrs: ...

    def opendir(self, root: str | bytes) -> bytes: ...

    def readdir(self, handle: bytes) -> list[SftpEntry]: ...

    def close(self, handle: bytes) -> None: ...


class DirectSftpAcceptanceHarness:
    """Run non-destructive INIT, path, metadata, and directory baselines."""

    def __init__(self, client: SftpClientLike) -> None:
        self.client = client

    def run(self, root: str | bytes = "/") -> SftpAcceptanceReport:
        version = self.client.connect()
        extensions = validate_extensions(self.client.extensions)
        canonical = self.client.realpath(root)
        self.client.stat(canonical)
        self.client.stat(canonical, follow_symlinks=False)
        handle = self.client.opendir(canonical)
        entries: list[SftpEntry] = []
        try:
            while True:
                batch = self.client.readdir(handle)
                if not batch:
                    break
                entries.extend(batch)
        finally:
            self.client.close(handle)
        return SftpAcceptanceReport(
            version=version,
            extensions=extensions,
            root=canonical,
            root_entries=tuple(entries),
            operations=(
                "INIT",
                "VERSION",
                "REALPATH",
                "STAT",
                "LSTAT",
                "OPENDIR",
                "READDIR",
                "CLOSE",
            ),
        )
