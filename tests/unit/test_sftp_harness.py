from __future__ import annotations

from astral_project.sftp.client import SftpAttrs, SftpEntry, SftpExtensions
from astral_project.sftp.harness import DirectSftpAcceptanceHarness


class FakeClient:
    extensions = SftpExtensions({b"supported2": b""})

    def __init__(self) -> None:
        self.reads = 0

    def connect(self) -> int:
        return 3

    def realpath(self, _root: str | bytes) -> bytes:
        return b"/"

    def stat(self, _root: str | bytes, *, follow_symlinks: bool = True) -> SftpAttrs:
        _ = follow_symlinks
        return SftpAttrs(permissions=0o40755)

    def opendir(self, _root: str | bytes) -> bytes:
        return b"h"

    def readdir(self, _handle: bytes) -> list[SftpEntry]:
        self.reads += 1
        return [SftpEntry(b"file", b"file", SftpAttrs(size=1))] if self.reads == 1 else []

    def close(self, _handle: bytes) -> None:
        return None


def test_direct_acceptance_harness_runs_ordered_baseline() -> None:
    report = DirectSftpAcceptanceHarness(FakeClient()).run()
    assert report.version == 3
    assert report.root == b"/"
    assert report.root_entries[0].filename == b"file"
    assert report.operations[0:3] == ("INIT", "VERSION", "REALPATH")
