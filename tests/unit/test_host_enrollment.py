from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

import astral_project.host.enrollment as enrollment
from astral_project.core.errors import AstralError, ErrorCode
from astral_project.host.enrollment import (
    ControlFileIdentity,
    RollbackJournal,
    authorized_key_entry,
    enroll,
    verify_host_fingerprint,
)
from astral_project.host.records import CapabilityStatus, HostRecord

FIXTURE = Path(__file__).parents[1] / "fixtures" / "hosts" / "supported.toml"


class Remote:
    def __init__(self, fail: str = "") -> None:
        self.fail = fail
        self.events: list[str] = []

    def install_bundle(self, bundle: bytes, digest: str) -> bool:
        self.events.append("bundle")
        return self.fail != "bundle"

    def remove_bundle(self, digest: str) -> None:
        self.events.append("remove-bundle")

    def install_issuer_key(self, key: bytes) -> bool:
        self.events.append("issuer")
        if self.fail == "issuer":
            raise RuntimeError("issuer")
        return True

    def remove_issuer_key(self, key: bytes) -> None:
        self.events.append("remove-issuer")

    def add_authorized_key(self, path: str, entry: str) -> bool:
        self.events.append("key")
        if self.fail == "key":
            raise RuntimeError("key")
        return True

    def remove_authorized_key(self, path: str, entry: str) -> None:
        self.events.append("remove-key")

    def smoke_test(self) -> None:
        self.events.append("smoke")
        if self.fail == "smoke":
            raise RuntimeError("failed")


def test_restricted_key_and_enrollment_idempotent(tmp_path: Path) -> None:
    entry = authorized_key_entry(b"x" * 32, "transport-1")
    assert entry.startswith(
        'restrict,no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding,command="'
    )
    assert "/usr/libexec/astral-project/aspr-server server ssh-entry" in entry
    remote = Remote()
    result = enroll(
        HostRecord.load(FIXTURE),
        remote,
        bundle=b"bundle",
        issuer_key=b"i" * 32,
        transport_key_id="transport-1",
        private_key_path=tmp_path / "key",
        control_file=ControlFileIdentity(1, "a" * 64, 1),
    )
    assert result.authorized_key.endswith(" aspr-transport-1")
    assert remote.events == ["bundle", "issuer", "key", "smoke"]


@pytest.mark.parametrize("fail", ["issuer", "key", "smoke"])
def test_partial_enrollment_rolls_back(tmp_path: Path, fail: str) -> None:
    remote = Remote(fail)
    with pytest.raises(AstralError) as error:
        enroll(
            HostRecord.load(FIXTURE),
            remote,
            bundle=b"bundle",
            issuer_key=b"i" * 32,
            transport_key_id="id",
            private_key_path=tmp_path / "key",
            control_file=ControlFileIdentity(1, "a" * 64, 1),
        )
    assert error.value.code is ErrorCode.HOST_ENROLLMENT
    assert any(event.startswith("remove-") for event in remote.events)
    assert not (tmp_path / "key").exists()


def test_enrollment_refuses_existing_key_without_remote_mutation(tmp_path: Path) -> None:
    path = tmp_path / "key"
    path.write_bytes(b"trusted")
    remote = Remote()
    with pytest.raises(AstralError):
        enroll(
            HostRecord.load(FIXTURE),
            remote,
            bundle=b"bundle",
            issuer_key=b"i" * 32,
            transport_key_id="id",
            private_key_path=path,
            control_file=ControlFileIdentity(1, "a" * 64, 1),
        )
    assert remote.events == []
    assert path.read_bytes() == b"trusted"


def test_idempotent_and_rollback_failure_paths(tmp_path: Path) -> None:
    class Existing(Remote):
        def install_bundle(self, bundle: bytes, digest: str) -> bool:
            self.events.append("bundle")
            return False

        def install_issuer_key(self, key: bytes) -> bool:
            self.events.append("issuer")
            return False

        def add_authorized_key(self, path: str, entry: str) -> bool:
            self.events.append("key")
            return False

    remote = Existing()
    enroll(
        HostRecord.load(FIXTURE),
        remote,
        bundle=b"bundle",
        issuer_key=b"i" * 32,
        transport_key_id="id",
        private_key_path=tmp_path / "key",
        control_file=ControlFileIdentity(1, "a" * 64, 1),
    )
    assert remote.events == ["bundle", "issuer", "key", "smoke"]

    with pytest.raises(AstralError):
        enroll(
            HostRecord.load(FIXTURE),
            Remote("smoke"),
            bundle=b"",
            issuer_key=b"i" * 32,
            transport_key_id="id",
            private_key_path=tmp_path / "bad",
            control_file=ControlFileIdentity(1, "a" * 64, 1),
        )


def test_rollback_journal_reports_compensation_failure() -> None:
    journal = RollbackJournal()
    journal.add(lambda: (_ for _ in ()).throw(RuntimeError("cannot remove")))
    with pytest.raises(AstralError) as error:
        journal.rollback()
    assert error.value.code is ErrorCode.HOST_ENROLLMENT


def test_enrollment_reports_incomplete_rollback(tmp_path: Path) -> None:
    class BrokenRemove(Remote):
        def remove_bundle(self, digest: str) -> None:
            raise RuntimeError("remove bundle")

    with pytest.raises(AstralError) as error:
        enroll(
            HostRecord.load(FIXTURE),
            BrokenRemove("smoke"),
            bundle=b"bundle",
            issuer_key=b"i" * 32,
            transport_key_id="id",
            private_key_path=tmp_path / "key",
            control_file=ControlFileIdentity(1, "a" * 64, 1),
        )
    assert error.value.dependency_error == "remove bundle"


@pytest.mark.parametrize("evidence", ["unsupported", "/one;/two"])
def test_enrollment_rejects_ambiguous_or_unsupported_authorized_keys(
    tmp_path: Path, evidence: str
) -> None:
    record = HostRecord.load(FIXTURE)
    capabilities = tuple(
        replace(
            item,
            status=CapabilityStatus.UNSUPPORTED if evidence == "unsupported" else item.status,
            evidence=evidence,
        )
        if item.name == "authorized_keys"
        else item
        for item in record.probe.capabilities
    )
    record = replace(record, probe=replace(record.probe, capabilities=capabilities))
    with pytest.raises(AstralError):
        enroll(
            record,
            Remote(),
            bundle=b"bundle",
            issuer_key=b"i" * 32,
            transport_key_id="id",
            private_key_path=tmp_path / "key",
            control_file=ControlFileIdentity(1, "a" * 64, 1),
        )


def test_remove_new_private_key_handles_missing_and_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    enrollment._remove_new_private_key(tmp_path / "missing")
    monkeypatch.setattr(Path, "unlink", lambda _path: (_ for _ in ()).throw(OSError("no")))
    with pytest.raises(AstralError):
        enrollment._remove_new_private_key(tmp_path / "key")


def test_bad_key_and_control_identity_fail() -> None:
    with pytest.raises(AstralError):
        authorized_key_entry(b"x", "id")
    with pytest.raises(AstralError):
        authorized_key_entry(b"x" * 32, "bad id")
    with pytest.raises(AstralError):
        authorized_key_entry(b"x" * 32, "--option")
    with pytest.raises(AstralError):
        ControlFileIdentity(1, "a" * 64, 2)
    verify_host_fingerprint("SHA256:pinned", "SHA256:pinned")
    with pytest.raises(AstralError):
        verify_host_fingerprint("SHA256:pinned", "SHA256:changed")
