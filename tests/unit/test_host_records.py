from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import pytest

from astral_project.core.errors import AstralError, ErrorCode
from astral_project.host.records import (
    Capability,
    CapabilityStatus,
    HostRecord,
    ProbeReport,
    _string,
    _toml_string,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "hosts"


def test_host_record_string_helpers_cover_control_escapes() -> None:
    assert _toml_string('\\"\n\r\t\x01') == '"\\\\\\"\\n\\r\\t\\u0001"'
    with pytest.raises(AstralError):
        _string({"field": ""}, "field")
    with pytest.raises(AstralError):
        _string({"field": 1}, "field")


def test_supported_and_restricted_fixtures_round_trip(tmp_path: Path) -> None:
    for name in ("supported.toml", "restricted-hpc.toml"):
        record = HostRecord.load(FIXTURES / name)
        path = tmp_path / name
        path.write_text(record.to_toml())
        assert HostRecord.load(path) == record
    assert (
        HostRecord.load(FIXTURES / "restricted-hpc.toml").probe.capabilities[1].status
        is CapabilityStatus.UNSUPPORTED
    )


def test_host_record_toml_escapes_dynamic_values(tmp_path: Path) -> None:
    record = HostRecord.load(FIXTURES / "supported.toml")
    first = replace(
        record.probe.capabilities[0], reason='quote " slash \\ newline\n', evidence="é\ttext"
    )
    escaped = replace(
        record, probe=replace(record.probe, capabilities=(first, *record.probe.capabilities[1:]))
    )
    path = tmp_path / "escaped.toml"
    path.write_text(escaped.to_toml(), encoding="utf-8")

    assert HostRecord.load(path) == escaped


@pytest.mark.parametrize(
    "data",
    [
        {},
        {
            "version": 2,
            "host_id": "123e4567-e89b-42d3-a456-426614174000",
            "ssh_host_fingerprint": "x",
            "probe": {},
        },
    ],
)
def test_host_record_strict_parse_fails_closed(tmp_path: Path, data: dict[str, object]) -> None:
    path = tmp_path / "record.toml"
    path.write_text("version = 2\n")
    with pytest.raises(AstralError) as error:
        HostRecord.load(path)
    assert error.value.code is ErrorCode.HOST_RECORD
    with pytest.raises(AstralError):
        HostRecord.load(tmp_path / "missing.toml")
    path.write_text(
        "version = 1\n"
        'host_id = "123e4567-e89b-42d3-a456-426614174000"\n'
        'ssh_host_fingerprint = "x"\n'
        'probe = "bad"\n'
    )
    with pytest.raises(AstralError):
        HostRecord.load(path)


def test_probe_requires_complete_unique_capabilities() -> None:
    record = HostRecord.load(FIXTURES / "supported.toml")
    capability = Capability("bubblewrap", CapabilityStatus.SUPPORTED, "yes", "probe")
    with pytest.raises(AstralError):
        ProbeReport("Linux", "x86_64", "alice", "relative", record.probe.capabilities)
    with pytest.raises(AstralError):
        ProbeReport("Linux", "x86_64", "alice", "/home/alice", (capability,))
    with pytest.raises(AstralError):
        Capability("", CapabilityStatus.SUPPORTED, "yes", "probe")
    with pytest.raises(AstralError):
        HostRecord(record.host_id, "", record.probe)
    assert ProbeReport.from_dict(record.probe.to_dict()) == record.probe
    invalid = record.probe.to_dict()
    invalid["os"] = ""
    with pytest.raises(AstralError):
        ProbeReport.from_dict(invalid)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda data: data.clear(),
        lambda data: data.update(version=2),
        lambda data: data.update(capabilities=[{}]),
        lambda data: data.update(
            capabilities=[{"name": "x", "status": "bad", "reason": "r", "evidence": "e"}]
        ),
    ],
)
def test_probe_strict_field_and_status_rejection(
    mutate: Callable[[dict[str, object]], None],
) -> None:
    data = HostRecord.load(FIXTURES / "supported.toml").probe.to_dict()
    mutate(data)
    with pytest.raises(AstralError):
        ProbeReport.from_dict(data)
