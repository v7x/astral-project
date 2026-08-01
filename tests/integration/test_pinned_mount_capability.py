"""Packet 13 staged capability-probe result contract."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parents[2]
PROBE = PROJECT_ROOT / "scripts" / "pinned_mount_probe.py"
EXPECTED_STAGES = (
    "user_namespace_creation",
    "uid_gid_map",
    "mount_namespace_creation",
    "mount_propagation_privatization",
    "trusted_root_open",
    "source_resolution",
    "open_tree",
    "mount_setattr",
    "move_mount",
    "invariant_verification",
)


def test_pinned_mount_probe_reports_each_required_stage() -> None:
    result = subprocess.run(
        [sys.executable, str(PROBE)],
        capture_output=True,
        check=False,
        cwd=PROJECT_ROOT,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["result"] in {"passed", "unsupported", "failed", "inconclusive"}
    assert set(payload) >= {"direct_control", "rootless_gate"}
    direct = payload["direct_control"]
    assert direct["backend"] == "direct_unprofiled_python"
    assert tuple(item["stage"] for item in direct["stages"]) == EXPECTED_STAGES
    for stage in direct["stages"]:
        assert set(stage) == {
            "errno",
            "evidence",
            "flags",
            "operation",
            "stage",
            "status",
            "syscall",
        }
        assert stage["status"] in {"passed", "failed", "skipped"}
    assert set(payload["apparmor_userns"]) == {"apparmor_restrict_unprivileged_userns"}
    assert payload["rootless_gate"]["backend"] == "rootless_parent_mapped_python"


def test_probe_classifies_ubuntu_identity_map_denial_as_unsupported() -> None:
    spec = importlib.util.spec_from_file_location("pinned_mount_probe", PROBE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    probe = module.Probe()
    probe.stages.append(
        {
            "errno": 13,
            "evidence": "[Errno 13] Permission denied: '/proc/self/setgroups'",
            "flags": "paths=/proc/self/setgroups,/proc/self/uid_map,/proc/self/gid_map",
            "operation": "write_uid_gid_map",
            "stage": "uid_gid_map",
            "status": "failed",
            "syscall": "write",
        }
    )

    result = module._backend_result("direct_unprofiled_python", probe)

    assert result["result"] == "unsupported"
    assert result["backend"] == "direct_unprofiled_python"
    assert result["reason"] == "apparmor_denied_identity_map"


@pytest.mark.parametrize(
    ("stage", "error_number", "expected"),
    [
        ("open_tree", 1, "unsupported"),
        ("invariant_verification", None, "failed"),
        ("trusted_root_open", 5, "inconclusive"),
    ],
)
def test_probe_result_kinds_are_distinct(
    stage: str, error_number: int | None, expected: str
) -> None:
    spec = importlib.util.spec_from_file_location("pinned_mount_probe_kinds", PROBE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    probe = module.Probe()
    probe.stages.append(
        {
            "errno": error_number,
            "evidence": "fixture",
            "flags": None,
            "operation": stage,
            "stage": stage,
            "status": "failed",
            "syscall": stage,
        }
    )

    assert module._backend_result("rootless_parent_mapped_python", probe)["result"] == expected


def test_probe_uses_parent_written_maps_and_no_admin_launcher() -> None:
    source = PROBE.read_text(encoding="utf-8")
    assert "--cap-add" not in source
    assert '_write_identity_map(Path("/proc") / str(child.pid)' in source
    assert "parent_uid, parent_gid = os.getuid(), os.getgid()" in source
    assert "aa-exec" not in source
    profile = PROJECT_ROOT / "packaging/apparmor/usr.libexec.astral-project.aspr-broker"
    assert profile.is_file()
    assert "aa-exec" not in profile.read_text(encoding="utf-8")
    assert "deny network" in profile.read_text(encoding="utf-8")
    assert not (PROJECT_ROOT / "packaging/install").exists()
    assert not (PROJECT_ROOT / "packaging/setup").exists()
