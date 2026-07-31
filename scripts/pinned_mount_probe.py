#!/usr/bin/env python3
"""Packet 13 rootless descriptor-pinned mount capability gate."""

from __future__ import annotations

import argparse
import errno
import json
import os
import platform
import subprocess
import sys
import tempfile
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import Literal, TypedDict, cast

from astral_project.server import linux
from astral_project.server.path_resolver import ResolvedSource, TrustedRoot, resolve_source

CLONE_NEWNS = 0x00020000
CLONE_NEWUSER = 0x10000000
ResultKind = Literal["passed", "failed", "unsupported", "inconclusive"]
StageResult = dict[str, object]
_STAGE_FAILED = object()
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


class BackendResult(TypedDict):
    backend: str
    reason: str | None
    result: ResultKind
    stages: list[StageResult]


class Probe:
    def __init__(self) -> None:
        self.stages: list[StageResult] = []

    def run(
        self,
        stage: str,
        operation: str,
        action: Callable[[], object],
        *,
        syscall: str | None = None,
        flags: str | None = None,
    ) -> object:
        try:
            value = action()
        except Exception as error:
            self.stages.append(_failure(stage, operation, error, syscall=syscall, flags=flags))
            return _STAGE_FAILED
        self.stages.append(_success(stage, operation, syscall=syscall, flags=flags))
        return value

    def skip_missing(self) -> None:
        reported = {str(item["stage"]) for item in self.stages}
        for stage in EXPECTED_STAGES:
            if stage not in reported:
                self.stages.append(
                    {
                        "errno": None,
                        "evidence": "skipped because prerequisite stage did not pass",
                        "flags": None,
                        "operation": stage,
                        "stage": stage,
                        "status": "skipped",
                        "syscall": None,
                    }
                )


def _success(
    stage: str, operation: str, *, syscall: str | None = None, flags: str | None = None
) -> StageResult:
    return {
        "errno": None,
        "evidence": "completed",
        "flags": flags,
        "operation": operation,
        "stage": stage,
        "status": "passed",
        "syscall": syscall,
    }


def _failure(
    stage: str,
    operation: str,
    error: Exception,
    *,
    syscall: str | None = None,
    flags: str | None = None,
) -> StageResult:
    syscall_error = _find_syscall_error(error)
    return {
        "errno": _find_errno(error),
        "evidence": str(error),
        "flags": syscall_error.flags if syscall_error else flags,
        "operation": operation,
        "stage": stage,
        "status": "failed",
        "syscall": syscall_error.syscall if syscall_error else syscall or operation,
    }


def _find_syscall_error(error: Exception) -> linux.LinuxSyscallError | None:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, linux.LinuxSyscallError):
            return current
        current = current.__cause__
    return None


def _find_errno(error: Exception) -> int | None:
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, OSError):
            return current.errno
        current = current.__cause__
    return None


def _write_identity_map(proc: Path, parent_uid: int, parent_gid: int) -> None:
    """Write one bounded map using creator identity captured before unshare."""
    with suppress(FileNotFoundError):
        (proc / "setgroups").write_text("deny\n", encoding="ascii")
    (proc / "uid_map").write_text(f"0 {parent_uid} 1\n", encoding="ascii")
    (proc / "gid_map").write_text(f"0 {parent_gid} 1\n", encoding="ascii")


def _workspace() -> tuple[Path, Path, Path]:
    workspace = Path(tempfile.mkdtemp(prefix="aspr-pinned-mount-"))
    root, source, staging = workspace / "root", workspace / "root" / "source", workspace / "staging"
    root.mkdir()
    source.mkdir()
    staging.mkdir()
    (source / "original.txt").write_text("original\n", encoding="utf-8")
    return root, source, staging


def _mount_stages(probe: Probe, root: Path, source: Path, staging: Path) -> None:
    if (
        probe.run(
            "mount_namespace_creation",
            "unshare",
            lambda: os.unshare(CLONE_NEWNS),
            syscall="unshare",
            flags=f"flags=0x{CLONE_NEWNS:x}",
        )
        is _STAGE_FAILED
    ):
        return
    if (
        probe.run(
            "mount_propagation_privatization",
            "mount",
            linux.make_private_mount_namespace,
            syscall="mount",
            flags=f"flags=0x{linux.MS_REC | linux.MS_PRIVATE:x}",
        )
        is _STAGE_FAILED
    ):
        return
    trusted_root = probe.run(
        "trusted_root_open",
        "TrustedRoot.open",
        lambda: TrustedRoot.open(str(root)),
        syscall="open",
        flags="O_PATH|O_CLOEXEC|O_NOFOLLOW|O_DIRECTORY",
    )
    if trusted_root is _STAGE_FAILED or not isinstance(trusted_root, TrustedRoot):
        return
    try:
        resolved = probe.run(
            "source_resolution",
            "resolve_source",
            lambda: resolve_source(trusted_root, str(source)),
            syscall="openat2",
            flags="O_PATH|O_CLOEXEC|O_NOFOLLOW;RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_SYMLINKS",
        )
        if resolved is _STAGE_FAILED or not isinstance(resolved, ResolvedSource):
            return
        try:
            target = staging / "directory"
            target.mkdir()
            original = root / "original-source"
            os.rename(source, original)
            source.mkdir()
            (source / "original.txt").write_text("attacker\n", encoding="utf-8")
            mount_fd = probe.run(
                "open_tree",
                "open_tree",
                lambda: linux.clone_mount(resolved.descriptor),
                syscall="open_tree",
                flags=(
                    "flags=0x"
                    f"{linux.OPEN_TREE_CLONE | linux.OPEN_TREE_CLOEXEC | linux.AT_EMPTY_PATH:x}"
                ),
            )
            if mount_fd is _STAGE_FAILED or not isinstance(mount_fd, int):
                return
            try:
                if (
                    probe.run(
                        "mount_setattr",
                        "mount_setattr",
                        lambda: linux.make_mount_read_only(mount_fd),
                        syscall="mount_setattr",
                        flags=f"flags=0x{linux.AT_EMPTY_PATH:x},attr_set=0x{linux.MOUNT_ATTR_RDONLY:x}",
                    )
                    is _STAGE_FAILED
                ):
                    return
                if (
                    probe.run(
                        "move_mount",
                        "move_mount",
                        lambda: linux.attach_mount(mount_fd, os.fsencode(target)),
                        syscall="move_mount",
                        flags=f"flags=0x{linux.MOVE_MOUNT_F_EMPTY_PATH:x}",
                    )
                    is _STAGE_FAILED
                ):
                    return
            finally:
                os.close(mount_fd)
            _verify_directory(target)
            probe.stages.append(_success("invariant_verification", "verify_pinned_read_only_mount"))
        except Exception as error:
            probe.stages.append(
                _failure("invariant_verification", "verify_pinned_read_only_mount", error)
            )
        finally:
            resolved.close()
    finally:
        trusted_root.close()


def _verify_directory(target: Path) -> None:
    if (target / "original.txt").read_text(encoding="utf-8") != "original\n":
        raise RuntimeError("attached mount was reopened from replacement pathname")
    try:
        (target / "write-denied.txt").write_text("no\n", encoding="utf-8")
    except OSError as error:
        if error.errno != errno.EROFS:
            raise RuntimeError(f"read-only mount returned errno {error.errno}") from error
    else:
        raise RuntimeError("read-only mount accepted write")


def _backend_result(backend: str, probe: Probe) -> BackendResult:
    probe.skip_missing()
    failed = next((item for item in probe.stages if item["status"] == "failed"), None)
    if failed is None:
        return {"backend": backend, "reason": None, "result": "passed", "stages": probe.stages}
    stage, error_number = failed["stage"], failed["errno"]
    if (
        backend == "direct_unprofiled_python"
        and stage == "uid_gid_map"
        and error_number in {errno.EACCES, errno.EPERM}
    ):
        return {
            "backend": backend,
            "reason": "apparmor_denied_identity_map",
            "result": "unsupported",
            "stages": probe.stages,
        }
    if stage in {
        "user_namespace_creation",
        "uid_gid_map",
        "mount_namespace_creation",
        "open_tree",
        "mount_setattr",
        "move_mount",
    } and error_number in {errno.EACCES, errno.EPERM, errno.ENOSYS, errno.EOPNOTSUPP}:
        return {
            "backend": backend,
            "reason": "kernel_or_host_policy_denied",
            "result": "unsupported",
            "stages": probe.stages,
        }
    if stage == "invariant_verification":
        return {
            "backend": backend,
            "reason": "mount_security_invariant_violated",
            "result": "failed",
            "stages": probe.stages,
        }
    return {
        "backend": backend,
        "reason": "unknown_environmental_failure",
        "result": "inconclusive",
        "stages": probe.stages,
    }


def _direct_child() -> BackendResult:
    probe = Probe()
    parent_uid, parent_gid = os.getuid(), os.getgid()
    if (
        probe.run(
            "user_namespace_creation",
            "unshare",
            lambda: os.unshare(CLONE_NEWUSER),
            syscall="unshare",
            flags=f"flags=0x{CLONE_NEWUSER:x}",
        )
        is _STAGE_FAILED
    ):
        return _backend_result("direct_unprofiled_python", probe)
    if (
        probe.run(
            "uid_gid_map",
            "write_uid_gid_map",
            lambda: _write_identity_map(Path("/proc/self"), parent_uid, parent_gid),
            syscall="write",
            flags="paths=/proc/self/setgroups,/uid_map,/gid_map",
        )
        is _STAGE_FAILED
    ):
        return _backend_result("direct_unprofiled_python", probe)
    probe.stages.append(
        {
            "errno": None,
            "evidence": "ordinary Python obtained namespace setup authority",
            "flags": None,
            "operation": "negative_control",
            "stage": "invariant_verification",
            "status": "failed",
            "syscall": None,
        }
    )
    return _backend_result("direct_unprofiled_python", probe)


def _rootless_child(
    root: Path, source: Path, staging: Path, ready_fd: int, continue_fd: int
) -> BackendResult:
    probe = Probe()
    if (
        probe.run(
            "user_namespace_creation",
            "unshare",
            lambda: os.unshare(CLONE_NEWUSER),
            syscall="unshare",
            flags=f"flags=0x{CLONE_NEWUSER:x}",
        )
        is _STAGE_FAILED
    ):
        return _backend_result("rootless_parent_mapped_python", probe)
    os.write(ready_fd, b"R")
    if os.read(continue_fd, 1) != b"G":
        return _backend_result("rootless_parent_mapped_python", probe)
    probe.stages.append(
        _success(
            "uid_gid_map",
            "parent_write_uid_gid_map",
            syscall="write",
            flags="paths=/proc/<child-pid>/setgroups,/uid_map,/gid_map",
        )
    )
    _mount_stages(probe, root, source, staging)
    return _backend_result("rootless_parent_mapped_python", probe)


def _run_rootless() -> BackendResult:
    parent_uid, parent_gid = os.getuid(), os.getgid()
    root, source, staging = _workspace()
    ready_r, ready_w = os.pipe()
    continue_r, continue_w = os.pipe()
    command = [
        sys.executable,
        __file__,
        "--rootless-child",
        str(root),
        str(source),
        str(staging),
        str(ready_w),
        str(continue_r),
    ]
    child = subprocess.Popen(
        command, pass_fds=(ready_w, continue_r), stdout=subprocess.PIPE, text=True
    )
    os.close(ready_w)
    os.close(continue_r)
    try:
        if os.read(ready_r, 1) != b"R":
            stdout, _ = child.communicate(timeout=10)
            return cast(BackendResult, json.loads(stdout))
        map_probe = Probe()
        if (
            map_probe.run(
                "uid_gid_map",
                "parent_write_uid_gid_map",
                lambda: _write_identity_map(Path("/proc") / str(child.pid), parent_uid, parent_gid),
                syscall="write",
                flags="paths=/proc/<child-pid>/setgroups,/uid_map,/gid_map",
            )
            is _STAGE_FAILED
        ):
            child.terminate()
            child.wait(timeout=10)
            return _backend_result("rootless_parent_mapped_python", map_probe)
        os.write(continue_w, b"G")
        stdout, _ = child.communicate(timeout=30)
        return cast(BackendResult, json.loads(stdout))
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError) as error:
        child.kill()
        child.wait()
        return {
            "backend": "rootless_parent_mapped_python",
            "reason": f"rootless_control_failure:{error}",
            "result": "inconclusive",
            "stages": [],
        }
    finally:
        os.close(ready_r)
        os.close(continue_w)


def _run_direct() -> BackendResult:
    result = subprocess.run(
        [sys.executable, __file__, "--direct-child"], capture_output=True, check=False, text=True
    )
    if result.returncode:
        return {
            "backend": "direct_unprofiled_python",
            "reason": "direct_control_execution_failed",
            "result": "inconclusive",
            "stages": [],
        }
    return cast(BackendResult, json.loads(result.stdout))


def _evidence() -> dict[str, object]:
    return {
        "apparmor_userns": {
            "apparmor_restrict_unprivileged_userns": _read_text(
                "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
            )
        },
        "distro": _read_text("/etc/os-release") or "unknown",
        "kernel": platform.release(),
    }


def _read_text(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend", choices=("direct", "rootless"))
    parser.add_argument("--direct-child", action="store_true")
    parser.add_argument("--rootless-child", nargs=5)
    arguments = parser.parse_args()
    if arguments.direct_child:
        print(json.dumps(_direct_child(), sort_keys=True))
        return
    if arguments.rootless_child:
        root, source, staging, ready_fd, continue_fd = arguments.rootless_child
        print(
            json.dumps(
                _rootless_child(
                    Path(root), Path(source), Path(staging), int(ready_fd), int(continue_fd)
                ),
                sort_keys=True,
            )
        )
        return
    direct = _run_direct() if arguments.backend != "rootless" else None
    rootless = _run_rootless() if arguments.backend != "direct" else None
    if arguments.backend == "direct":
        assert direct is not None
        payload: dict[str, object] = {**_evidence(), **direct}
    elif arguments.backend == "rootless":
        assert rootless is not None
        payload = {**_evidence(), **rootless}
    else:
        assert direct is not None and rootless is not None
        passed = (
            direct["result"] == "unsupported"
            and direct["reason"] == "apparmor_denied_identity_map"
            and rootless["result"] == "passed"
        )
        payload = {
            **_evidence(),
            "direct_control": direct,
            "rootless_gate": rootless,
            "result": "passed" if passed else rootless["result"],
        }
    print(json.dumps(payload, sort_keys=True))


if __name__ == "__main__":
    main()
