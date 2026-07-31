#!/usr/bin/env python3
"""Packet 10 release gate for rclone external-SSH behavior.

Run once per pinned binary. This is a test harness, never production transport.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import NoReturn

MAX_WAIT_SECONDS = 15
SFTP_SUBSYSTEM_ARGUMENTS = ["-s", "sftp"]


def fail(message: str) -> NoReturn:
    raise SystemExit(f"spike failed: {message}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(
    command: list[str], *, environment: dict[str, str], input_data: bytes | None = None
) -> bytes:
    result = subprocess.run(
        command,
        check=False,
        env=environment,
        input=input_data,
        capture_output=True,
        timeout=MAX_WAIT_SECONDS,
    )
    if result.returncode:
        fail(
            f"command failed ({result.returncode}): {command!r}; "
            f"stderr={result.stderr.decode('utf-8', 'backslashreplace')}"
        )
    return result.stdout


def wrapper(arguments: list[str]) -> int:
    capture = Path(os.environ["ASPR_SPIKE_CAPTURE"])
    record = {
        "argv": arguments,
        "environment": dict(sorted(os.environ.items())),
        "accepted": arguments == SFTP_SUBSYSTEM_ARGUMENTS,
    }
    with capture.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, separators=(",", ":"), sort_keys=True))
        stream.write("\n")
    if not record["accepted"]:
        return 64
    os.execv(
        os.environ["ASPR_SPIKE_RCLONE"],
        [
            os.environ["ASPR_SPIKE_RCLONE"],
            "serve",
            "sftp",
            "--stdio",
            "--no-auth",
            os.environ["ASPR_SPIKE_ROOT"],
        ],
    )
    return 70


def candidate(manifest: Path, version: str) -> dict[str, str]:
    with manifest.open("rb") as stream:
        values = tomllib.load(stream)
    item = values.get(version)
    if (
        not isinstance(item, dict)
        or set(item)
        != {
            "archive_sha256",
            "archive_url",
            "binary_sha256",
        }
        or not all(isinstance(value, str) for value in item.values())
    ):
        fail(f"candidate {version} is absent or malformed")
    return item


def wait_for_mount(mountpoint: Path) -> None:
    deadline = time.monotonic() + MAX_WAIT_SECONDS
    while time.monotonic() < deadline:
        if os.path.ismount(mountpoint):
            return
        time.sleep(0.05)
    fail("mount never became ready")


def run_spike(rclone: Path, version: str, manifest: Path, output: Path) -> None:
    pin = candidate(manifest, version)
    if sha256(rclone) != pin["binary_sha256"]:
        fail("rclone binary digest differs from pinned candidate")
    observed_version = run([str(rclone), "version"], environment=os.environ.copy()).splitlines()[0]
    if observed_version != f"rclone v{version}".encode():
        fail(f"rclone reports {observed_version!r}, expected v{version}")

    with tempfile.TemporaryDirectory(prefix="aspr-rclone-spike-") as temporary:
        root = Path(temporary) / "root"
        mountpoint = Path(temporary) / "mount"
        cache = Path(temporary) / "cache"
        config = Path(temporary) / "rclone.conf"
        capture = Path(temporary) / "capture.jsonl"
        root.mkdir()
        mountpoint.mkdir()
        cache.mkdir()
        (root / "seed.txt").write_bytes(b"seed\n")
        wrapper_path = Path(__file__).resolve()
        interpreter = Path(sys.executable)
        if any(character.isspace() for character in (str(wrapper_path), str(interpreter))):
            fail("spike wrapper or interpreter path contains whitespace")
        config.write_text(
            "[spike]\n"
            "type = sftp\n"
            f"ssh = {interpreter} {wrapper_path} --wrapper\n"
            "disable_hashcheck = true\n",
            encoding="utf-8",
        )
        environment = {
            "ASPR_SPIKE_CAPTURE": str(capture),
            "ASPR_SPIKE_RCLONE": str(rclone),
            "ASPR_SPIKE_ROOT": str(root),
            "HOME": temporary,
            "PATH": os.environ.get("PATH", ""),
            "RCLONE_CONFIG": str(config),
        }
        client = [str(rclone), "--transfers", "1"]
        operations: list[str] = []
        run([*client, "lsjson", "spike:"], environment=environment)
        operations.append("lsjson")
        run([*client, "lsjson", "--stat", "spike:seed.txt"], environment=environment)
        operations.append("stat")
        if run([*client, "cat", "spike:seed.txt"], environment=environment) != b"seed\n":
            fail("read returned unexpected bytes")
        operations.append("read")
        run(
            [*client, "rcat", "spike:written.txt"], environment=environment, input_data=b"written\n"
        )
        operations.append("write")
        run([*client, "moveto", "spike:written.txt", "spike:renamed.txt"], environment=environment)
        if run([*client, "cat", "spike:renamed.txt"], environment=environment) != b"written\n":
            fail("rename did not preserve file")
        operations.append("rename")
        run(
            [
                *client,
                "mount",
                "--daemon",
                "--daemon-wait",
                "10s",
                "--cache-dir",
                str(cache),
                "--vfs-cache-mode",
                "writes",
                "spike:",
                str(mountpoint),
            ],
            environment=environment,
        )
        wait_for_mount(mountpoint)
        if (mountpoint / "renamed.txt").read_bytes() != b"written\n":
            fail("mounted read returned unexpected bytes")
        run(["fusermount3", "-u", str(mountpoint)], environment=environment)
        operations.append("mount-read-unmount")
        records = [json.loads(line) for line in capture.read_text(encoding="utf-8").splitlines()]
        final_config = config.read_text(encoding="utf-8")

    accepted = [record for record in records if record["accepted"]]
    rejected = [record for record in records if not record["accepted"]]
    if not accepted or any(record["argv"] != SFTP_SUBSYSTEM_ARGUMENTS for record in accepted):
        fail("external wrapper accepted non-SFTP invocation")
    if "shell_type = none" in final_config:
        fail("shell_type=none is forbidden with external SSH")
    output.write_text(
        json.dumps(
            {
                "candidate": version,
                "config_after": final_config,
                "disable_hashcheck": True,
                "operations": operations,
                "rejected_probes": [record["argv"] for record in rejected],
                "wrapper_invocations": records,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wrapper", action="store_true")
    parser.add_argument("--rclone", type=Path)
    parser.add_argument("--version")
    parser.add_argument(
        "--manifest", type=Path, default=Path("tests/fixtures/rclone/candidates.toml")
    )
    parser.add_argument("--output", type=Path)
    arguments, wrapper_arguments = parser.parse_known_args()
    if arguments.wrapper:
        raise SystemExit(wrapper(wrapper_arguments))
    if wrapper_arguments:
        parser.error("unexpected positional arguments")
    if not all((arguments.rclone, arguments.version, arguments.output)):
        parser.error("--rclone, --version, and --output are required outside --wrapper mode")
    run_spike(arguments.rclone, arguments.version, arguments.manifest, arguments.output)


if __name__ == "__main__":
    main()
