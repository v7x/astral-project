#!/usr/bin/env python3
"""Packet 16A direct packaged-path SFTP acceptance harness.

No shell is used. SSH command and identity are fixed by typed arguments; the
remote forced command remains `aspr-channel-v1`.
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import uuid
from pathlib import Path

from astral_project.core.ids import SessionId
from astral_project.crypto.grants import SignedGrant
from astral_project.server.protocol import read_outer_response, write_outer_request
from astral_project.session.contracts import RemoteSessionRequestV1
from astral_project.sftp.client import SftpClient
from astral_project.sftp.harness import DirectSftpAcceptanceHarness
from astral_project.transport.local import ProcessStream


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh", type=Path, default=Path("/usr/bin/ssh"))
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--known-hosts", type=Path)
    parser.add_argument("--grant-cbor", type=Path, required=True)
    parser.add_argument("--root", default="/")
    parser.add_argument("--read-write", action="store_true")
    args = parser.parse_args()
    if (
        not args.ssh.is_absolute()
        or not args.identity.is_absolute()
        or not args.grant_cbor.is_absolute()
        or not args.host
        or not args.user
        or any(character.isspace() for character in args.host + args.user)
        or not 1 <= args.port <= 65535
        or (args.known_hosts is not None and not args.known_hosts.is_absolute())
    ):
        parser.error("SSH, identity, grant, and endpoint arguments are invalid")
    request = RemoteSessionRequestV1(
        session_id=SessionId(str(uuid.uuid4())),
        session_nonce=secrets.token_bytes(32),
        signed_grant=SignedGrant.from_cbor(args.grant_cbor.read_bytes()),
    )
    ssh_argv = [
        str(args.ssh),
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "RequestTTY=no",
        "-i",
        str(args.identity),
        "-p",
        str(args.port),
        f"{args.user}@{args.host}",
        "aspr-channel-v1",
    ]
    if args.known_hosts is not None:
        ssh_argv[1:1] = [
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={args.known_hosts}",
        ]
    process = subprocess.Popen(
        ssh_argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdin is not None and process.stdout is not None
    write_outer_request(process.stdin, request)
    try:
        response = read_outer_response(process.stdout)
    except Exception:
        _stop_process(process)
        if process.stderr is not None:
            diagnostic = process.stderr.read()
            if diagnostic:
                sys.stderr.buffer.write(diagnostic)
        raise
    if response.get("status") != "ready":
        stderr = process.stderr.read() if process.stderr is not None else b""
        print(
            json.dumps(
                {"status": "rejected", "response": response},
                default=lambda value: value.hex() if isinstance(value, bytes) else str(value),
            ),
            file=sys.stderr,
        )
        if stderr:
            sys.stderr.buffer.write(stderr)
        _stop_process(process)
        return 70
    client = SftpClient(ProcessStream(process))
    try:
        report = DirectSftpAcceptanceHarness(client).run(args.root)
    except Exception:
        _stop_process(process)
        if process.stderr is not None:
            diagnostic = process.stderr.read()
            if diagnostic:
                sys.stderr.buffer.write(diagnostic)
        raise
    read_write = False
    if args.read_write:
        path = args.root.rstrip("/") + "/.aspr-sftp-acceptance-" + secrets.token_hex(8)
        data = b"astral-sftp-landlock-acceptance\n"
        handle = client.open(path, read=False, write=True, create=True, exclusive=True)
        client.write(handle, 0, data)
        client.close(handle)
        read_handle = client.open(path, read=True)
        observed = client.read(read_handle, 0, len(data))
        client.close(read_handle)
        if observed != data:
            raise RuntimeError("remote SFTP read-back mismatch")
        client.remove(path)
        read_write = True
    print(
        json.dumps(
            {
                "extensions": sorted(name.decode("utf-8", "replace") for name in report.extensions),
                "operations": report.operations
                + (("OPEN", "WRITE", "READ", "REMOVE") if read_write else ()),
                "read_write": read_write,
                "root": report.root.decode("utf-8", "replace"),
                "root_entries": len(report.root_entries),
                "version": report.version,
            },
            sort_keys=True,
        )
    )
    _stop_process(process)
    return 0


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
