from __future__ import annotations

import struct
from io import BytesIO
from typing import BinaryIO, cast

import pytest

from astral_project.sftp.client import (
    SftpAttrs,
    SftpClient,
    SftpProtocolError,
    SftpStatus,
    SftpStatusError,
    _attrs,
    _field,
    _packet,
    _parse_attrs,
    _Reader,
    read_packet,
)


def field(value: bytes) -> bytes:
    return struct.pack(">I", len(value)) + value


def status(request_id: int, code: SftpStatus, message: bytes = b"") -> bytes:
    return _packet(101, struct.pack(">II", request_id, code) + field(message) + field(b""))


def name(request_id: int, entries: list[tuple[bytes, bytes, SftpAttrs]]) -> bytes:
    body = struct.pack(">II", request_id, len(entries))
    for filename, longname, attrs in entries:
        body += field(filename) + field(longname) + _attrs(attrs)
    return _packet(104, body)


class ScriptedStream:
    def __init__(self, responses: bytes) -> None:
        self.input = BytesIO(responses)
        self.output = BytesIO()

    def read(self, size: int = -1) -> bytes:
        return self.input.read(size)

    def write(self, value: bytes) -> int:
        return self.output.write(value)

    def flush(self) -> None:
        return None


def handshake() -> bytes:
    extensions = field(b"supported2") + field(b"hardlink,fsync")
    return _packet(2, struct.pack(">I", 3) + extensions)


def test_sftp_client_acceptance_operations() -> None:
    directory_attrs = SftpAttrs(size=0, uid=1000, gid=1000, permissions=0o40755, atime=1, mtime=2)
    file_attrs = SftpAttrs(size=3, permissions=0o100644)
    responses = b"".join(
        [
            handshake(),
            name(1, [(b"/project", b"/project", directory_attrs)]),
            _packet(105, struct.pack(">I", 2) + _attrs(file_attrs)),
            _packet(105, struct.pack(">I", 3) + _attrs(file_attrs)),
            _packet(102, struct.pack(">I", 4) + field(b"dir-handle")),
            name(5, [(b"file", b"-rw-r--r-- 1", file_attrs)]),
            status(6, SftpStatus.EOF),
            _packet(102, struct.pack(">I", 7) + field(b"file-handle")),
            _packet(103, struct.pack(">I", 8) + field(b"abc")),
            status(9, SftpStatus.OK),
            status(10, SftpStatus.OK),
            status(11, SftpStatus.OK),
            status(12, SftpStatus.OK),
            status(13, SftpStatus.OK),
            status(14, SftpStatus.OK),
            name(15, [(b"target", b"target", file_attrs)]),
            status(16, SftpStatus.OK),
            status(17, SftpStatus.OK),
            status(18, SftpStatus.OK),
        ]
    )
    stream = ScriptedStream(responses)
    client = SftpClient(cast(BinaryIO, stream))

    assert client.connect() == 3
    assert client.extensions.names() == {b"supported2"}
    assert client.realpath("/project") == b"/project"
    assert client.stat("/file").size == 3
    assert client.stat("/link", follow_symlinks=False).permissions == 0o100644
    handle = client.opendir("/")
    assert handle == b"dir-handle"
    assert client.readdir(handle)[0].filename == b"file"
    assert client.readdir(handle) == []
    file_handle = client.open("/file", write=True, create=True)
    assert file_handle == b"file-handle"
    assert client.read(file_handle, 0, 3) == b"abc"
    client.write(file_handle, 0, b"abc")
    client.close(file_handle)
    client.mkdir("/new")
    client.rmdir("/new")
    client.remove("/file")
    client.rename("/old", "/new")
    assert client.readlink("/link") == b"target"
    client.symlink("target", "/link")
    client.hardlink("/file", "/hard")
    client.posix_rename("/hard", "/harder")

    written = stream.output.getvalue()
    assert written.startswith(struct.pack(">I", 5) + b"\x01")
    assert b"/project" in written


def test_sftp_low_level_bounds_and_attributes() -> None:
    assert SftpAttrs(permissions=0o40755).is_directory
    assert not SftpAttrs(permissions=0o100644).is_directory
    reader = _Reader(struct.pack(">Q", 9))
    assert reader.u64() == 9
    with pytest.raises(SftpProtocolError):
        _Reader(b"x").take(2)
    with pytest.raises(SftpProtocolError):
        _Reader(struct.pack(">I", 10)).string(max_length=1)
    with pytest.raises(SftpProtocolError):
        _Reader(b"x").done()
    attrs = SftpAttrs(uid=1, gid=2, atime=3, mtime=4, extended=((b"x", b"y"),))
    parsed = _parse_attrs(_Reader(_attrs(attrs)))
    assert parsed.uid == 1 and parsed.extended == ((b"x", b"y"),)
    with pytest.raises(ValueError):
        _attrs(SftpAttrs(atime=1))
    with pytest.raises(SftpProtocolError):
        _parse_attrs(_Reader(struct.pack(">I", 0x10)))
    with pytest.raises(SftpProtocolError):
        _parse_attrs(_Reader(struct.pack(">II", 0x80000000, 257)))
    with pytest.raises(SftpProtocolError):
        _field(b"x" * (1 << 20 | 1))
    with pytest.raises(SftpProtocolError):
        _packet(1, b"x" * (1 << 20))
    with pytest.raises(SftpProtocolError):
        read_packet(BytesIO(struct.pack(">I", 2) + b"x"))


def test_sftp_client_status_and_malformed_responses() -> None:
    stream = ScriptedStream(handshake() + status(1, SftpStatus.PERMISSION_DENIED, b"no"))
    client = SftpClient(cast(BinaryIO, stream))
    client.connect()
    with pytest.raises(SftpStatusError) as error:
        client.remove("/secret")
    assert error.value.code is SftpStatus.PERMISSION_DENIED
    assert error.value.request_id == 1

    bad = ScriptedStream(_packet(2, struct.pack(">I", 2)))
    with pytest.raises(SftpProtocolError):
        SftpClient(cast(BinaryIO, bad)).connect()

    with pytest.raises(SftpProtocolError):
        read_packet(BytesIO(struct.pack(">I", 0)))
    with pytest.raises(SftpProtocolError):
        SftpClient(cast(BinaryIO, ScriptedStream(_packet(101, struct.pack(">I", 1))))).connect()


def test_sftp_client_response_shape_failures() -> None:
    def run(response: bytes, operation: str) -> None:
        client = SftpClient(cast(BinaryIO, ScriptedStream(handshake() + response)))
        client.connect()
        with pytest.raises(SftpProtocolError):
            getattr(client, operation)("/x")

    run(_packet(2, struct.pack(">I", 1)), "remove")
    run(
        _packet(101, struct.pack(">I", 1) + struct.pack(">I", 99) + field(b"") + field(b"")),
        "remove",
    )
    run(_packet(104, struct.pack(">II", 1, 0)), "realpath")
    run(_packet(104, struct.pack(">II", 1, 0)), "readlink")
    expect_client = SftpClient(
        cast(BinaryIO, ScriptedStream(handshake() + status(1, SftpStatus.OK)))
    )
    expect_client.connect()
    with pytest.raises(SftpProtocolError):
        expect_client.stat("/x")

    eof_client = SftpClient(cast(BinaryIO, ScriptedStream(handshake() + status(1, SftpStatus.EOF))))
    eof_client.connect()
    assert eof_client.read(b"h", 0, 1) == b""

    truncated_client = SftpClient(cast(BinaryIO, ScriptedStream(handshake() + _packet(101, b""))))
    truncated_client.connect()
    with pytest.raises(SftpProtocolError):
        truncated_client.remove("/x")

    mismatch_client = SftpClient(
        cast(BinaryIO, ScriptedStream(handshake() + status(2, SftpStatus.OK)))
    )
    mismatch_client.connect()
    with pytest.raises(SftpProtocolError):
        mismatch_client.remove("/x")

    read_client = SftpClient(
        cast(BinaryIO, ScriptedStream(handshake() + _packet(200, struct.pack(">I", 1))))
    )
    read_client.connect()
    with pytest.raises(SftpProtocolError):
        read_client.read(b"h", 0, 1)

    too_many = _packet(104, struct.pack(">II", 1, 4097))
    count_client = SftpClient(cast(BinaryIO, ScriptedStream(handshake() + too_many)))
    count_client.connect()
    with pytest.raises(SftpProtocolError):
        count_client.realpath("/x")

    readdir_client = SftpClient(
        cast(BinaryIO, ScriptedStream(handshake() + _packet(200, struct.pack(">I", 1))))
    )
    readdir_client.connect()
    with pytest.raises(SftpProtocolError):
        readdir_client.readdir(b"h")

    client = SftpClient(cast(BinaryIO, ScriptedStream(handshake() + status(1, SftpStatus.EOF))))
    client.connect()
    with pytest.raises(SftpStatusError):
        client.remove("/eof")


def test_sftp_client_argument_and_attribute_validation() -> None:
    flag_stream = ScriptedStream(handshake() + _packet(102, struct.pack(">I", 1) + field(b"h")))
    flag_client = SftpClient(cast(BinaryIO, flag_stream))
    flag_client.connect()
    assert (
        flag_client.open("/x", read=False, write=True, append=True, truncate=True, exclusive=True)
        == b"h"
    )
    client = SftpClient(cast(BinaryIO, ScriptedStream(b"")))
    client._request_id = 0xFFFFFFFF
    assert client._next_id() == 1
    with pytest.raises(ValueError):
        client.open("/file", read=False, write=False)
    with pytest.raises(ValueError):
        client.read(b"h", -1, 1)
    with pytest.raises(ValueError):
        client.write(b"h", -1, b"")
    with pytest.raises(ValueError):
        SftpClient(cast(BinaryIO, ScriptedStream(b"")), max_packet_bytes=10)
    with pytest.raises(ValueError):
        _attrs(SftpAttrs(uid=1))
    duplicate_extensions = field(b"supported") + field(b"x") + field(b"supported") + field(b"y")
    with pytest.raises(SftpProtocolError):
        SftpClient(
            cast(BinaryIO, ScriptedStream(_packet(2, struct.pack(">I", 3) + duplicate_extensions)))
        ).connect()
