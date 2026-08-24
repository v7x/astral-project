"""Bounded SFTP version 3 client for direct acceptance tests.

This client is deliberately transport-neutral. Caller supplies an already
authenticated byte stream; this module never performs SSH, grant, or path
authorization. Filesystem failures remain SFTP status responses.
"""

from __future__ import annotations

import os
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum
from typing import BinaryIO

MAX_PACKET_BYTES = 1 << 20
MAX_ENTRIES_PER_READDIR = 4096
MAX_EXTENSIONS = 256

_INIT = 1
_VERSION = 2
_OPEN = 3
_CLOSE = 4
_READ = 5
_WRITE = 6
_LSTAT = 7
_FSTAT = 8
_SETSTAT = 9
_FSETSTAT = 10
_OPENDIR = 11
_READDIR = 12
_REMOVE = 13
_MKDIR = 14
_RMDIR = 15
_REALPATH = 16
_STAT = 17
_RENAME = 18
_READLINK = 19
_SYMLINK = 20
_EXTENDED = 200
_STATUS = 101
_HANDLE = 102
_DATA = 103
_NAME = 104
_ATTRS = 105

_ATTR_SIZE = 0x00000001
_ATTR_UIDGID = 0x00000002
_ATTR_PERMISSIONS = 0x00000004
_ATTR_ACMODTIME = 0x00000008
_ATTR_EXTENDED = 0x80000000

_OPEN_READ = 0x00000001
_OPEN_WRITE = 0x00000002
_OPEN_APPEND = 0x00000004
_OPEN_CREAT = 0x00000008
_OPEN_TRUNC = 0x00000010
_OPEN_EXCL = 0x00000020


class SftpStatus(IntEnum):
    """SFTP v3 operation status codes."""

    OK = 0
    EOF = 1
    NO_SUCH_FILE = 2
    PERMISSION_DENIED = 3
    FAILURE = 4
    BAD_MESSAGE = 5
    NO_CONNECTION = 6
    CONNECTION_LOST = 7
    OP_UNSUPPORTED = 8


class SftpProtocolError(ValueError):
    """Malformed or unexpected SFTP packet."""


class SftpStatusError(OSError):
    """SFTP server returned an operation failure."""

    def __init__(self, code: SftpStatus, message: str, *, request_id: int) -> None:
        super().__init__(message)
        self.code = code
        self.request_id = request_id
        self.message = message


@dataclass(frozen=True, slots=True)
class SftpExtensions:
    """Server-advertised extension name/value pairs."""

    values: Mapping[bytes, bytes]

    def names(self) -> frozenset[bytes]:
        return frozenset(self.values)


@dataclass(frozen=True, slots=True)
class SftpAttrs:
    """Subset of SSH_FILEXFER_ATTRS understood by acceptance harness."""

    size: int | None = None
    uid: int | None = None
    gid: int | None = None
    permissions: int | None = None
    atime: int | None = None
    mtime: int | None = None
    extended: tuple[tuple[bytes, bytes], ...] = ()

    @property
    def is_directory(self) -> bool:
        return self.permissions is not None and self.permissions & 0o170000 == 0o040000


@dataclass(frozen=True, slots=True)
class SftpEntry:
    """One NAME response entry."""

    filename: bytes
    longname: bytes
    attrs: SftpAttrs


class _Reader:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.offset = 0

    def take(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.payload):
            raise SftpProtocolError("SFTP packet field is truncated")
        value = self.payload[self.offset : self.offset + length]
        self.offset += length
        return value

    def u8(self) -> int:
        return self.take(1)[0]

    def u32(self) -> int:
        return int(struct.unpack(">I", self.take(4))[0])

    def u64(self) -> int:
        return int(struct.unpack(">Q", self.take(8))[0])

    def string(self, *, max_length: int = MAX_PACKET_BYTES) -> bytes:
        length = self.u32()
        if length > max_length:
            raise SftpProtocolError("SFTP string exceeds limit")
        return self.take(length)

    def done(self) -> None:
        if self.offset != len(self.payload):
            raise SftpProtocolError("SFTP packet has trailing bytes")


def _string(value: str | bytes) -> bytes:
    return os.fsencode(value) if isinstance(value, str) else value


def _field(value: bytes) -> bytes:
    if len(value) > MAX_PACKET_BYTES:
        raise SftpProtocolError("SFTP string exceeds limit")
    return struct.pack(">I", len(value)) + value


def _attrs(value: SftpAttrs | None = None) -> bytes:
    attrs = SftpAttrs() if value is None else value
    flags = 0
    body = bytearray()
    if attrs.size is not None:
        flags |= _ATTR_SIZE
        body.extend(struct.pack(">Q", attrs.size))
    if attrs.uid is not None or attrs.gid is not None:
        if attrs.uid is None or attrs.gid is None:
            raise ValueError("uid and gid must be supplied together")
        flags |= _ATTR_UIDGID
        body.extend(struct.pack(">II", attrs.uid, attrs.gid))
    if attrs.permissions is not None:
        flags |= _ATTR_PERMISSIONS
        body.extend(struct.pack(">I", attrs.permissions))
    if attrs.atime is not None or attrs.mtime is not None:
        if attrs.atime is None or attrs.mtime is None:
            raise ValueError("atime and mtime must be supplied together")
        flags |= _ATTR_ACMODTIME
        body.extend(struct.pack(">II", attrs.atime, attrs.mtime))
    if attrs.extended:
        flags |= _ATTR_EXTENDED
        body.extend(struct.pack(">I", len(attrs.extended)))
        for name, extension_value in attrs.extended:
            body.extend(_field(name))
            body.extend(_field(extension_value))
    return struct.pack(">I", flags) + bytes(body)


def _parse_attrs(reader: _Reader) -> SftpAttrs:
    flags = reader.u32()
    unknown = flags & ~(
        _ATTR_SIZE | _ATTR_UIDGID | _ATTR_PERMISSIONS | _ATTR_ACMODTIME | _ATTR_EXTENDED
    )
    if unknown:
        raise SftpProtocolError("SFTP attrs contain unknown flags")
    size = struct.unpack(">Q", reader.take(8))[0] if flags & _ATTR_SIZE else None
    uid = gid = None
    if flags & _ATTR_UIDGID:
        uid, gid = struct.unpack(">II", reader.take(8))
    permissions = reader.u32() if flags & _ATTR_PERMISSIONS else None
    atime = mtime = None
    if flags & _ATTR_ACMODTIME:
        atime, mtime = struct.unpack(">II", reader.take(8))
    extended: list[tuple[bytes, bytes]] = []
    if flags & _ATTR_EXTENDED:
        count = reader.u32()
        if count > MAX_EXTENSIONS:
            raise SftpProtocolError("too many SFTP extended attributes")
        for _ in range(count):
            extended.append((reader.string(), reader.string()))
    return SftpAttrs(size, uid, gid, permissions, atime, mtime, tuple(extended))


def _packet(packet_type: int, body: bytes) -> bytes:
    payload = bytes([packet_type]) + body
    if len(payload) > MAX_PACKET_BYTES:
        raise SftpProtocolError("SFTP packet exceeds limit")
    return struct.pack(">I", len(payload)) + payload


def read_packet(stream: BinaryIO, *, max_packet_bytes: int = MAX_PACKET_BYTES) -> bytes:
    header = _read_exact(stream, 4)
    length = struct.unpack(">I", header)[0]
    if not 1 <= length <= max_packet_bytes:
        raise SftpProtocolError("SFTP packet length is outside limit")
    return _read_exact(stream, length)


def write_packet(stream: BinaryIO, packet: bytes) -> None:
    stream.write(packet)
    stream.flush()


def _read_exact(stream: BinaryIO, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise SftpProtocolError("SFTP stream ended before packet completed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class SftpClient:
    """Synchronous bounded SFTP v3 client over an authenticated byte stream."""

    def __init__(self, stream: BinaryIO, *, max_packet_bytes: int = MAX_PACKET_BYTES) -> None:
        if not 1024 <= max_packet_bytes <= MAX_PACKET_BYTES:
            raise ValueError("max_packet_bytes is invalid")
        self.stream = stream
        self.max_packet_bytes = max_packet_bytes
        self.version: int | None = None
        self.extensions = SftpExtensions({})
        self._request_id = 0

    def connect(self) -> int:
        write_packet(self.stream, _packet(_INIT, struct.pack(">I", 3)))
        packet = read_packet(self.stream, max_packet_bytes=self.max_packet_bytes)
        if packet[0] != _VERSION:
            raise SftpProtocolError("SFTP server did not return VERSION")
        reader = _Reader(packet[1:])
        version = reader.u32()
        if version < 3:
            raise SftpProtocolError("SFTP server version is unsupported")
        extensions: dict[bytes, bytes] = {}
        while reader.offset < len(reader.payload):
            name = reader.string()
            value = reader.string()
            if name in extensions:
                raise SftpProtocolError("SFTP server repeated an extension")
            extensions[name] = value
        self.version = version
        self.extensions = SftpExtensions(extensions)
        return version

    def realpath(self, path: str | bytes) -> bytes:
        packet = self._request(_REALPATH, _field(_string(path)) + struct.pack(">I", 0))
        reader = self._expect(packet, _NAME)
        entries = self._read_entries(reader)
        if len(entries) != 1:
            raise SftpProtocolError("REALPATH returned unexpected entry count")
        return entries[0].filename

    def stat(self, path: str | bytes, *, follow_symlinks: bool = True) -> SftpAttrs:
        packet_type = _STAT if follow_symlinks else _LSTAT
        packet = self._request(packet_type, _field(_string(path)) + struct.pack(">I", 0))
        reader = self._expect(packet, _ATTRS)
        attrs = _parse_attrs(reader)
        reader.done()
        return attrs

    def opendir(self, path: str | bytes) -> bytes:
        reader = self._expect(self._request(_OPENDIR, _field(_string(path))), _HANDLE)
        handle = reader.string()
        reader.done()
        return handle

    def readdir(self, handle: bytes) -> list[SftpEntry]:
        reader = self._response_reader(self._request(_READDIR, _field(handle)))
        packet_type = reader.u8()
        request_id = reader.u32()
        if packet_type == _STATUS:
            self._raise_status(reader, request_id, allow_eof=True)
            reader.done()
            return []
        if packet_type != _NAME:
            raise SftpProtocolError("READDIR returned unexpected packet")
        entries = self._read_entries(reader)
        reader.done()
        return entries

    def open(
        self,
        path: str | bytes,
        *,
        read: bool = True,
        write: bool = False,
        create: bool = False,
        truncate: bool = False,
        exclusive: bool = False,
        append: bool = False,
        attrs: SftpAttrs | None = None,
    ) -> bytes:
        if not (read or write):
            raise ValueError("open requires read or write")
        flags = (_OPEN_READ if read else 0) | (_OPEN_WRITE if write else 0)
        if append:
            flags |= _OPEN_APPEND
        if create:
            flags |= _OPEN_CREAT
        if truncate:
            flags |= _OPEN_TRUNC
        if exclusive:
            flags |= _OPEN_EXCL
        body = _field(_string(path)) + struct.pack(">I", flags) + _attrs(attrs)
        reader = self._expect(self._request(_OPEN, body), _HANDLE)
        handle = reader.string()
        reader.done()
        return handle

    def read(self, handle: bytes, offset: int, length: int) -> bytes:
        if offset < 0 or not 0 < length <= MAX_PACKET_BYTES:
            raise ValueError("read offset or length is invalid")
        reader = self._response_reader(
            self._request(_READ, _field(handle) + struct.pack(">QI", offset, length))
        )
        packet_type = reader.u8()
        request_id = reader.u32()
        if packet_type == _DATA:
            data = reader.string(max_length=MAX_PACKET_BYTES)
            reader.done()
            return data
        if packet_type == _STATUS:
            self._raise_status(reader, request_id, allow_eof=True)
            reader.done()
            return b""
        raise SftpProtocolError("READ returned unexpected packet")

    def write(self, handle: bytes, offset: int, data: bytes) -> None:
        if offset < 0 or len(data) > MAX_PACKET_BYTES:
            raise ValueError("write offset or data is invalid")
        reader = self._response_reader(
            self._request(_WRITE, _field(handle) + struct.pack(">Q", offset) + _field(data))
        )
        self._expect_status(reader, allow_eof=False)

    def close(self, handle: bytes) -> None:
        self._expect_status(
            self._response_reader(self._request(_CLOSE, _field(handle))), allow_eof=False
        )

    def mkdir(self, path: str | bytes, attrs: SftpAttrs | None = None) -> None:
        self._expect_status(
            self._response_reader(self._request(_MKDIR, _field(_string(path)) + _attrs(attrs))),
            allow_eof=False,
        )

    def rmdir(self, path: str | bytes) -> None:
        self._expect_status(
            self._response_reader(self._request(_RMDIR, _field(_string(path)))), allow_eof=False
        )

    def remove(self, path: str | bytes) -> None:
        self._expect_status(
            self._response_reader(self._request(_REMOVE, _field(_string(path)))), allow_eof=False
        )

    def rename(self, old: str | bytes, new: str | bytes) -> None:
        body = _field(_string(old)) + _field(_string(new))
        self._expect_status(self._response_reader(self._request(_RENAME, body)), allow_eof=False)

    def readlink(self, path: str | bytes) -> bytes:
        reader = self._expect(self._request(_READLINK, _field(_string(path))), _NAME)
        entries = self._read_entries(reader)
        if len(entries) != 1:
            raise SftpProtocolError("READLINK returned unexpected entry count")
        return entries[0].filename

    def symlink(self, target: str | bytes, link: str | bytes) -> None:
        self._expect_status(
            self._response_reader(
                self._request(_SYMLINK, _field(_string(link)) + _field(_string(target)))
            ),
            allow_eof=False,
        )

    def hardlink(self, old: str | bytes, new: str | bytes) -> None:
        """Create hardlink through OpenSSH's fixed hardlink extension."""
        body = _field(b"hardlink@openssh.com") + _field(_string(old)) + _field(_string(new))
        self._expect_status(self._response_reader(self._request(_EXTENDED, body)), allow_eof=False)

    def posix_rename(self, old: str | bytes, new: str | bytes) -> None:
        """Use OpenSSH atomic rename extension when advertised."""
        body = _field(b"posix-rename@openssh.com") + _field(_string(old)) + _field(_string(new))
        self._expect_status(self._response_reader(self._request(_EXTENDED, body)), allow_eof=False)

    def _next_id(self) -> int:
        self._request_id = (self._request_id + 1) & 0xFFFFFFFF
        if self._request_id == 0:
            self._request_id = 1
        return self._request_id

    def _request(self, packet_type: int, body: bytes) -> bytes:
        request_id = self._next_id()
        write_packet(self.stream, _packet(packet_type, struct.pack(">I", request_id) + body))
        packet = read_packet(self.stream, max_packet_bytes=self.max_packet_bytes)
        if len(packet) < 5:
            raise SftpProtocolError("SFTP response is truncated")
        response_id = struct.unpack(">I", packet[1:5])[0]
        if response_id != request_id:
            raise SftpProtocolError("SFTP response request identifier mismatched")
        return packet

    def _response_reader(self, packet: bytes) -> _Reader:
        return _Reader(packet)

    def _expect(self, packet: bytes, expected_type: int) -> _Reader:
        reader = self._response_reader(packet)
        if reader.u8() != expected_type:
            self._raise_status(reader, struct.unpack(">I", reader.take(4))[0], allow_eof=False)
            raise SftpProtocolError("SFTP response type is unexpected")
        reader.u32()
        return reader

    def _expect_status(self, reader: _Reader, *, allow_eof: bool) -> None:
        packet_type = reader.u8()
        if packet_type != _STATUS:
            raise SftpProtocolError("SFTP operation did not return STATUS")
        request_id = reader.u32()
        self._raise_status(reader, request_id, allow_eof=allow_eof)
        reader.done()

    def _raise_status(self, reader: _Reader, request_id: int, *, allow_eof: bool) -> None:
        code_value = reader.u32()
        try:
            code = SftpStatus(code_value)
        except ValueError as error:
            raise SftpProtocolError("SFTP status code is unknown") from error
        message = reader.string().decode("utf-8", "replace")
        _ = reader.string()  # language tag
        if code is SftpStatus.OK or (allow_eof and code is SftpStatus.EOF):
            return
        raise SftpStatusError(code, message, request_id=request_id)

    def _read_entries(self, reader: _Reader) -> list[SftpEntry]:
        count = reader.u32()
        if count > MAX_ENTRIES_PER_READDIR:
            raise SftpProtocolError("SFTP response contains too many entries")
        entries: list[SftpEntry] = []
        for _ in range(count):
            entries.append(SftpEntry(reader.string(), reader.string(), _parse_attrs(reader)))
        return entries
