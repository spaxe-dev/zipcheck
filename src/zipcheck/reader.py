"""Small binary-reading helpers and a scan deadline."""

from __future__ import annotations

import io
import struct
import time
from typing import BinaryIO, Optional


class FormatError(Exception):
    """Raised when a file's metadata cannot be parsed."""


class ScanTimeout(Exception):
    """Raised when a scan exceeds its wall-clock budget."""


class ScanBudget(Exception):
    """Raised when nested inspection exceeds its decompression budget."""


class Deadline:
    def __init__(self, seconds: float = 0.0) -> None:
        self._end = time.monotonic() + seconds if seconds and seconds > 0 else None

    def check(self) -> None:
        if self._end is not None and time.monotonic() > self._end:
            raise ScanTimeout("scan exceeded its time budget")

    @property
    def expired(self) -> bool:
        return self._end is not None and time.monotonic() > self._end


def file_size(fp: BinaryIO) -> int:
    pos = fp.tell()
    fp.seek(0, io.SEEK_END)
    size = fp.tell()
    fp.seek(pos)
    return size


def read_at(fp: BinaryIO, offset: int, length: int) -> bytes:
    if offset < 0 or length < 0:
        return b""
    try:
        fp.seek(offset)
    except (OSError, ValueError):
        return b""
    return fp.read(length)


def u16le(data: bytes, off: int = 0) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32le(data: bytes, off: int = 0) -> int:
    return struct.unpack_from("<I", data, off)[0]


def u64le(data: bytes, off: int = 0) -> int:
    return struct.unpack_from("<Q", data, off)[0]


def enc_size(n: Optional[int]) -> bytes:
    """Test helper: little-endian 64-bit size (not part of the public API)."""
    return struct.pack("<Q", n or 0)


def human_size(n: Optional[int]) -> str:
    if n is None:
        return "unknown"
    if n < 1024:
        return f"{n} B"
    units = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"]
    value = float(n)
    for unit in units:
        value /= 1024.0
        if value < 1024.0 or unit == units[-1]:
            if value >= 100:
                return f"{value:.0f} {unit}"
            if value >= 10:
                return f"{value:.1f} {unit}"
            return f"{value:.2f} {unit}"
    return f"{n} B"


def human_ratio(r: Optional[float]) -> str:
    if r is None:
        return "n/a"
    if r >= 1_000_000:
        return f"{r:.0e}:1"
    if r >= 1000:
        return f"{r:,.0f}:1"
    if r >= 10:
        return f"{r:.1f}:1"
    return f"{r:.2f}:1"


class ByteReader:
    """Bounds-checked little-endian reader over an in-memory buffer."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    def remaining(self) -> int:
        return len(self.data) - self.pos

    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise FormatError("truncated archive header")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return u16le(self.take(2))

    def u32(self) -> int:
        return u32le(self.take(4))

    def u64(self) -> int:
        return u64le(self.take(8))

    def skip(self, n: int) -> None:
        if n < 0 or self.pos + n > len(self.data):
            raise FormatError("truncated archive header")
        self.pos += n

    # 7-Zip's variable-length integer.
    def num(self) -> int:
        first = self.u8()
        mask = 0x80
        value = 0
        for i in range(8):
            if first & mask == 0:
                value |= (first & (mask - 1)) << (8 * i)
                return value
            value |= self.u8() << (8 * i)
            mask >>= 1
        return value

    # RAR 5's little-endian base-128 varint.
    def vint(self) -> int:
        value = 0
        shift = 0
        while shift <= 63:
            byte = self.u8()
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
        raise FormatError("invalid RAR5 variable-length integer")


def round_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment
