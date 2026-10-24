"""xz and LZMA-alone metadata.

An xz stream ends with a footer pointing at an index that stores the
uncompressed size of every block, so no decompression is needed.  Bare
``.lzma`` files usually store the size in their 13-byte header; a sentinel
value means unknown and triggers a bounded probe.
"""

from __future__ import annotations

import lzma
from typing import BinaryIO, List, Optional

from ..limits import Limits
from ..model import Facts
from ..reader import Deadline, FormatError, read_at, u32le, u64le

XZ_MAGIC = b"\xfd7zXZ\x00"
LZMA_MAGIC = b"\x5d\x00\x00"
UNKNOWN_SIZE = 0xFFFFFFFFFFFFFFFF
MAX_STREAMS = 8


def _varint(data: bytes, pos: int) -> tuple:
    value = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
        if shift > 63:
            break
    raise FormatError("invalid xz variable-length integer")


def _scan_xz(fp: BinaryIO, size: int, limits: Limits) -> Facts:
    if size < 32:
        raise FormatError("xz stream is too short")
    footer = read_at(fp, size - 12, 12)
    if len(footer) < 12 or footer[10:12] != b"YZ":
        raise FormatError("xz stream footer not found")
    flags = footer[8:10]
    if flags[0] != 0:
        raise FormatError("unsupported xz stream flags")
    backward = u32le(footer, 4)
    index_size = (backward + 1) * 4
    if index_size > limits.max_header_bytes or index_size + 12 > size:
        raise FormatError("xz index is implausibly large")
    index_start = size - 12 - index_size
    index = read_at(fp, index_start, index_size)
    if len(index) < index_size or index[0] != 0:
        raise FormatError("invalid xz index")

    pos = 1
    count, pos = _varint(index, pos)
    if count > limits.max_entries:
        raise FormatError("xz index declares too many blocks")
    total = 0
    for _ in range(count):
        _unpadded, pos = _varint(index, pos)
        uncompressed, pos = _varint(index, pos)
        total += uncompressed

    notes: List[str] = []
    notes.append("xz index sizes come from the final stream; concatenated streams are not summed")
    return Facts(
        format="xz",
        detail=f"xz, {count} block(s)",
        declared_uncompressed=total,
        declared_compressed=size,
        notes=notes,
    )


def _scan_lzma(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    head = read_at(fp, 0, 13)
    if len(head) < 13 or not head.startswith(LZMA_MAGIC):
        raise FormatError("not an LZMA-alone stream")
    declared: Optional[int] = u64le(head, 5)
    notes: List[str] = []
    measured = False
    capped = False
    probe_input: Optional[int] = None
    unknown = False

    if declared == UNKNOWN_SIZE:
        declared = None
        unknown = True
        notes.append("LZMA header does not store an uncompressed size")
        if limits.probe:
            from .probe import bounded_probe

            output, consumed, capped, eof = bounded_probe(
                fp,
                0,
                lambda: lzma.LZMADecompressor(
                    format=lzma.FORMAT_ALONE, memlimit=limits.max_decoder_memory
                ),
                limits.probe_limit,
                deadline,
            )
            declared = output
            measured = True
            probe_input = consumed
            unknown = capped
            if capped:
                notes.append("bounded probe reached its output cap; size is a lower bound")
            elif not eof:
                notes.append("bounded probe could not decode the stream")
                unknown = True

    return Facts(
        format="lzma",
        detail="LZMA-alone",
        declared_uncompressed=declared,
        declared_compressed=size,
        measured=measured,
        probe_capped=capped,
        probe_input=probe_input,
        notes=notes,
        unknown=unknown,
    )


def scan(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    deadline.check()
    head = read_at(fp, 0, 6)
    if head.startswith(XZ_MAGIC):
        return _scan_xz(fp, size, limits)
    return _scan_lzma(fp, size, limits, deadline)


def decompress_prefix(
    fp: BinaryIO,
    size: int,
    cap: int,
    deadline: Deadline,
    fmt: str = "xz",
    memlimit: int = 128 * 1024 * 1024,
) -> bytes:
    fmt_obj = lzma.FORMAT_XZ if fmt == "xz" else lzma.FORMAT_ALONE
    try:
        decompressor = lzma.LZMADecompressor(format=fmt_obj, memlimit=memlimit)
    except (lzma.LZMAError, ValueError):
        return b""
    fp.seek(0)
    out = bytearray()
    while len(out) < cap:
        deadline.check()
        chunk = fp.read(64 * 1024)
        if not chunk:
            break
        data = chunk
        while len(out) < cap:
            try:
                produced = decompressor.decompress(data, cap - len(out))
            except lzma.LZMAError:
                return bytes(out)
            out.extend(produced)
            if decompressor.eof:
                return bytes(out)
            if decompressor.needs_input:
                break
            data = b""
            if not produced:
                break
    return bytes(out)
