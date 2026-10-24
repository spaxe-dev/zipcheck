"""gzip member metadata.

gzip stores the uncompressed size in the last four bytes of each member
(``ISIZE``), modulo 2^32.  Reading it requires no decompression at all.  The
value is ambiguous when the real size is an exact multiple of 4 GiB, so that
case falls back to a bounded probe.
"""

from __future__ import annotations

import zlib
from typing import BinaryIO, List, Optional

from ..limits import Limits
from ..model import Facts
from ..reader import Deadline, FormatError, read_at, u16le, u32le

FHCRC = 0x02
FEXTRA = 0x04
FNAME = 0x08
FCOMMENT = 0x10
FRESERVED = 0xE0

MAGIC = b"\x1f\x8b"


def _header(fp: BinaryIO, size: int, limits: Limits) -> tuple:
    if size < 18:
        raise FormatError("gzip file is too short")
    head = read_at(fp, 0, min(size, 64 * 1024))
    if not head.startswith(MAGIC) or head[2] != 8:
        raise FormatError("not a gzip member (bad magic or method)")
    flags = head[3]
    notes: List[str] = []
    if flags & FRESERVED:
        notes.append("gzip reserved header bits are set")
    pos = 10
    name = None
    if flags & FEXTRA:
        if pos + 2 > len(head):
            raise FormatError("truncated gzip extra field")
        xlen = u16le(head, pos)
        pos += 2 + xlen
    if flags & FNAME:
        end = head.find(b"\x00", pos)
        if end < 0:
            raise FormatError("unterminated gzip original name")
        name = head[pos:end].decode("latin-1", "replace")
        pos = end + 1
    if flags & FCOMMENT:
        end = head.find(b"\x00", pos)
        if end < 0:
            raise FormatError("unterminated gzip comment")
        pos = end + 1
    if flags & FHCRC:
        pos += 2
    if pos > len(head):
        raise FormatError("truncated gzip header")
    if pos > limits.max_header_bytes:
        raise FormatError("gzip header exceeds safety limit")
    return flags, name, notes


def scan(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    deadline.check()
    flags, name, notes = _header(fp, size, limits)
    isize_raw = read_at(fp, size - 4, 4)
    if len(isize_raw) < 4:
        raise FormatError("gzip member has no trailer")
    isize = u32le(isize_raw)
    declared = isize
    measured = False
    probe_capped = False
    probe_input: Optional[int] = None

    if isize == 0 and size > 64 and limits.probe:
        from .probe import bounded_probe

        output, consumed, capped, _eof = bounded_probe(
            fp,
            0,
            lambda: zlib.decompressobj(16 + zlib.MAX_WBITS),
            limits.probe_limit,
            deadline,
        )
        declared = output
        measured = True
        probe_capped = capped
        probe_input = consumed
        notes.append(
            "ISIZE is zero (empty file or a multiple of 4 GiB); used a bounded "
            "decompression probe"
        )

    detail = "gzip"
    if name:
        detail += f", original name {name!r}"
    notes.append("gzip ISIZE describes the final member and wraps at 4 GiB")

    return Facts(
        format="gzip",
        detail=detail,
        declared_uncompressed=declared,
        declared_compressed=size,
        measured=measured,
        probe_capped=probe_capped,
        probe_input=probe_input,
        notes=notes,
        unknown=probe_capped,
    )


def decompress_prefix(
    fp: BinaryIO, size: int, cap: int, deadline: Deadline
) -> bytes:
    """Return at most ``cap`` decompressed bytes across all members, in memory.

    gzip concatenation is defined as the concatenation of member payloads, so a
    valid TAR or ZIP may span several members.  Stopping at the first member
    would hide a nested archive split across members.
    """
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    fp.seek(0)
    out = bytearray()
    while len(out) < cap:
        deadline.check()
        chunk = fp.read(64 * 1024)
        if not chunk:
            break
        data = chunk
        while data and len(out) < cap:
            try:
                out.extend(decompressor.decompress(data, cap - len(out)))
            except zlib.error:
                return bytes(out)
            if decompressor.eof:
                data = decompressor.unused_data
                decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                if not data:
                    break
                continue
            data = b""
    return bytes(out)
