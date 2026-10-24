"""Zstandard frame-header metadata.

A zstd frame may declare its decompressed size in the frame header.  This is
often omitted for streamed data, in which case zipcheck reports the archive as
*unknown* rather than pretending it is clean.  No zstd decompression is done.
"""

from __future__ import annotations

from typing import BinaryIO, Optional

from ..limits import Limits
from ..model import Facts
from ..reader import Deadline, FormatError, read_at, u32le

MAGIC = b"\x28\xb5\x2f\xfd"
SKIPPABLE_BASE = 0x184D2A50
SKIPPABLE_MASK = 0xFFFFFFF0


def _frame_header(fp: BinaryIO, offset: int, size: int) -> tuple:
    head = read_at(fp, offset, 18)
    if len(head) < 5:
        raise FormatError("truncated zstd frame header")
    if u32le(head, 0) != u32le(MAGIC, 0):
        raise FormatError("not a zstd frame")
    descriptor = head[4]
    fcs_code = descriptor >> 6
    single_segment = (descriptor >> 5) & 1
    checksum = (descriptor >> 2) & 1
    dict_code = descriptor & 0x03
    reserved = (descriptor >> 3) & 1
    pos = 5
    if not single_segment:
        pos += 1  # window descriptor
    dict_size = [0, 1, 2, 4][dict_code]
    pos += dict_size
    fcs_size = (1 if single_segment else 0) if fcs_code == 0 else [0, 2, 4, 8][fcs_code]
    pos += fcs_size
    if pos > len(head):
        raise FormatError("truncated zstd frame header")
    content: Optional[int] = None
    if fcs_size:
        raw = head[pos - fcs_size : pos]
        content = int.from_bytes(raw, "little")
        if fcs_size == 2:
            content += 256
    return content, checksum, reserved


def scan(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    deadline.check()
    offset = 0
    notes = []
    for _ in range(8):
        if offset + 8 > size:
            raise FormatError("truncated zstd frame")
        magic = u32le(read_at(fp, offset, 4))
        if magic & SKIPPABLE_MASK == SKIPPABLE_BASE:
            skip = u32le(read_at(fp, offset + 4, 4))
            offset += 8 + skip
            notes.append("skipped a zstd skippable frame")
            continue
        break
    content, checksum, reserved = _frame_header(fp, offset, size)
    if reserved:
        notes.append("zstd reserved frame-header bit is set")
    if content is None:
        notes.append(
            "zstd frame does not declare a content size; expansion cannot be "
            "determined without decompression"
        )
    return Facts(
        format="zstd",
        detail="Zstandard" + ("" if checksum else ", no content checksum"),
        declared_uncompressed=content,
        declared_compressed=size,
        notes=notes,
        unknown=content is None,
    )
