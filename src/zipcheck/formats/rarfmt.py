"""RAR 4.x / RAR 5.x metadata parser.

RAR file headers carry the unpacked size of every member, so no decompression
is needed.  Encrypted headers cannot be parsed and are reported as unknown.
"""

from __future__ import annotations

import zlib
from typing import BinaryIO, List, Tuple

from ..limits import Limits
from ..model import Facts, Finding
from ..reader import ByteReader, Deadline, FormatError, read_at, u16le, u32le

RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"

# RAR5 block types
RAR5_MAIN = 1
RAR5_FILE = 2
RAR5_ENCRYPTION = 4
RAR5_END = 5

RAR5_HFL_EXTRA = 0x0001
RAR5_HFL_DATA = 0x0002

RAR5_FHFL_DIRECTORY = 0x0001
RAR5_FHFL_UTIME = 0x0002
RAR5_FHFL_CRC32 = 0x0004
RAR5_FHFL_UNPUNKNOWN = 0x0008

# RAR4 block types / flags
RAR4_FILE = 0x74
RAR4_MAIN = 0x73
RAR4_END = 0x7B
RAR4_LARGE = 0x0100
RAR4_PASSWORD = 0x0004
RAR4_MAIN_PASSWORD = 0x0080
RAR4_ADD_SIZE = 0x8000


def _vint(data: bytes, pos: int) -> Tuple[int, int]:
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
    raise FormatError("invalid RAR5 variable-length integer")


def _scan_rar5(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    pos = 8
    entries = total_usize = total_packed = 0
    headers = 0
    encrypted = False
    unknown_size = False
    notes: List[str] = []
    findings: List[Finding] = []
    complete = True

    while pos + 8 <= size:
        deadline.check()
        headers += 1
        if headers > limits.max_entries_parse:
            notes.append("RAR header limit reached; totals are partial")
            complete = False
            break
        prefix = read_at(fp, pos, 64)
        if len(prefix) < 8:
            break
        crc = u32le(prefix, 0)
        try:
            header_size, after_size = _vint(prefix, 4)
        except FormatError:
            notes.append("invalid RAR5 header size; stopping")
            complete = False
            break
        header_start = pos + after_size
        header_end = header_start + header_size
        if header_size == 0 or header_end > size:
            notes.append("RAR5 header extends past EOF; archive is truncated")
            complete = False
            break
        if header_size > limits.max_header_bytes:
            notes.append("RAR5 header exceeds safety cap")
            complete = False
            break
        header = read_at(fp, header_start, header_size)
        if len(header) < header_size:
            complete = False
            break
        if (zlib.crc32(prefix[4:after_size] + header) & 0xFFFFFFFF) != crc:
            notes.append("RAR5 header CRC mismatch (continuing)")
        try:
            r = ByteReader(header)
            block_type = r.vint()
            flags = r.vint()
            extra_size = r.vint() if flags & RAR5_HFL_EXTRA else 0
            data_size = r.vint() if flags & RAR5_HFL_DATA else 0
        except FormatError:
            notes.append("malformed RAR5 header; stopping")
            complete = False
            break

        if block_type == RAR5_FILE:
            try:
                file_flags = r.vint()
                unp_size = r.vint()
                r.vint()  # attributes
                if file_flags & RAR5_FHFL_UTIME:
                    r.skip(4)
                if file_flags & RAR5_FHFL_CRC32:
                    r.skip(4)
                r.vint()  # compression info
                r.vint()  # host OS
                name_size = r.vint()
                r.take(name_size)  # member name; not needed for size totals
            except FormatError:
                notes.append("malformed RAR5 file header; stopping")
                complete = False
                break
            if file_flags & RAR5_FHFL_UNPUNKNOWN:
                unknown_size = True
            is_dir = bool(file_flags & RAR5_FHFL_DIRECTORY)
            if not is_dir:
                entries += 1
                total_usize += unp_size
                total_packed += data_size
            # File encryption is recorded in the extra area.
            if extra_size:
                extra_start = max(0, len(header) - extra_size)
                ep = extra_start
                while ep < len(header):
                    try:
                        record_size, p = _vint(header, ep)
                        record_type, p = _vint(header, p)
                    except FormatError:
                        break
                    if record_size <= 0 or ep + record_size > len(header):
                        break
                    if record_type == 1:  # file encryption record
                        encrypted = True
                    ep += record_size
        elif block_type == RAR5_MAIN:
            try:
                archive_flags = r.vint()
            except FormatError:
                archive_flags = 0
            if archive_flags & 0x0020:
                encrypted = True
        elif block_type == RAR5_ENCRYPTION:
            encrypted = True
        elif block_type == RAR5_END:
            break

        pos = header_end + data_size

    if entries == 0:
        if encrypted:
            return Facts(
                format="rar5",
                detail="RAR 5, encrypted headers",
                unknown=True,
                encrypted=True,
                notes=[
                    "RAR headers are encrypted; member sizes cannot be read "
                    "without the password"
                ],
            )
        raise FormatError("RAR archive contains no file headers")
    if encrypted:
        notes.append("archive headers or members are encrypted; sizes may be unavailable")
    if unknown_size:
        notes.append("one or more members declare an unknown unpacked size")

    return Facts(
        format="rar5",
        detail=f"RAR 5, {entries} file(s)",
        declared_uncompressed=0 if unknown_size else total_usize,
        declared_compressed=total_packed,
        entry_count=entries,
        findings=findings,
        notes=notes,
        complete=complete,
        encrypted=encrypted,
        unknown=unknown_size,
    )


def _scan_rar4(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    pos = 7
    entries = total_usize = total_packed = 0
    headers = 0
    encrypted = False
    notes: List[str] = []
    complete = True

    while pos + 7 <= size:
        deadline.check()
        headers += 1
        if headers > limits.max_entries_parse:
            notes.append("RAR header limit reached; totals are partial")
            complete = False
            break
        header = read_at(fp, pos, 32)
        if len(header) < 7:
            break
        block_type = header[2]
        flags = u16le(header, 3)
        head_size = u16le(header, 5)
        if head_size < 7 or pos + head_size > size:
            notes.append("invalid RAR4 header size; stopping")
            complete = False
            break
        add_size = u32le(header, 7) if flags & RAR4_ADD_SIZE else 0
        block = read_at(fp, pos, head_size)
        if len(block) < head_size:
            complete = False
            break

        if block_type == RAR4_MAIN and flags & RAR4_MAIN_PASSWORD:
            encrypted = True
        if block_type == RAR4_FILE:
            if len(block) < 32:
                complete = False
                break
            pack_size = u32le(block, 7)
            unp_size = u32le(block, 11)
            name_size = u16le(block, 26)
            if flags & RAR4_PASSWORD:
                encrypted = True
            if flags & RAR4_LARGE:
                high = 32 + name_size
                if high + 8 <= len(block):
                    pack_size |= u32le(block, high) << 32
                    unp_size |= u32le(block, high + 4) << 32
                else:
                    notes.append("RAR4 large-file sizes are truncated")
            name = block[32 : 32 + name_size].decode("utf-8", "replace")
            entries += 1
            total_usize += unp_size
            total_packed += pack_size
            del name
        elif block_type == RAR4_END:
            break
        if head_size + add_size <= 0:
            break
        pos += head_size + add_size

    if entries == 0:
        raise FormatError("RAR archive contains no file headers")
    if encrypted:
        notes.append("archive is encrypted; sizes may be unavailable")

    return Facts(
        format="rar4",
        detail=f"RAR 4, {entries} file(s)",
        declared_uncompressed=total_usize,
        declared_compressed=total_packed,
        entry_count=entries,
        notes=notes,
        complete=complete,
        encrypted=encrypted,
    )


def scan(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    head = read_at(fp, 0, 8)
    if head.startswith(RAR5_MAGIC):
        return _scan_rar5(fp, size, limits, deadline)
    if head.startswith(RAR4_MAGIC):
        return _scan_rar4(fp, size, limits, deadline)
    raise FormatError("not a RAR archive")
