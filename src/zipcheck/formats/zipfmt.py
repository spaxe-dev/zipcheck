"""ZIP / ZIP64 metadata parser.

The central directory is read directly from the file; no member data is ever
decompressed just to obtain sizes.  For nested inspection the engine asks for
a *bounded prefix* of a member, which is decompressed into memory with a hard
output cap and never written to disk.
"""

from __future__ import annotations

import bz2
import struct
import zlib
from typing import BinaryIO, List, Optional, Tuple

from ..limits import Limits
from ..model import EntryInfo, Facts, Finding, Severity
from ..reader import (
    ByteReader,
    Deadline,
    FormatError,
    read_at,
    u16le,
    u64le,
)

EOCD_SIG = b"PK\x05\x06"
ZIP64_EOCD_SIG = b"PK\x06\x06"
ZIP64_LOCATOR_SIG = b"PK\x06\x07"
CD_SIG = b"PK\x01\x02"
LOCAL_SIG = b"PK\x03\x04"

EOCD_MIN = 22
MAX_COMMENT = 65535

METHOD_NAMES = {
    0: "stored",
    8: "deflate",
    9: "deflate64",
    12: "bzip2",
    14: "lzma",
    93: "zstd",
    95: "xz",
    98: "ppmd",
    99: "aes",
}

DEFLATE_METHOD = 8
STORED_METHOD = 0
BZIP2_METHOD = 12

FLAG_ENCRYPTED = 0x0001
FLAG_DATA_DESCRIPTOR = 0x0008
FLAG_UTF8 = 0x0800


def _decode_name(raw: bytes, flags: int) -> str:
    if flags & FLAG_UTF8:
        return raw.decode("utf-8", "replace")
    try:
        return raw.decode("cp437")
    except UnicodeDecodeError:  # pragma: no cover - cp437 is total
        return raw.decode("latin-1", "replace")


def _is_suspicious_path(name: str) -> bool:
    if not name:
        return False
    norm = name.replace("\\", "/")
    if norm.startswith("/") or (len(norm) > 1 and norm[1] == ":"):
        return True
    return any(part == ".." for part in norm.split("/"))


def _parse_zip64_extra(
    extra: bytes, sentinel: List[str]
) -> Tuple[dict, bool]:
    """Return (values, ok).  Values are consumed in ZIP64 field order."""
    values = {}
    pos = 0
    while pos + 4 <= len(extra):
        header_id, size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        body = extra[pos : pos + size]
        pos += size
        if header_id != 0x0001:
            continue
        reader = ByteReader(body)
        for field in sentinel:
            try:
                values[field] = reader.u32() if field == "disk" else reader.u64()
            except FormatError:
                return values, False
        return values, True
    return values, not sentinel


def _find_eocd(fp: BinaryIO, size: int) -> Tuple[int, bytes]:
    tail_len = min(size, EOCD_MIN + MAX_COMMENT + 16)
    tail = read_at(fp, size - tail_len, tail_len)
    search_end = len(tail)
    while True:
        idx = tail.rfind(EOCD_SIG, 0, search_end)
        if idx < 0:
            raise FormatError("ZIP end-of-central-directory signature not found")
        abs_pos = size - tail_len + idx
        if idx + EOCD_MIN <= len(tail):
            comment_len = u16le(tail, idx + 20)
            if abs_pos + EOCD_MIN + comment_len <= size + 4:  # tolerate tiny trailing junk
                return abs_pos, tail[idx : idx + EOCD_MIN]
        search_end = idx


def scan(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    deadline.check()
    if size < EOCD_MIN:
        raise FormatError("file is too small to be a ZIP archive")

    eocd_pos, eocd = _find_eocd(fp, size)
    (
        _sig,
        _disk,
        cd_disk,
        entries_disk,
        total_entries,
        cd_size,
        cd_offset,
        comment_len,
    ) = struct.unpack_from("<IHHHHIIH", eocd, 0)

    notes: List[str] = []
    findings: List[Finding] = []
    z64_pos: Optional[int] = None

    need_zip64 = (
        total_entries == 0xFFFF
        or cd_size == 0xFFFFFFFF
        or cd_offset == 0xFFFFFFFF
        or entries_disk == 0xFFFF
    )
    if need_zip64 or size > 0xFFFFFFFF:
        z64_pos = _find_zip64_eocd(fp, eocd_pos, size)
    if z64_pos is not None:
        z64 = read_at(fp, z64_pos, 56)
        if len(z64) < 56 or not z64.startswith(ZIP64_EOCD_SIG):
            notes.append("ZIP64 locator points at an invalid record; using classic EOCD")
        else:
            total_entries = u64le(z64, 32)
            entries_disk = u64le(z64, 24)
            cd_size = u64le(z64, 40)
            cd_offset = u64le(z64, 48)
            need_zip64 = False
    elif need_zip64:
        notes.append("ZIP64 EOCD expected but not found; counts may be truncated")

    if comment_len and eocd_pos + EOCD_MIN + comment_len > size:
        notes.append("EOCD comment length exceeds the file; archive may be truncated")

    cd_reader = ByteReader(b"")
    cd_start = 0
    if cd_size:
        reference = z64_pos if z64_pos is not None else eocd_pos
        delta = reference - (cd_offset + cd_size)
        if delta < 0:
            notes.append(
                "central directory overlaps the end record; using unadjusted offsets"
            )
            delta = 0
        cd_start = cd_offset + delta
        if cd_start < 0 or cd_start + cd_size > size:
            # Some archives have a bogus EOCD offset but a usable size.
            candidate_start = max(0, reference - cd_size)
            if candidate_start + cd_size <= size:
                notes.append("central directory offset was invalid; recovered from EOCD")
                cd_start = candidate_start
                delta = cd_start - cd_offset
            else:
                raise FormatError("central directory lies outside the file")
        read_len = min(cd_size, limits.max_cd_bytes)
        cd_reader = ByteReader(read_at(fp, cd_start, read_len))
        if read_len < cd_size:
            notes.append(
                f"central directory truncated at {read_len} bytes for safety; "
                "declared totals are partial"
            )
    else:
        delta = 0

    parse_count = min(int(total_entries), limits.max_entries_parse)
    if total_entries > parse_count:
        notes.append(
            f"only the first {parse_count} of {total_entries} entries were parsed; "
            "totals are partial"
        )

    entries: List[EntryInfo] = []
    data_ranges: List[Tuple[int, int, str]] = []
    local_offsets: dict = {}
    total_usize = 0
    total_csize = 0
    encrypted = 0
    lzma_entries = 0
    parsed = 0
    complete = parse_count == total_entries and cd_size <= limits.max_cd_bytes

    while parsed < parse_count and cd_reader.remaining() >= 46:
        if parsed % 1024 == 0:
            deadline.check()
        start = cd_reader.pos
        sig = cd_reader.take(4)
        if sig != CD_SIG:
            notes.append("central directory entry signature mismatch; stopping early")
            complete = False
            break
        (
            _made,
            _needed,
            flags,
            method_id,
            _mtime,
            _mdate,
            _crc,
            csize,
            usize,
            name_len,
            extra_len,
            comment_len_e,
            disk_start,
            _iattr,
            _eattr,
            local_offset,
        ) = struct.unpack_from("<HHHHHHIIIHHHHHII", cd_reader.data, start + 4)
        cd_reader.skip(42)
        name_raw = cd_reader.take(name_len)
        extra = cd_reader.take(extra_len)
        cd_reader.skip(comment_len_e)

        sentinel = []
        if usize == 0xFFFFFFFF:
            sentinel.append("usize")
        if csize == 0xFFFFFFFF:
            sentinel.append("csize")
        if local_offset == 0xFFFFFFFF:
            sentinel.append("offset")
        if disk_start == 0xFFFF:
            sentinel.append("disk")
        if sentinel:
            zvals, ok = _parse_zip64_extra(extra, sentinel)
            if not ok:
                notes.append("truncated ZIP64 extra field; sizes may be wrong")
                complete = False
            usize = zvals.get("usize", usize)
            csize = zvals.get("csize", csize)
            local_offset = zvals.get("offset", local_offset)
            disk_start = zvals.get("disk", disk_start)

        name = _decode_name(name_raw, flags)
        is_dir = name.endswith("/") or name.endswith("\\")
        enc = bool(flags & FLAG_ENCRYPTED)
        method = METHOD_NAMES.get(method_id, f"method-{method_id}")
        if enc:
            encrypted += 1
        if method_id == 14:
            lzma_entries += 1

        adjusted_local = local_offset + delta
        data_offset = _local_data_offset(fp, adjusted_local, size, limits)
        if data_offset is None:
            notes.append(f"entry {name!r} has an invalid local header offset")
            complete = False
        elif csize > 0 and not is_dir:
            end = data_offset + csize
            if end > size:
                notes.append(f"entry {name!r} declares data past end of file")
            data_ranges.append((data_offset, end, name))
            if adjusted_local in local_offsets and csize > 0:
                findings.append(
                    Finding(
                        code="OVERLAPPING_ENTRIES",
                        severity=Severity.HIGH,
                        title="Multiple entries share one local header",
                        detail=(
                            f"Entries {local_offsets[adjusted_local]!r} and {name!r} "
                            "point at the same local header. This is a classic "
                            "non-recursive ZIP-bomb technique."
                        ),
                        evidence={"entries": [local_offsets[adjusted_local], name]},
                    )
                )
            local_offsets[adjusted_local] = name

        entry = EntryInfo(
            name=name,
            usize=usize,
            csize=csize,
            method=method,
            is_dir=is_dir,
            encrypted=enc,
            data_offset=data_offset,
        )
        entries.append(entry)
        total_usize += usize
        total_csize += csize
        parsed += 1

        if _is_suspicious_path(name):
            findings.append(
                Finding(
                    code="UNSAFE_PATH",
                    severity=Severity.LOW,
                    title="Archive member escapes the extraction directory",
                    detail=f"Member name {name!r} is absolute or contains '..'.",
                    evidence={"name": name},
                )
            )

        if method_id == DEFLATE_METHOD and csize > 0 and usize >= limits.min_expansion_bytes:
            ratio = usize / csize
            if ratio > limits.deflate_max_ratio:
                findings.append(
                    Finding(
                        code="IMPOSSIBLE_DEFLATE_RATIO",
                        severity=Severity.HIGH,
                        title="Declared ratio exceeds DEFLATE's theoretical maximum",
                        detail=(
                            f"Entry {name!r} declares {usize} bytes from {csize} "
                            f"compressed bytes ({ratio:,.0f}:1). DEFLATE cannot exceed "
                            f"~{limits.deflate_max_ratio:.0f}:1, so the metadata is "
                            "lying or entries overlap."
                        ),
                        evidence={
                            "name": name,
                            "usize": usize,
                            "csize": csize,
                            "ratio": ratio,
                        },
                    )
                )
        if method_id == STORED_METHOD and csize > 0 and usize > csize * 1.01:
            findings.append(
                Finding(
                    code="STORED_SIZE_MISMATCH",
                    severity=Severity.HIGH,
                    title="Stored member claims to expand",
                    detail=(
                        f"Stored (uncompressed) entry {name!r} declares {usize} bytes "
                        f"but only {csize} bytes are stored. This is only possible if "
                        "the data is shared with another entry."
                    ),
                    evidence={"name": name, "usize": usize, "csize": csize},
                )
            )

    if parsed == 0 and total_entries:
        raise FormatError("no central-directory entries could be parsed")

    overlap = _find_overlap(data_ranges)
    if overlap:
        a, b = overlap
        findings.append(
            Finding(
                code="OVERLAPPING_DATA",
                severity=Severity.HIGH,
                title="Entry data ranges overlap",
                detail=(
                    f"The compressed data of {a[2]!r} and {b[2]!r} overlap in the "
                    "file. Overlapping ranges let many central-directory entries "
                    "expand the same bytes (non-recursive zip bomb)."
                ),
                evidence={"first": a[2], "second": b[2]},
            )
        )

    if total_csize > size + 1024:
        findings.append(
            Finding(
                code="INCONSISTENT_TOTALS",
                severity=Severity.MEDIUM,
                title="Declared compressed sizes exceed the file size",
                detail=(
                    f"Central directory claims {total_csize} compressed bytes but the "
                    f"file is only {size} bytes. Entries likely overlap or lie."
                ),
                evidence={"declared_compressed": total_csize, "file_size": size},
            )
        )

    if lzma_entries and limits.max_depth:
        notes.append(
            f"{lzma_entries} LZMA-compressed ZIP member(s) are not recursively inspected"
        )

    archive_names = (
        ".zip",
        ".zipx",
        ".7z",
        ".rar",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".tbz2",
        ".xz",
        ".txz",
        ".zst",
        ".lzma",
    )
    encrypted_archives = [
        entry.name
        for entry in entries
        if entry.encrypted and entry.name.lower().endswith(archive_names)
    ]
    if encrypted_archives:
        findings.append(
            Finding(
                code="ENCRYPTED_NESTED_ARCHIVE",
                severity=Severity.MEDIUM,
                title="Encrypted archive members cannot be inspected",
                detail=(
                    f"{len(encrypted_archives)} encrypted member(s) look like archives. "
                    "Their content cannot be recursed into without a password, so a "
                    "nested bomb cannot be ruled out."
                ),
                evidence={"members": encrypted_archives[:10]},
            )
        )

    if not entries and total_entries == 0:
        notes.append("archive has no members")

    return Facts(
        format="zip",
        detail=f"ZIP, {len(entries)} parsed entries",
        declared_uncompressed=total_usize,
        declared_compressed=total_csize,
        entry_count=int(total_entries),
        entries=entries,
        findings=findings,
        notes=notes,
        complete=complete,
        encrypted=encrypted > 0,
    )


def _find_zip64_eocd(fp: BinaryIO, eocd_pos: int, size: int) -> Optional[int]:
    window = min(eocd_pos, 256)
    tail = read_at(fp, eocd_pos - window, window + EOCD_MIN)
    idx = tail.rfind(ZIP64_LOCATOR_SIG, 0, window)
    if idx < 0:
        return None
    locator = tail[idx : idx + 20]
    if len(locator) < 20:
        return None
    offset = u64le(locator, 8)
    if 0 <= offset <= size - 56:
        return offset
    return None


def _local_data_offset(
    fp: BinaryIO, local_offset: int, size: int, limits: Limits
) -> Optional[int]:
    if local_offset < 0 or local_offset + 30 > size:
        return None
    header = read_at(fp, local_offset, 30)
    if len(header) < 30 or not header.startswith(LOCAL_SIG):
        return None
    name_len = u16le(header, 26)
    extra_len = u16le(header, 28)
    if name_len > limits.max_name_bytes or extra_len > limits.max_header_bytes:
        return None
    data_offset = local_offset + 30 + name_len + extra_len
    if data_offset > size:
        return None
    return data_offset


def _find_overlap(
    ranges: List[Tuple[int, int, str]]
) -> Optional[Tuple[Tuple[int, int, str], Tuple[int, int, str]]]:
    ordered = sorted(ranges)
    previous = None
    for current in ordered:
        if (
            previous is not None
            and current[0] < previous[1]
            and previous[2] != current[2]
        ):
            return previous, current
        if previous is None or current[1] > previous[1]:
            previous = current
    return None


def parse_prefix(data: bytes, limits: Limits) -> Facts:
    """Parse local headers from a bounded prefix of a ZIP member.

    The prefix usually lacks the central directory, so this path is explicitly
    partial.  It is still enough to expose classic nested bombs whose first
    local header declares petabytes.
    """

    start = data.find(LOCAL_SIG, 0, min(len(data), 4096))
    if start < 0:
        raise FormatError("no ZIP local header in prefix")
    pos = start
    entries: List[EntryInfo] = []
    findings: List[Finding] = []
    notes = ["nested archive inspected from a bounded prefix only"]
    total_usize = total_csize = 0
    while pos + 30 <= len(data) and len(entries) < limits.max_entries_parse:
        if data[pos : pos + 4] != LOCAL_SIG:
            break
        (flags, method_id, _t, _d, _crc, csize, usize, name_len, extra_len) = (
            struct.unpack_from("<HHHHIIIHH", data, pos + 4)
        )
        name_start = pos + 30
        name_raw = data[name_start : name_start + name_len]
        extra = data[name_start + name_len : name_start + name_len + extra_len]
        if len(name_raw) < name_len:
            break
        if flags & FLAG_ENCRYPTED:
            notes.append("nested ZIP member is encrypted")
            break
        sentinel = []
        if usize == 0xFFFFFFFF:
            sentinel.append("usize")
        if csize == 0xFFFFFFFF:
            sentinel.append("csize")
        if sentinel:
            zvals, _ok = _parse_zip64_extra(extra, sentinel)
            usize = zvals.get("usize", usize)
            csize = zvals.get("csize", csize)
        name = _decode_name(name_raw, flags)
        data_start = name_start + name_len + extra_len
        if flags & FLAG_DATA_DESCRIPTOR and csize == 0 and usize == 0:
            entries.append(
                EntryInfo(
                    name=name,
                    usize=None,
                    csize=None,
                    method=METHOD_NAMES.get(method_id, f"method-{method_id}"),
                    is_dir=name.endswith("/"),
                    data_offset=data_start,
                )
            )
            notes.append("local header uses a data descriptor; sizes unavailable")
            break
        entry = EntryInfo(
            name=name,
            usize=usize,
            csize=csize,
            method=METHOD_NAMES.get(method_id, f"method-{method_id}"),
            is_dir=name.endswith("/"),
            data_offset=data_start,
        )
        entries.append(entry)
        total_usize += usize
        total_csize += csize
        if data_start + csize > len(data):
            notes.append("nested ZIP prefix ends inside member data")
            break
        pos = data_start if csize == 0 and usize == 0 else data_start + csize
    if not entries:
        raise FormatError("no complete ZIP local header found in prefix")

    overlap = _find_overlap(
        [
            (e.data_offset or 0, (e.data_offset or 0) + (e.csize or 0), e.name)
            for e in entries
            if e.csize and e.usize and e.data_offset is not None
        ]
    )
    if overlap:
        findings.append(
            Finding(
                code="OVERLAPPING_DATA",
                severity=Severity.HIGH,
                title="Nested ZIP entry data ranges overlap",
                detail="Overlapping ranges indicate a non-recursive zip bomb.",
                evidence={"first": overlap[0][2], "second": overlap[1][2]},
            )
        )

    return Facts(
        format="zip",
        detail=f"ZIP prefix, {len(entries)} local header(s)",
        declared_uncompressed=total_usize,
        declared_compressed=total_csize,
        entry_count=len(entries),
        entries=entries,
        findings=findings,
        notes=notes,
        complete=False,
    )


def member_prefix(
    fp: BinaryIO,
    entry: EntryInfo,
    cap: int,
    max_compressed: int,
    deadline: Deadline,
) -> bytes:
    """Read at most ``cap`` decompressed bytes of one member, in memory.

    No output is written anywhere.  Compressed input is also capped.  Stored,
    deflate and bzip2 members are supported; other methods return b"".
    """

    if entry.data_offset is None or entry.encrypted or not entry.csize:
        return b""
    csize = entry.csize
    if csize > max_compressed:
        return b""
    method = entry.method
    fp.seek(entry.data_offset)
    if method == "stored":
        return fp.read(min(cap, csize))

    if method == "deflate":
        decompressor = zlib.decompressobj(-15)
    elif method == "bzip2":
        decompressor = bz2.BZ2Decompressor()
    else:
        return b""

    out = bytearray()
    remaining = min(csize, max_compressed)
    while remaining > 0 and len(out) < cap:
        deadline.check()
        chunk = fp.read(min(64 * 1024, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
        try:
            produced = decompressor.decompress(chunk, cap - len(out))
        except (zlib.error, OSError, ValueError):
            break
        out.extend(produced)
        if getattr(decompressor, "eof", False):
            break
        if getattr(decompressor, "unused_data", b""):
            break
    return bytes(out)
