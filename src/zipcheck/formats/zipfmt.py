"""ZIP / ZIP64 metadata parser.

The central directory is read directly from the file; no member data is ever
decompressed just to obtain sizes.  For nested inspection the engine asks for
a *bounded prefix* of a member, which is decompressed into memory with a hard
output cap and never written to disk.
"""

from __future__ import annotations

import bz2
import lzma
import struct
import zlib
from dataclasses import dataclass
from typing import Any, BinaryIO, List, Optional, Tuple

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
from ..verify import count_zip_entry

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

# Only the ZIP64 field is needed from a local extra area; cap the read so a
# header cannot force a large allocation or I/O per entry.
LOCAL_EXTRA_READ = 64 * 1024

_HIGH_RISK_MISMATCHES = {
    "compression method",
    "uncompressed size",
    "compressed size",
    "encryption flag",
}


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

    # The EOCD entry count is attacker-controlled.  Parse the central
    # directory to its declared end (bounded), not just to the advertised
    # count: hiding extra entries behind a small EOCD is a known bypass.
    declared_total = int(total_entries)
    entries: List[EntryInfo] = []
    data_ranges: List[Tuple[int, int, str]] = []
    local_offsets: dict = {}
    structural_starts: List[int] = []
    header_mismatches: List[dict] = []
    high_risk_mismatch = False
    total_usize = 0
    total_csize = 0
    encrypted = 0
    lzma_entries = 0
    parsed = 0
    complete = cd_size <= limits.max_cd_bytes

    while parsed < limits.max_entries_parse and cd_reader.remaining() >= 46:
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
        local = _parse_local_header(fp, adjusted_local, size, limits)
        data_offset: Optional[int] = None
        if local is None:
            notes.append(f"entry {name!r} has an invalid local header offset")
            complete = False
        else:
            data_offset = local.data_offset
            structural_starts.append(adjusted_local)
            if local.usize is None or local.csize is None:
                notes.append(f"entry {name!r} has unresolved ZIP64 local sizes")
                complete = False
            conflicts = _header_conflicts(
                local, flags, method_id, csize, usize, name_raw
            )
            if conflicts:
                header_mismatches.append(
                    {
                        "name": name,
                        "fields": conflicts,
                        "central": {
                            "usize": usize,
                            "csize": csize,
                            "method": method_id,
                        },
                        "local": {
                            "usize": local.usize,
                            "csize": local.csize,
                            "method": local.method,
                        },
                    }
                )
                if any(kind in _HIGH_RISK_MISMATCHES for kind in conflicts):
                    high_risk_mismatch = True
            if csize > 0 and not is_dir:
                end = data_offset + csize
                if end > size:
                    notes.append(f"entry {name!r} declares data past end of file")
                data_ranges.append((data_offset, end, name))
                if adjusted_local in local_offsets:
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

    if parsed == 0 and (declared_total or cd_size):
        raise FormatError("no central-directory entries could be parsed")

    if header_mismatches:
        findings.append(
            Finding(
                code="HEADER_MISMATCH",
                severity=(
                    Severity.HIGH if high_risk_mismatch else Severity.MEDIUM
                ),
                title="Local header disagrees with the central directory",
                detail=(
                    f"{len(header_mismatches)} member(s) advertise different "
                    "metadata in the local header and the central directory. "
                    "Extractors disagree on which copy is authoritative, so the "
                    "declared totals cannot be trusted."
                ),
                evidence={
                    "count": len(header_mismatches),
                    "samples": header_mismatches[:5],
                },
            )
        )

    remaining_cd = cd_reader.remaining()
    # Leftover CD bytes only mean "hidden" when the EOCD count is *lower* than
    # what was parsed.  Stopping at the entry cap with more declared entries is
    # truncation, not an understated count.
    hidden_entries = (
        remaining_cd >= 4
        and cd_reader.data[cd_reader.pos : cd_reader.pos + 4] == CD_SIG
        and parsed >= declared_total
        and parsed < limits.max_entries_parse
    )
    if hidden_entries:
        complete = False
        findings.append(
            Finding(
                code="ENTRY_COUNT_MISMATCH",
                severity=Severity.HIGH,
                title="Central directory contains entries the EOCD does not count",
                detail=(
                    "The end-of-central-directory record advertises "
                    f"{declared_total} member(s), but the central directory "
                    f"contains at least {parsed + 1}. Scanners that trust the "
                    "count see less than an extractor that walks the directory."
                ),
                evidence={
                    "declared_entries": declared_total,
                    "parsed_entries": parsed,
                    "directory_bytes_left": remaining_cd,
                },
            )
        )
    elif parsed > declared_total:
        complete = False
        findings.append(
            Finding(
                code="ENTRY_COUNT_MISMATCH",
                severity=Severity.HIGH,
                title="Central directory contains more entries than declared",
                detail=(
                    f"The EOCD advertises {declared_total} member(s) but "
                    f"{parsed} were parsed. Hidden entries can change extraction "
                    "behaviour between tools."
                ),
                evidence={
                    "declared_entries": declared_total,
                    "parsed_entries": parsed,
                },
            )
        )
    elif parsed < declared_total:
        complete = False
        if parsed >= limits.max_entries_parse:
            notes.append(
                f"central directory entry limit {limits.max_entries_parse} "
                "reached; totals are partial"
            )
        findings.append(
            Finding(
                code="ENTRY_COUNT_MISMATCH",
                severity=Severity.MEDIUM,
                title="Central directory has fewer entries than declared",
                detail=(
                    f"The EOCD advertises {declared_total} member(s) but only "
                    f"{parsed} could be parsed. The archive is truncated or its "
                    "metadata is inconsistent."
                ),
                evidence={
                    "declared_entries": declared_total,
                    "parsed_entries": parsed,
                },
            )
        )

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

    _probe_stream_tails(
        fp,
        size,
        entries,
        structural_starts,
        cd_start,
        limits,
        deadline,
        findings,
        notes,
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

    if not entries and declared_total == 0:
        notes.append("archive has no members")

    return Facts(
        format="zip",
        detail=f"ZIP, {len(entries)} parsed entries",
        declared_uncompressed=total_usize,
        declared_compressed=total_csize,
        entry_count=parsed,
        entries=entries,
        findings=findings,
        notes=notes,
        complete=complete,
        encrypted=encrypted > 0,
    )


def _probe_stream_tails(
    fp: BinaryIO,
    size: int,
    entries: List[EntryInfo],
    structural_starts: List[int],
    cd_start: int,
    limits: Limits,
    deadline: Deadline,
    findings: List[Finding],
    notes: List[str],
) -> None:
    """Check that member streams end where the central directory says.

    A forged compressed size can be internally consistent (both headers agree)
    and leave the real stream in an *unclaimed gap* before the next structure.
    Probing only those gaps keeps static scans from decompressing normal
    archives while still exposing the crude forged-size class.
    """

    if not limits.probe or limits.verify:
        return
    starts = sorted(set(structural_starts))
    if cd_start > 0:
        starts.append(cd_start)
        starts.sort()

    probes = 0
    output_left = limits.stream_probe_total_output
    cap_hit = False
    under_compressed: List[str] = []
    under_output: List[Tuple[str, int, int]] = []

    for entry in entries:
        if entry.is_dir or entry.encrypted or entry.data_offset is None:
            continue
        if entry.csize is None or entry.usize is None:
            continue
        if entry.method not in ("deflate", "bzip2", "lzma"):
            continue
        if entry.csize <= 0 or entry.csize > limits.stream_probe_max_compressed:
            continue
        end = entry.data_offset + entry.csize
        if end > size:
            continue
        boundary = next((start for start in starts if start >= end), size)
        if boundary <= end:
            continue
        if entry.usize + 1 > limits.stream_probe_max_output:
            continue
        if entry.usize + 1 > output_left:
            cap_hit = True
            break
        if probes >= limits.stream_probe_max_entries:
            cap_hit = True
            break
        deadline.check()
        probes += 1
        counted = count_zip_entry(
            fp, size, entry, entry.usize + 1, limits, deadline
        )
        output_left -= counted.total
        if counted.error:
            continue
        if counted.total > entry.usize:
            under_output.append((entry.name, entry.usize, counted.total))
        elif not counted.eof and counted.fed >= entry.csize:
            under_compressed.append(entry.name)

    if under_compressed:
        findings.append(
            Finding(
                code="UNDERSTATED_COMPRESSED_SIZE",
                severity=Severity.HIGH,
                title="Member stream continues past its declared compressed size",
                detail=(
                    f"{len(under_compressed)} member(s) have compressed streams "
                    "that do not end at the size in the central directory. An "
                    "extractor that reads to stream end consumes data the "
                    "metadata hides."
                ),
                evidence={"members": under_compressed[:5]},
            )
        )
    if under_output:
        samples = [
            {"name": name, "declared": declared, "actual_at_least": actual}
            for name, declared, actual in under_output[:5]
        ]
        findings.append(
            Finding(
                code="METADATA_UNDERSTATED",
                severity=Severity.HIGH,
                title="Member data exceeds its declared size",
                detail=(
                    f"{len(under_output)} member(s) produced more output than the "
                    "central directory declares during a bounded static probe. "
                    "Extraction tools may write the real data, not the declared "
                    "size."
                ),
                evidence={"samples": samples},
            )
        )
    if cap_hit:
        notes.append(
            "bounded stream-tail probe limit reached; later members were not probed"
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


@dataclass
class _LocalHeader:
    data_offset: int
    flags: int
    method: int
    csize: Optional[int]
    usize: Optional[int]
    name: bytes


def _parse_local_header(
    fp: BinaryIO, local_offset: int, size: int, limits: Limits
) -> Optional[_LocalHeader]:
    if local_offset < 0 or local_offset + 30 > size:
        return None
    header = read_at(fp, local_offset, 30)
    if len(header) < 30 or not header.startswith(LOCAL_SIG):
        return None
    (
        _version,
        flags,
        method_id,
        _time,
        _date,
        _crc,
        csize,
        usize,
        name_len,
        extra_len,
    ) = struct.unpack_from("<HHHHHIIIHH", header, 4)
    if name_len > limits.max_name_bytes:
        return None
    data_offset = local_offset + 30 + name_len + extra_len
    if data_offset > size:
        return None
    name = read_at(fp, local_offset + 30, name_len)
    if len(name) < name_len:
        return None

    resolved_u: Optional[int] = usize
    resolved_c: Optional[int] = csize
    if usize == 0xFFFFFFFF or csize == 0xFFFFFFFF:
        sentinel = []
        if usize == 0xFFFFFFFF:
            sentinel.append("usize")
        if csize == 0xFFFFFFFF:
            sentinel.append("csize")
        extra = read_at(
            fp,
            local_offset + 30 + name_len,
            min(extra_len, LOCAL_EXTRA_READ),
        )
        zvals, ok = _parse_zip64_extra(extra, sentinel)
        if not ok:
            resolved_u = resolved_c = None
        else:
            resolved_u = zvals.get("usize", usize)
            resolved_c = zvals.get("csize", csize)
            if resolved_u == 0xFFFFFFFF:
                resolved_u = None
            if resolved_c == 0xFFFFFFFF:
                resolved_c = None
    return _LocalHeader(
        data_offset=data_offset,
        flags=flags,
        method=method_id,
        csize=resolved_c,
        usize=resolved_u,
        name=name,
    )


def _header_conflicts(
    local: _LocalHeader,
    flags: int,
    method_id: int,
    csize: int,
    usize: int,
    name_raw: bytes,
) -> List[str]:
    conflicts: List[str] = []
    if local.method != method_id:
        conflicts.append("compression method")
    if local.name != name_raw:
        conflicts.append("member name")
    if (local.flags ^ flags) & FLAG_ENCRYPTED:
        conflicts.append("encryption flag")
    if (local.flags ^ flags) & FLAG_DATA_DESCRIPTOR:
        conflicts.append("data-descriptor flag")
    # A data descriptor legitimately leaves the local sizes at zero.
    descriptor_sizes = (
        bool(flags & FLAG_DATA_DESCRIPTOR)
        and local.csize == 0
        and local.usize == 0
    )
    if not descriptor_sizes:
        if local.usize is not None and local.usize != usize:
            conflicts.append("uncompressed size")
        if local.csize is not None and local.csize != csize:
            conflicts.append("compressed size")
    return conflicts


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
        (
            _version,
            flags,
            method_id,
            _t,
            _d,
            _crc,
            csize,
            usize,
            name_len,
            extra_len,
        ) = struct.unpack_from("<HHHHHIIIHH", data, pos + 4)
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


def _zip_lzma_stream(
    fp: BinaryIO, csize: int, max_dict: int
) -> Optional[Tuple[lzma.LZMADecompressor, int]]:
    """Consume a ZIP LZMA entry header; return (decoder, payload bytes left)."""

    header = fp.read(4)
    if len(header) < 4:
        return None
    props_size = u16le(header, 2)
    if props_size < 5 or props_size > 64 or 4 + props_size > csize:
        return None
    props = fp.read(props_size)
    if len(props) < props_size:
        return None
    prop0 = props[0]
    lc = prop0 % 9
    rest = prop0 // 9
    lp = rest % 5
    pb = rest // 5
    dict_size = int.from_bytes(props[1:5], "little")
    if dict_size > max_dict:
        return None
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "lc": lc,
            "lp": lp,
            "pb": pb,
            "dict_size": max(dict_size, 4096),
        }
    ]
    try:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    except (lzma.LZMAError, ValueError):
        return None
    return decoder, csize - 4 - props_size


def member_probe(
    fp: BinaryIO,
    entry: EntryInfo,
    cap: int,
    max_input: int,
    max_dict: int,
    deadline: Deadline,
) -> bytes:
    """Read a small decompressed prefix without trusting ``csize`` as a bound.

    Used only to identify archives that are too large to capture in full.
    Compressed input and output are both capped.
    """

    if entry.data_offset is None or entry.encrypted or not entry.csize:
        return b""
    csize = entry.csize
    fp.seek(entry.data_offset)
    if entry.method == "stored":
        return fp.read(min(cap, csize))

    decompressor: Any
    if entry.method == "deflate":
        decompressor = zlib.decompressobj(-15)
        remaining = min(csize, max_input)
    elif entry.method == "bzip2":
        decompressor = bz2.BZ2Decompressor()
        remaining = min(csize, max_input)
    elif entry.method == "lzma":
        opened = _zip_lzma_stream(fp, csize, max_dict)
        if opened is None:
            return b""
        decompressor, payload = opened
        remaining = min(payload, max_input)
    else:
        return b""

    out = bytearray()
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
    return bytes(out)


def member_image(
    fp: BinaryIO,
    size: int,
    entry: EntryInfo,
    cap: int,
    max_compressed: int,
    max_dict: int,
    deadline: Deadline,
) -> Tuple[bytes, bool]:
    """Materialize a complete member image, bounded by ``cap``.

    Returns ``(data, complete)``.  ``complete`` is only true when the member's
    entire decompressed payload fits in ``cap`` and the compressed stream
    actually terminated inside its declared range.
    """

    if entry.data_offset is None or entry.encrypted or not entry.csize:
        return b"", False
    csize = entry.csize
    if csize > max_compressed or entry.data_offset + csize > size:
        return b"", False
    fp.seek(entry.data_offset)

    if entry.method == "stored":
        data = fp.read(min(cap, csize))
        return data, csize <= cap and len(data) == csize

    decompressor: Any
    if entry.method == "deflate":
        decompressor = zlib.decompressobj(-15)
        remaining = csize
    elif entry.method == "bzip2":
        decompressor = bz2.BZ2Decompressor()
        remaining = csize
    elif entry.method == "lzma":
        opened = _zip_lzma_stream(fp, csize, max_dict)
        if opened is None:
            return b"", False
        decompressor, remaining = opened
    else:
        return b"", False

    out = bytearray()
    while remaining > 0 and len(out) < cap:
        deadline.check()
        chunk = fp.read(min(64 * 1024, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
        try:
            produced = decompressor.decompress(chunk, cap - len(out))
        except (zlib.error, OSError, ValueError):
            return bytes(out), False
        out.extend(produced)
        if getattr(decompressor, "eof", False):
            return bytes(out), True
        if getattr(decompressor, "unused_data", b""):
            return bytes(out), True
    return bytes(out), False


def member_prefix(
    fp: BinaryIO,
    entry: EntryInfo,
    cap: int,
    max_compressed: int,
    max_dict: int,
    deadline: Deadline,
) -> bytes:
    """Read at most ``cap`` decompressed bytes of one member, in memory.

    No output is written anywhere.  Compressed input is also capped.  Stored,
    deflate, bzip2 and LZMA members are supported; other methods return b"".
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

    decompressor: Any
    if method == "deflate":
        decompressor = zlib.decompressobj(-15)
        remaining = min(csize, max_compressed)
    elif method == "bzip2":
        decompressor = bz2.BZ2Decompressor()
        remaining = min(csize, max_compressed)
    elif method == "lzma":
        opened = _zip_lzma_stream(fp, csize, max_dict)
        if opened is None:
            return b""
        decompressor, payload = opened
        remaining = min(payload, max_compressed)
    else:
        return b""

    out = bytearray()
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
