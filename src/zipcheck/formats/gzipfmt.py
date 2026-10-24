"""gzip member metadata.

gzip stores the uncompressed size in the last four bytes of each member
(``ISIZE``), modulo 2^32.  That covers only the *final* member: concatenated
members are legal, and a stream can expand past 4 GiB so the trailer wraps.
Both cases hide real output from a metadata-only scan, so a bounded
multi-member probe is always run (unless probing is disabled).  The probe
counts bytes in memory and never writes output.
"""

from __future__ import annotations

import zlib
from typing import BinaryIO, List, Optional, Tuple

from ..limits import Limits
from ..model import Facts, Finding, Severity
from ..reader import Deadline, FormatError, read_at, u16le, u32le

FHCRC = 0x02
FEXTRA = 0x04
FNAME = 0x08
FCOMMENT = 0x10
FRESERVED = 0xE0

MAGIC = b"\x1f\x8b"

# zlib discards the output buffer of a call that ends in a trailer error, so
# decode in slices: at most this much valid output is lost when a forged
# trailer makes the final call fail.
PROBE_SLICE = 1024 * 1024


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


def _probe_total(
    fp: BinaryIO, cap: int, deadline: Deadline
) -> Tuple[int, int, bool, Optional[str]]:
    """Measure the output of every concatenated member, capped at ``cap``.

    Returns ``(bytes, input_bytes, capped, error)``.  ``bytes`` never exceeds
    ``cap``; the stream is only fully measured when ``capped`` is false and
    ``error`` is None.  Members are decoded by zlib directly, so a malformed
    second-member header cannot block inside the standard library's gzip
    reader without a deadline check.
    """

    total = 0
    consumed = 0
    capped = False
    error: Optional[str] = None
    current_eof = False
    need_new_member = False
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    fp.seek(0)
    while not capped:
        deadline.check()
        chunk = fp.read(64 * 1024)
        if not chunk:
            break
        consumed += len(chunk)
        if need_new_member:
            chunk = chunk.lstrip(b"\x00")
            if not chunk:
                continue
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
            need_new_member = False
            current_eof = False
        data = chunk
        while data:
            limit = min(PROBE_SLICE, cap - total + 1)
            try:
                produced = decompressor.decompress(data, limit)
            except zlib.error as exc:
                error = str(exc)
                break
            total += len(produced)
            if total > cap:
                total = cap
                capped = True
                break
            if decompressor.eof:
                current_eof = True
                data = decompressor.unused_data.lstrip(b"\x00")
                if not data:
                    need_new_member = True
                    break
                decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                current_eof = False
                continue
            tail = decompressor.unconsumed_tail
            if tail:
                data = tail
                continue
            data = b""
        if error or capped:
            break
    if not capped and error is None and not current_eof:
        error = "gzip stream ended before its trailer"
    return total, consumed, capped, error


def scan(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    deadline.check()
    flags, name, notes = _header(fp, size, limits)
    isize_raw = read_at(fp, size - 4, 4)
    if len(isize_raw) < 4:
        raise FormatError("gzip member has no trailer")
    isize = u32le(isize_raw)
    declared: Optional[int] = isize
    measured = False
    probe_capped = False
    probe_input: Optional[int] = None
    probe_output: Optional[int] = None
    unknown = False
    error: Optional[str] = None

    if limits.probe:
        total, consumed, capped, error = _probe_total(
            fp, limits.probe_limit, deadline
        )
        measured = True
        probe_capped = capped
        probe_input = consumed
        probe_output = total
        if capped:
            # The measured prefix is a hard lower bound.  A larger ISIZE is
            # still untrusted metadata, but it is the same claim every other
            # static rule acts on, so use it as the best available estimate.
            declared = max(total, isize)
            unknown = True
            notes.append(
                f"bounded multi-member probe stopped at {limits.probe_limit} "
                "bytes of output; the real total is larger and cannot be "
                "determined statically"
            )
            if isize > total:
                notes.append(
                    f"the final member's ISIZE claims {isize} bytes; if accurate, "
                    "the real total is at least that, but it could not be measured"
                )
            elif isize < limits.probe_limit:
                notes.append(
                    f"ISIZE declares only {isize} bytes (the final member); the "
                    "stream is already larger than that"
                )
        else:
            declared = total if total else isize
            if error:
                unknown = True
                notes.append(
                    f"bounded multi-member probe could not finish: {error}"
                )
            else:
                notes.append(
                    f"bounded multi-member probe measured {total} bytes across all "
                    "gzip members"
                )
    elif isize == 0:
        unknown = True
        notes.append(
            "ISIZE is zero; the real size cannot be determined with probing disabled"
        )

    detail = "gzip"
    if name:
        detail += f", original name {name!r}"
    notes.append("gzip ISIZE describes only the final member and wraps at 4 GiB")

    findings: List[Finding] = []
    if (
        measured
        and not probe_capped
        and error is None
        and isize
        and declared is not None
        and declared > isize
    ):
        findings.append(
            Finding(
                code="ISIZE_UNDERSTATED",
                severity=Severity.LOW,
                title="gzip ISIZE does not cover the whole stream",
                detail=(
                    f"The final member's ISIZE trailer declares {isize} bytes, "
                    f"but bounded decompression measured {declared} bytes across "
                    "concatenated members. This is legal for multi-member gzip, "
                    "but it also hides expansion from metadata-only scans."
                ),
                evidence={"isize": isize, "measured": declared},
            )
        )

    return Facts(
        format="gzip",
        detail=detail,
        declared_uncompressed=declared,
        declared_compressed=size,
        findings=findings,
        measured=measured,
        probe_capped=probe_capped,
        probe_input=probe_input,
        probe_output=probe_output,
        notes=notes,
        unknown=unknown,
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
