"""Bounded content verification.

Static metadata can be forged.  This module actually decompresses archive
content into a *counting sink* (nothing is stored or written), with hard caps on
output and time.  It exists to catch the important production failure mode:
an archive whose headers claim a small size but whose data expands far beyond
it.  It is not a sandbox and it is not a substitute for extracting in an
isolated worker with OS quotas.
"""

from __future__ import annotations

import bz2
import gzip
import lzma
import zlib
from dataclasses import dataclass, field
from typing import BinaryIO, List, Optional, Tuple

from .decrypt import (
    DECRYPTABLE_METHODS,
    DecryptionError,
    ZipDecryptor,
    open_zip_decryptor,
)
from .limits import Limits
from .model import Finding, ScanResult, Severity
from .reader import Deadline, u16le

SUPPORTED_ZIP_METHODS = {"stored", "deflate", "bzip2", "lzma"}

MAX_CHUNK = 64 * 1024
MAX_OUTPUT_PER_CALL = 1024 * 1024


@dataclass
class Verification:
    supported: bool
    verified: bool
    output_bytes: int
    declared_bytes: Optional[int]
    capped: bool
    detail: str
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


def verify_archive(
    fp: BinaryIO,
    size: int,
    result: ScanResult,
    limits: Limits,
    deadline: Deadline,
    budget: Optional[int] = None,
) -> Verification:
    if budget is None:
        budget = limits.verify_limit
    budget = max(0, budget)
    fmt = result.format
    if fmt == "zip":
        return _verify_zip(fp, size, result, limits, deadline, budget)
    if fmt == "gzip":
        return _verify_gzip(fp, size, result, limits, deadline, budget)
    if fmt == "bzip2":
        return _verify_bzip2(fp, size, result, limits, deadline, budget)
    if fmt in ("xz", "lzma"):
        return _verify_lzma(fp, size, result, limits, deadline, budget)
    if fmt == "tar":
        return _verify_tar(result, limits, budget)
    return Verification(
        supported=False,
        verified=False,
        output_bytes=0,
        declared_bytes=result.declared_uncompressed,
        capped=False,
        detail=f"content verification is not implemented for {fmt}",
        notes=[
            f"{fmt} has no dependency-free decoder here; verify it by extracting "
            "inside a resource-limited sandbox"
        ],
    )


# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------


def _verify_zip(
    fp: BinaryIO,
    size: int,
    result: ScanResult,
    limits: Limits,
    deadline: Deadline,
    budget: int,
) -> Verification:
    notes: List[str] = []
    findings: List[Finding] = []
    total = 0
    unsupported = 0
    encrypted_skipped = 0
    errors: List[str] = []
    understated: List[Tuple[str, int, int]] = []
    overstated: List[Tuple[str, int, int]] = []
    short_streams: List[str] = []
    padded_streams: List[str] = []
    capped = False
    complete = result.complete and (
        result.entry_count is None or len(result.entries) >= result.entry_count
    )

    has_encrypted = any(entry.encrypted for entry in result.entries)
    decryptor: Optional[ZipDecryptor] = None
    decrypt_error: Optional[str] = None
    if limits.password is not None and has_encrypted:
        if complete:
            try:
                decryptor = open_zip_decryptor(
                    fp, result.entries, limits.password
                )
            except DecryptionError as exc:
                decrypt_error = str(exc)
        else:
            decrypt_error = (
                "encrypted members were not decrypted because the ZIP metadata "
                "was only partially parsed"
            )

    try:
        for index, entry in enumerate(result.entries):
            deadline.check()
            if entry.is_dir:
                continue
            if entry.encrypted:
                if (
                    decryptor is None
                    or entry.method not in DECRYPTABLE_METHODS
                    or entry.csize is None
                    or entry.data_offset is None
                ):
                    unsupported += 1
                    encrypted_skipped += 1
                    continue
                remaining = budget - total
                if remaining <= 0:
                    capped = True
                    break
                decrypted = decryptor.count_member(
                    index, entry, remaining, deadline
                )
                total += decrypted.total
                if decrypted.error:
                    errors.append(f"{entry.name}: {decrypted.error}")
                if entry.usize is not None:
                    if decrypted.total > entry.usize:
                        understated.append(
                            (entry.name, entry.usize, decrypted.total)
                        )
                    elif decrypted.total < entry.usize and decrypted.eof:
                        overstated.append(
                            (entry.name, entry.usize, decrypted.total)
                        )
                if decrypted.capped or total >= budget:
                    capped = True
                    break
                continue
            if entry.method not in SUPPORTED_ZIP_METHODS:
                unsupported += 1
                continue
            if entry.csize is None or entry.data_offset is None:
                unsupported += 1
                continue
            remaining = budget - total
            if remaining <= 0:
                capped = True
                break
            counted = count_zip_entry(
                fp, size, entry, remaining, limits, deadline
            )
            total += counted.total
            declared_csize = entry.csize or 0
            data_start = entry.data_offset or 0
            available = min(declared_csize, max(0, size - data_start))

            if counted.error:
                errors.append(f"{entry.name}: {counted.error}")
            elif not counted.capped:
                if available < declared_csize:
                    errors.append(f"{entry.name}: member data is truncated")
                elif not counted.eof:
                    if counted.fed == available:
                        # We fed the directory-declared number of compressed
                        # bytes and the stream still had not terminated.  A
                        # stream-consuming extractor will read further bytes than
                        # the metadata admits.
                        short_streams.append(entry.name)
                    else:
                        errors.append(
                            f"{entry.name}: compressed stream did not terminate"
                        )
                elif counted.unused_compressed:
                    padded_streams.append(entry.name)

            if entry.usize is not None:
                if counted.total > entry.usize:
                    understated.append((entry.name, entry.usize, counted.total))
                elif counted.total < entry.usize and counted.eof:
                    overstated.append((entry.name, entry.usize, counted.total))
            if counted.capped or total >= budget:
                capped = True
                break
    finally:
        if decryptor is not None:
            decryptor.close()

    if short_streams:
        findings.append(
            Finding(
                code="UNDERSTATED_COMPRESSED_SIZE",
                severity=Severity.HIGH,
                title="Member stream continues past its declared compressed size",
                detail=(
                    f"{len(short_streams)} member(s) have DEFLATE/bzip2/LZMA "
                    "streams that do not end at the compressed size in the "
                    "central directory. An extractor that reads until stream "
                    "end will consume data the metadata hides."
                ),
                evidence={"members": short_streams[:5]},
            )
        )
    if padded_streams:
        findings.append(
            Finding(
                code="OVERSTATED_COMPRESSED_SIZE",
                severity=Severity.MEDIUM,
                title="Compressed stream ends before its declared size",
                detail=(
                    f"{len(padded_streams)} member(s) terminate before the "
                    "declared compressed size. Metadata and content disagree."
                ),
                evidence={"members": padded_streams[:5]},
            )
        )

    if capped:
        findings.append(_limit_finding(total, budget))
    if understated:
        names = [item[0] for item in understated[:5]]
        findings.append(
            Finding(
                code="METADATA_UNDERSTATED",
                severity=Severity.HIGH,
                title="Member data expands beyond its declared size",
                detail=(
                    f"{len(understated)} member(s) produced more output than the "
                    "central directory declares. Extraction tools may write the "
                    "real data, not the declared size."
                ),
                evidence={
                    "members": names,
                    "declared": [item[1] for item in understated[:5]],
                    "actual": [item[2] for item in understated[:5]],
                },
            )
        )
    if overstated and complete and not capped:
        findings.append(
            Finding(
                code="METADATA_OVERSTATED",
                severity=Severity.MEDIUM,
                title="Declared size is larger than the actual data",
                detail=(
                    f"{len(overstated)} member(s) produced less output than the "
                    "central directory declares. The archive is corrupt, truncated, "
                    "or lying in the other direction."
                ),
                evidence={"members": [item[0] for item in overstated[:5]]},
            )
        )
    if errors:
        notes.append(f"decoder errors: {'; '.join(errors[:3])}")

    if not complete:
        notes.append("static parse was partial, so verification cannot cover every member")
    if unsupported:
        if encrypted_skipped and decrypt_error:
            notes.append(
                f"{encrypted_skipped} encrypted member(s) were not verified: "
                f"{decrypt_error}"
            )
        elif encrypted_skipped and limits.password is None:
            notes.append(
                f"{encrypted_skipped} encrypted member(s) were skipped; supply "
                "a password to verify them"
            )
        undecodable = unsupported - encrypted_skipped
        if undecodable:
            notes.append(
                f"{undecodable} member(s) use a compression method this "
                "verifier cannot decode"
            )

    verified = (
        complete
        and unsupported == 0
        and not errors
        and not capped
        and not understated
        and not overstated
        and not short_streams
        and not padded_streams
    )
    if verified:
        detail = f"verified {total} bytes across {len(result.entries)} member(s)"
    elif capped:
        detail = f"output reached the {budget}-byte verification cap"
    else:
        detail = "verification incomplete"

    _add_actual_expansion(findings, total, size, result.declared_uncompressed, limits)
    return Verification(
        supported=True,
        verified=verified,
        output_bytes=total,
        declared_bytes=result.declared_uncompressed,
        capped=capped,
        detail=detail,
        findings=findings,
        notes=notes,
    )


@dataclass
class CountResult:
    total: int
    eof: bool
    error: Optional[str]
    capped: bool
    fed: int = 0
    unused_compressed: int = 0


def count_zip_entry(
    fp: BinaryIO,
    size: int,
    entry,
    budget: int,
    limits: Limits,
    deadline: Deadline,
) -> CountResult:
    data_start = entry.data_offset
    if data_start is None or data_start >= size:
        return CountResult(0, False, "data offset is outside the file", False)
    csize = entry.csize or 0
    available = min(csize, size - data_start)
    fp.seek(data_start)

    if entry.method == "stored":
        actual = min(available, budget)
        return CountResult(
            total=actual,
            eof=available >= csize and actual == csize,
            error=None,
            capped=available > budget,
        )

    if entry.method == "deflate":
        return _count_zlib(fp, available, budget, deadline)
    if entry.method == "bzip2":
        return _count_bzip2(fp, available, budget, deadline)
    if entry.method == "lzma":
        return _count_zip_lzma(fp, available, budget, limits, deadline)
    return CountResult(0, False, f"unsupported method {entry.method}", False)


def _count_zlib(
    fp: BinaryIO,
    compressed_len: int,
    budget: int,
    deadline: Deadline,
) -> CountResult:
    decompressor = zlib.decompressobj(-15)
    total = 0
    remaining = compressed_len
    fed = 0
    while total < budget and remaining > 0:
        deadline.check()
        chunk = fp.read(min(MAX_CHUNK, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
        fed += len(chunk)
        data = chunk
        while data and total < budget:
            try:
                produced = decompressor.decompress(
                    data, min(MAX_OUTPUT_PER_CALL, budget - total)
                )
            except zlib.error as exc:
                return CountResult(total, False, str(exc), False, fed)
            total += len(produced)
            if decompressor.eof:
                return CountResult(
                    total, True, None, False, fed, len(decompressor.unused_data)
                )
            tail = decompressor.unconsumed_tail
            if not tail:
                break
            if not produced and len(tail) == len(data):
                return CountResult(
                    total, False, "decompressor made no progress", False, fed
                )
            data = tail
    return CountResult(
        total,
        decompressor.eof,
        None,
        total >= budget,
        fed,
        len(decompressor.unused_data),
    )


def _count_bzip2(
    fp: BinaryIO, compressed_len: int, budget: int, deadline: Deadline
) -> CountResult:
    decompressor = bz2.BZ2Decompressor()
    total = 0
    remaining = compressed_len
    fed = 0
    while total < budget and remaining > 0:
        deadline.check()
        chunk = fp.read(min(MAX_CHUNK, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
        fed += len(chunk)
        data = chunk
        while total < budget:
            try:
                produced = decompressor.decompress(
                    data, min(MAX_OUTPUT_PER_CALL, budget - total)
                )
            except OSError as exc:
                return CountResult(total, False, str(exc), False, fed)
            total += len(produced)
            if decompressor.eof:
                return CountResult(
                    total, True, None, False, fed, len(decompressor.unused_data)
                )
            if decompressor.needs_input:
                break
            data = b""
            if not produced:
                break
    return CountResult(
        total,
        decompressor.eof,
        None,
        total >= budget,
        fed,
        len(decompressor.unused_data),
    )


def _count_zip_lzma(
    fp: BinaryIO,
    compressed_len: int,
    budget: int,
    limits: Limits,
    deadline: Deadline,
) -> CountResult:
    header = fp.read(4)
    if len(header) < 4:
        return CountResult(0, False, "truncated ZIP LZMA header", False)
    props_size = u16le(header, 2)
    if props_size < 5 or props_size > 64 or 4 + props_size > compressed_len:
        return CountResult(0, False, "invalid ZIP LZMA properties", False)
    props = fp.read(props_size)
    if len(props) < props_size:
        return CountResult(0, False, "truncated ZIP LZMA properties", False)
    prop0 = props[0]
    lc = prop0 % 9
    rest = prop0 // 9
    lp = rest % 5
    pb = rest // 5
    dict_size = int.from_bytes(props[1:5], "little")
    if dict_size > limits.max_decoder_memory:
        return CountResult(
            0, False, "ZIP LZMA dictionary exceeds safety cap", False
        )
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
        decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    except (lzma.LZMAError, ValueError) as exc:
        return CountResult(0, False, str(exc), False)
    payload_len = compressed_len - 4 - props_size
    total = 0
    remaining = payload_len
    fed = 4 + props_size
    while total < budget and remaining > 0:
        deadline.check()
        chunk = fp.read(min(MAX_CHUNK, remaining))
        if not chunk:
            break
        remaining -= len(chunk)
        fed += len(chunk)
        data = chunk
        while total < budget:
            try:
                produced = decompressor.decompress(
                    data, min(MAX_OUTPUT_PER_CALL, budget - total)
                )
            except lzma.LZMAError as exc:
                return CountResult(total, False, str(exc), False, fed)
            total += len(produced)
            if decompressor.eof:
                return CountResult(
                    total, True, None, False, fed, len(decompressor.unused_data)
                )
            if decompressor.needs_input:
                break
            data = b""
            if not produced:
                break
    return CountResult(
        total,
        decompressor.eof,
        None,
        total >= budget,
        fed,
        len(decompressor.unused_data),
    )


# ---------------------------------------------------------------------------
# Stream formats
# ---------------------------------------------------------------------------


def _verify_gzip(
    fp: BinaryIO,
    size: int,
    result: ScanResult,
    limits: Limits,
    deadline: Deadline,
    budget: int,
) -> Verification:
    findings: List[Finding] = []
    notes: List[str] = []
    total = 0
    capped = False
    error: Optional[str] = None
    fp.seek(0)
    try:
        with gzip.GzipFile(fileobj=fp, mode="rb") as stream:
            while total < budget:
                deadline.check()
                chunk = stream.read(min(MAX_CHUNK, budget - total))
                if not chunk:
                    break
                total += len(chunk)
    except (OSError, EOFError, gzip.BadGzipFile, zlib.error) as exc:
        error = str(exc)
    if total >= budget:
        capped = True
        findings.append(_limit_finding(total, budget))

    declared = result.declared_uncompressed
    mismatch = _gzip_size_mismatch(total, declared)
    if mismatch == "under":
        findings.append(
            Finding(
                code="METADATA_UNDERSTATED",
                severity=Severity.MEDIUM,
                title="gzip data is larger than its ISIZE trailer",
                detail=(
                    "The stream produced more output than the final member's ISIZE "
                    "declares. This is legal for multi-member gzip, but it is also "
                    "how a bomb can hide from a metadata-only scan."
                ),
                evidence={"actual": total, "declared": declared},
            )
        )
    elif mismatch == "over":
        findings.append(
            Finding(
                code="METADATA_OVERSTATED",
                severity=Severity.MEDIUM,
                title="gzip data is smaller than its ISIZE trailer",
                detail="The stream is truncated, corrupt, or its metadata is false.",
                evidence={"actual": total, "declared": declared},
            )
        )
    if error:
        notes.append(f"gzip decoder stopped: {error}")

    verified = not capped and not error and mismatch is None
    _add_actual_expansion(findings, total, size, declared, limits)
    detail = (
        f"verified {total} bytes"
        if verified
        else (f"stopped at {budget} bytes" if capped else "verification incomplete")
    )
    return Verification(
        supported=True,
        verified=verified,
        output_bytes=total,
        declared_bytes=declared,
        capped=capped,
        detail=detail,
        findings=findings,
        notes=notes,
    )


def _verify_bzip2(
    fp: BinaryIO,
    size: int,
    result: ScanResult,
    limits: Limits,
    deadline: Deadline,
    budget: int,
) -> Verification:
    findings: List[Finding] = []
    notes: List[str] = []
    total = 0
    capped = False
    error: Optional[str] = None
    fp.seek(0)
    try:
        with bz2.BZ2File(fp, "rb") as stream:
            while total < budget:
                deadline.check()
                chunk = stream.read(min(MAX_CHUNK, budget - total))
                if not chunk:
                    break
                total += len(chunk)
    except (OSError, EOFError) as exc:
        error = str(exc)
    if total >= budget:
        capped = True
        findings.append(_limit_finding(total, budget))
    if error:
        notes.append(f"bzip2 decoder stopped: {error}")

    verified = not capped and not error
    _add_actual_expansion(
        findings, total, size, result.declared_uncompressed, limits
    )
    detail = (
        f"verified {total} bytes"
        if verified
        else (f"stopped at {budget} bytes" if capped else "verification incomplete")
    )
    return Verification(
        supported=True,
        verified=verified,
        output_bytes=total,
        declared_bytes=None,
        capped=capped,
        detail=detail,
        findings=findings,
        notes=notes,
    )


def _verify_lzma(
    fp: BinaryIO,
    size: int,
    result: ScanResult,
    limits: Limits,
    deadline: Deadline,
    budget: int,
) -> Verification:
    findings: List[Finding] = []
    notes: List[str] = []
    fmt = lzma.FORMAT_XZ if result.format == "xz" else lzma.FORMAT_ALONE
    try:
        decompressor = lzma.LZMADecompressor(
            format=fmt, memlimit=limits.max_decoder_memory
        )
    except (lzma.LZMAError, ValueError) as exc:
        return Verification(
            supported=True,
            verified=False,
            output_bytes=0,
            declared_bytes=result.declared_uncompressed,
            capped=False,
            detail=f"cannot initialize decoder: {exc}",
            notes=["xz/lzma decoder memory limit rejected this stream"],
        )

    total = 0
    capped = False
    error: Optional[str] = None
    extra_stream = False
    fp.seek(0)
    while total < budget:
        deadline.check()
        chunk = fp.read(MAX_CHUNK)
        if not chunk:
            break
        data = chunk
        while total < budget:
            try:
                produced = decompressor.decompress(
                    data, min(MAX_OUTPUT_PER_CALL, budget - total)
                )
            except lzma.LZMAError as exc:
                error = str(exc)
                break
            total += len(produced)
            if decompressor.eof:
                extra_stream = bool(decompressor.unused_data) or fp.tell() < size
                break
            if decompressor.needs_input:
                break
            data = b""
            if not produced:
                break
        if decompressor.eof or error:
            break
    if total >= budget:
        capped = True
        findings.append(_limit_finding(total, budget))
    if extra_stream:
        notes.append("concatenated xz stream: only the first stream was verified")
    if error:
        notes.append(f"xz/lzma decoder stopped: {error}")

    declared = result.declared_uncompressed
    mismatch = None
    if not extra_stream and not capped and not error:
        if declared is not None and total > declared:
            mismatch = "under"
        elif declared is not None and total < declared:
            mismatch = "over"
    if mismatch == "under":
        findings.append(
            Finding(
                code="METADATA_UNDERSTATED",
                severity=Severity.MEDIUM,
                title="xz/lzma data is larger than the index/header declares",
                detail="The declared size does not match the decoded stream.",
                evidence={"actual": total, "declared": declared},
            )
        )
    elif mismatch == "over":
        findings.append(
            Finding(
                code="METADATA_OVERSTATED",
                severity=Severity.MEDIUM,
                title="xz/lzma data is smaller than declared",
                detail="The stream is truncated, corrupt, or its metadata is false.",
                evidence={"actual": total, "declared": declared},
            )
        )

    verified = (
        not capped
        and not error
        and not extra_stream
        and mismatch is None
    )
    _add_actual_expansion(findings, total, size, declared, limits)
    detail = (
        f"verified {total} bytes"
        if verified
        else (f"stopped at {budget} bytes" if capped else "verification incomplete")
    )
    return Verification(
        supported=True,
        verified=verified,
        output_bytes=total,
        declared_bytes=declared,
        capped=capped,
        detail=detail,
        findings=findings,
        notes=notes,
    )


def _verify_tar(result: ScanResult, limits: Limits, budget: int) -> Verification:
    findings: List[Finding] = []
    declared = result.declared_uncompressed or 0
    capped = declared > budget
    if capped:
        findings.append(_limit_finding(budget, budget))
    verified = bool(result.complete) and not capped
    detail = (
        "TAR is uncompressed; declared member sizes define the extraction plan"
        if verified
        else "TAR is truncated or exceeds the verification cap"
    )
    return Verification(
        supported=True,
        verified=verified,
        output_bytes=min(declared, budget),
        declared_bytes=declared,
        capped=capped,
        detail=detail,
        findings=findings,
        notes=[
            "TAR sizes are enforced by extractors; sparse holes still count as "
            "output and are covered by the declared total"
        ],
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _limit_finding(actual: int, limit: int) -> Finding:
    return Finding(
        code="VERIFICATION_LIMIT",
        severity=Severity.HIGH,
        title="Verified output reached the safety cap",
        detail=(
            f"Decompression produced at least {limit} bytes and was stopped. "
            "The true expansion is larger; treat the file as dangerous."
        ),
        evidence={"verified_bytes": actual, "limit": limit},
    )


def _gzip_size_mismatch(actual: int, declared: Optional[int]) -> Optional[str]:
    if declared is None:
        return None
    if actual == declared:
        return None
    # ISIZE is modulo 2^32.
    if actual >= 0x100000000 and actual % 0x100000000 == declared:
        return None
    return "under" if actual > declared else "over"


def _add_actual_expansion(
    findings: List[Finding],
    actual: int,
    file_size: int,
    declared: Optional[int],
    limits: Limits,
) -> None:
    if actual < limits.min_expansion_bytes or file_size <= 0:
        return
    # The static rules already cover the case where the declaration is honest.
    if declared is not None and actual <= declared * 1.05:
        return
    ratio = actual / file_size
    severity = Severity.INFO
    if ratio >= limits.critical_ratio:
        severity = Severity.CRITICAL if actual >= limits.total_medium else Severity.HIGH
    elif ratio >= limits.dangerous_ratio:
        severity = Severity.HIGH if actual >= limits.total_medium else Severity.MEDIUM
    elif ratio >= limits.suspicious_ratio:
        severity = Severity.MEDIUM
    if severity < Severity.MEDIUM:
        return
    findings.append(
        Finding(
            code="VERIFIED_EXPANSION",
            severity=severity,
            title="Verified expansion is dangerous",
            detail=(
                f"Actual decompression produced {actual} bytes from {file_size} "
                f"bytes on disk ({ratio:,.0f}:1), regardless of what the metadata "
                "declared."
            ),
            evidence={
                "actual_uncompressed": actual,
                "file_size": file_size,
                "ratio": ratio,
            },
        )
    )
