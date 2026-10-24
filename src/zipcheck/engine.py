"""Scan orchestration: metadata parsers, policy rules and nested archives."""

from __future__ import annotations

import io
import os
import time
from dataclasses import dataclass
from typing import BinaryIO, List, Optional

from . import detect
from .formats import (
    bzip2fmt,
    gzipfmt,
    rarfmt,
    sevenzipfmt,
    tarfmt,
    xzfmt,
    zipfmt,
    zstdfmt,
)
from .formats.zipfmt import member_prefix
from .limits import Limits
from .model import (
    Facts,
    Finding,
    ScanResult,
    Severity,
    result_from_facts,
)
from .reader import Deadline, FormatError, ScanBudget, ScanTimeout, read_at

PARSERS = {
    "zip": zipfmt.scan,
    "tar": tarfmt.scan,
    "gzip": gzipfmt.scan,
    "bzip2": bzip2fmt.scan,
    "xz": xzfmt.scan,
    "lzma": xzfmt.scan,
    "zstd": zstdfmt.scan,
    "7z": sevenzipfmt.scan,
    "rar4": rarfmt.scan,
    "rar5": rarfmt.scan,
}


@dataclass
class _Context:
    limits: Limits
    deadline: Deadline
    nested_used: int = 0
    nested_archives: int = 0

    def spend(self, amount: int) -> None:
        if self.nested_used + amount > self.limits.nested_budget_bytes:
            raise ScanBudget("nested inspection budget exhausted")
        self.nested_used += amount


def scan_file(path: str, limits: Optional[Limits] = None) -> ScanResult:
    """Scan one archive without extracting it.

    Only metadata regions are read.  Nested archives are decompressed by at
    most ``limits.nested_prefix_bytes`` into memory and never written to disk.
    """

    limits = limits or Limits()
    started = time.monotonic()
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        result = ScanResult(path=path, size=0, error=str(exc), unknown=True)
        result.duration_ms = (time.monotonic() - started) * 1000
        return result

    context = _Context(limits=limits, deadline=Deadline(limits.timeout))
    try:
        with open(path, "rb") as fp:
            result = _scan_stream(fp, size, path, context, depth=0)
    except ScanTimeout:
        result = ScanResult(
            path=path,
            size=size,
            error="scan timed out",
            unknown=True,
        )
    except (OSError, MemoryError) as exc:
        result = ScanResult(path=path, size=size, error=str(exc), unknown=True)
    except Exception as exc:  # never let a malformed archive crash the caller
        result = ScanResult(
            path=path, size=size, error=f"parser error: {exc}", unknown=True
        )
    result.duration_ms = (time.monotonic() - started) * 1000
    return result


def scan_bytes(
    data: bytes, name: str = "<memory>", limits: Optional[Limits] = None
) -> ScanResult:
    """Scan an in-memory archive image (useful for tests and pipelines)."""

    limits = limits or Limits()
    context = _Context(limits=limits, deadline=Deadline(limits.timeout))
    started = time.monotonic()
    fp = io.BytesIO(data)
    try:
        result = _scan_stream(fp, len(data), name, context, depth=0)
    except ScanTimeout:
        result = ScanResult(path=name, size=len(data), error="scan timed out", unknown=True)
    except Exception as exc:
        result = ScanResult(
            path=name, size=len(data), error=f"parser error: {exc}", unknown=True
        )
    result.duration_ms = (time.monotonic() - started) * 1000
    return result


def _scan_stream(
    fp: BinaryIO,
    size: int,
    path: str,
    context: _Context,
    depth: int,
    truncated: bool = False,
) -> ScanResult:
    limits = context.limits
    context.deadline.check()
    head = read_at(fp, 0, min(size, 1024))
    fmt, why = detect.sniff(head, path)

    if fmt is None:
        result = ScanResult(
            path=path,
            size=size,
            format="unknown",
            unknown=True,
            depth=depth,
            notes=["not a recognized archive format"],
        )
        result.findings.append(
            Finding(
                code="UNRECOGNIZED_FORMAT",
                severity=Severity.INFO,
                title="File is not a recognized archive",
                detail="zipcheck only inspects ZIP, TAR, gzip, bzip2, xz, LZMA, zstd, 7z and RAR.",
            )
        )
        return result

    detail_prefix = why
    try:
        if truncated and fmt == "gzip":
            facts = Facts(
                format="gzip",
                detail="gzip (nested prefix)",
                unknown=True,
                notes=[
                    "nested gzip was only partially decompressed; its ISIZE trailer "
                    "is not available"
                ],
            )
        elif truncated and fmt == "zip":
            facts = zipfmt.parse_prefix(read_at(fp, 0, size), limits)
        elif truncated and fmt in ("bzip2", "xz", "lzma", "zstd"):
            facts = Facts(
                format=fmt,
                detail=f"{fmt} (nested prefix)",
                unknown=True,
                notes=["nested compressed stream was only partially stored"],
            )
        else:
            facts = PARSERS[fmt](fp, size, limits, context.deadline)
    except FormatError as exc:
        result = ScanResult(
            path=path,
            size=size,
            format=fmt,
            detail=detail_prefix,
            error=str(exc),
            unknown=True,
            depth=depth,
        )
        return result
    except ScanBudget:
        return ScanResult(
            path=path,
            size=size,
            format=fmt,
            error="nested inspection budget exhausted",
            unknown=True,
            depth=depth,
        )

    result = result_from_facts(path, size, facts, depth)
    result.format = fmt
    result.detail = facts.detail or detail_prefix
    if not facts.complete:
        result.complete = False

    if depth < limits.max_depth:
        try:
            result.nested = _inspect_nested(
                fp, size, facts, fmt, result, context, depth
            )
        except ScanBudget:
            result.notes.append("nested inspection stopped: budget exhausted")
        except ScanTimeout:
            raise
        except (OSError, ValueError) as exc:
            result.notes.append(f"nested inspection failed: {exc}")
    elif facts.entries:
        result.notes.append(
            f"nested inspection limited to depth {limits.max_depth}"
        )

    _apply_rules(result, facts, limits)
    _apply_nested_rules(result)
    return result


# ---------------------------------------------------------------------------
# Generic policy
# ---------------------------------------------------------------------------


def _apply_rules(result: ScanResult, facts: Facts, limits: Limits) -> None:
    total = result.declared_uncompressed
    size = result.size
    codes = {f.code for f in result.findings}

    if facts.encrypted and "ENCRYPTED" not in codes:
        result.findings.append(
            Finding(
                code="ENCRYPTED",
                severity=Severity.INFO,
                title="Archive is encrypted",
                detail="Encrypted headers or members limit what can be verified statically.",
            )
        )

    ratio_severity = Severity.INFO
    ratio: Optional[float] = None
    if total is not None and total >= limits.min_expansion_bytes and size > 0:
        ratio = total / size
        if ratio >= limits.critical_ratio:
            ratio_severity = (
                Severity.CRITICAL if total >= limits.total_medium else Severity.HIGH
            )
        elif ratio >= limits.dangerous_ratio:
            ratio_severity = (
                Severity.HIGH if total >= limits.total_medium else Severity.MEDIUM
            )
        elif ratio >= limits.suspicious_ratio:
            ratio_severity = Severity.MEDIUM

    if ratio_severity >= Severity.MEDIUM:
        result.findings.append(
            Finding(
                code="EXTREME_EXPANSION"
                if ratio_severity >= Severity.HIGH
                else "HIGH_EXPANSION",
                severity=ratio_severity,
                title="Declared expansion is unusually large",
                detail=(
                    f"The archive declares {total} bytes of output from {size} bytes "
                    f"on disk ({ratio:,.0f}:1). Extract it only inside a resource-"
                    "limited sandbox."
                ),
                evidence={
                    "declared_uncompressed": total,
                    "file_size": size,
                    "ratio": ratio,
                },
            )
        )

    absolute_severity = Severity.INFO
    if total is not None and size > 0 and total > size * 2:
        if total >= limits.total_critical:
            absolute_severity = Severity.CRITICAL
        elif total >= limits.total_high:
            absolute_severity = Severity.HIGH
        elif total >= limits.total_medium:
            absolute_severity = Severity.MEDIUM
    if absolute_severity > ratio_severity:
        result.findings.append(
            Finding(
                code="ABSOLUTE_EXPANSION",
                severity=absolute_severity,
                title="Very large declared output",
                detail=(
                    f"This file declares {total} bytes of output. Even if the ratio "
                    "is modest, extracting it can exhaust disk space."
                ),
                evidence={"declared_uncompressed": total, "file_size": size},
            )
        )

    if result.entry_count is not None:
        if result.entry_count >= limits.entry_count_high:
            result.findings.append(
                Finding(
                    code="ENTRY_COUNT_BOMB",
                    severity=Severity.HIGH,
                    title="Very large number of archive members",
                    detail=(
                        f"{result.entry_count:,} members can exhaust inodes or "
                        "extraction time even when each member is small."
                    ),
                    evidence={"entry_count": result.entry_count},
                )
            )
        elif result.entry_count >= limits.entry_count_medium:
            result.findings.append(
                Finding(
                    code="MANY_ENTRIES",
                    severity=Severity.MEDIUM,
                    title="Large number of archive members",
                    detail=f"{result.entry_count:,} members may slow extraction.",
                    evidence={"entry_count": result.entry_count},
                )
            )

    if (
        result.declared_compressed is not None
        and result.declared_compressed > size + 1024
        and "INCONSISTENT_TOTALS" not in codes
        and result.format != "tar"
    ):
        result.findings.append(
            Finding(
                code="INCONSISTENT_TOTALS",
                severity=Severity.MEDIUM,
                title="Declared compressed size exceeds the file size",
                detail=(
                    f"Metadata claims {result.declared_compressed} compressed bytes "
                    f"in a {size}-byte file; members probably overlap."
                ),
                evidence={
                    "declared_compressed": result.declared_compressed,
                    "file_size": size,
                },
            )
        )

    if facts.probe_capped:
        probe_input = facts.probe_input or size
        probe_ratio = total / probe_input if total and probe_input else None
        if probe_ratio is not None and probe_ratio >= limits.dangerous_ratio:
            result.findings.append(
                Finding(
                    code="PROBE_LIMIT_EXCEEDED",
                    severity=Severity.HIGH,
                    title="Bounded decompression hit its cap with a high ratio",
                    detail=(
                        f"At least {total} bytes were produced from {probe_input} "
                        f"compressed bytes ({probe_ratio:,.0f}:1) before the probe "
                        f"stopped at {limits.probe_limit} bytes."
                    ),
                    evidence={
                        "probe_output": total,
                        "probe_input": probe_input,
                        "probe_ratio": probe_ratio,
                        "probe_limit": limits.probe_limit,
                    },
                )
            )
        elif probe_ratio is not None and probe_ratio >= limits.suspicious_ratio:
            result.findings.append(
                Finding(
                    code="PROBE_HIGH_RATIO",
                    severity=Severity.MEDIUM,
                    title="Bounded decompression produced a high ratio",
                    detail=(
                        f"Probe produced {total} bytes from {probe_input} compressed "
                        f"bytes ({probe_ratio:,.0f}:1) before stopping."
                    ),
                    evidence={
                        "probe_output": total,
                        "probe_input": probe_input,
                        "probe_ratio": probe_ratio,
                    },
                )
            )
    elif facts.measured and total is not None and ratio is None:
        # Probe completed but the output was below the expansion threshold.
        pass

    if result.unknown and not result.error:
        result.notes.append("verdict is unknown: not all sizes could be determined")


def _apply_nested_rules(result: ScanResult) -> None:
    for child in result.nested:
        if child.verdict == "dangerous":
            result.findings.append(
                Finding(
                    code="NESTED_BOMB",
                    severity=Severity.HIGH,
                    title="Nested archive is dangerous",
                    detail=(
                        f"Member {child.path!r} is itself rated {child.verdict}. "
                        "Extracting the outer archive may trigger the inner bomb."
                    ),
                    evidence={
                        "nested_path": child.path,
                        "nested_verdict": child.verdict,
                        "nested_format": child.format,
                    },
                )
            )
        elif child.verdict == "suspicious":
            result.findings.append(
                Finding(
                    code="NESTED_SUSPICIOUS",
                    severity=Severity.MEDIUM,
                    title="Nested archive is suspicious",
                    detail=f"Member {child.path!r} is rated {child.verdict}.",
                    evidence={"nested_path": child.path, "nested_verdict": child.verdict},
                )
            )


# ---------------------------------------------------------------------------
# Nested inspection
# ---------------------------------------------------------------------------


def _inspect_nested(
    fp: BinaryIO,
    size: int,
    facts: Facts,
    fmt: str,
    parent: ScanResult,
    context: _Context,
    depth: int,
) -> List[ScanResult]:
    children: List[ScanResult] = []
    if fmt == "zip":
        children = _inspect_zip(fp, size, facts, parent, context, depth)
    elif fmt == "tar":
        children = _inspect_tar(fp, size, facts, parent, context, depth)
    elif fmt in ("gzip", "bzip2", "xz", "lzma"):
        children = _inspect_compressed(fp, size, fmt, parent, context, depth)
    elif fmt in ("7z", "rar4", "rar5", "zstd") and (
        facts.entry_count or facts.declared_uncompressed
    ):
        parent.notes.append(f"nested archives inside {fmt} are not inspected statically")
    return children


def _nested_name(parent: ScanResult, member: str) -> str:
    return f"{parent.path}!{member}"


def _inspect_zip(
    fp: BinaryIO,
    size: int,
    facts: Facts,
    parent: ScanResult,
    context: _Context,
    depth: int,
) -> List[ScanResult]:
    limits = context.limits
    children: List[ScanResult] = []
    examined = 0
    inspected = 0
    for entry in facts.entries:
        if inspected >= limits.max_nested_candidates:
            break
        if examined >= limits.max_nested_candidates * 8:
            break
        if (
            entry.is_dir
            or entry.encrypted
            or not entry.csize
            or entry.data_offset is None
            or entry.method not in ("stored", "deflate", "bzip2")
        ):
            continue
        if entry.csize > limits.max_nested_compressed:
            continue
        if entry.data_offset + entry.csize > size:
            continue  # prefix does not contain the whole compressed member
        examined += 1
        context.deadline.check()
        try:
            head = member_prefix(
                fp,
                entry,
                64,
                limits.max_nested_compressed,
                context.deadline,
            )
        except (OSError, ValueError):
            continue
        if not detect.looks_like_archive(head, entry.name):
            continue
        cap = min(
            entry.usize if entry.usize is not None else limits.nested_prefix_bytes,
            limits.nested_prefix_bytes,
        )
        if cap <= 0:
            continue
        if context.nested_archives >= limits.max_nested_archives:
            parent.notes.append("nested archive limit reached; stopping inspection")
            break
        if context.nested_used + cap > limits.nested_budget_bytes:
            parent.notes.append("nested inspection budget reached; stopping inspection")
            break
        try:
            data = member_prefix(
                fp,
                entry,
                cap,
                limits.max_nested_compressed,
                context.deadline,
            )
        except (OSError, ValueError):
            continue
        if not data:
            continue
        context.spend(len(data))
        truncated = entry.usize is not None and len(data) < entry.usize
        child = _scan_bytes_nested(
            data,
            _nested_name(parent, entry.name),
            context,
            depth + 1,
            truncated,
        )
        children.append(child)
        inspected += 1
        if child.verdict == "dangerous":
            break
    return children


def _inspect_tar(
    fp: BinaryIO,
    size: int,
    facts: Facts,
    parent: ScanResult,
    context: _Context,
    depth: int,
) -> List[ScanResult]:
    limits = context.limits
    children: List[ScanResult] = []
    inspected = examined = 0
    for entry in facts.entries:
        if (
            inspected >= limits.max_nested_candidates
            or examined >= limits.max_nested_candidates * 8
        ):
            break
        if (
            entry.is_dir
            or entry.sparse
            or entry.data_offset is None
            or not entry.usize
        ):
            continue
        if entry.data_offset + min(entry.usize, 8) > size:
            continue
        examined += 1
        head = read_at(fp, entry.data_offset, 16)
        if not detect.looks_like_archive(head, entry.name):
            continue
        cap = min(entry.usize, limits.nested_prefix_bytes)
        if context.nested_archives >= limits.max_nested_archives:
            parent.notes.append("nested archive limit reached; stopping inspection")
            break
        if context.nested_used + cap > limits.nested_budget_bytes:
            parent.notes.append("nested inspection budget reached; stopping inspection")
            break
        data = read_at(fp, entry.data_offset, cap)
        context.spend(len(data))
        truncated = entry.usize > cap
        child = _scan_bytes_nested(
            data,
            _nested_name(parent, entry.name),
            context,
            depth + 1,
            truncated,
        )
        children.append(child)
        inspected += 1
        if child.verdict == "dangerous":
            break
    return children


def _inspect_compressed(
    fp: BinaryIO,
    size: int,
    fmt: str,
    parent: ScanResult,
    context: _Context,
    depth: int,
) -> List[ScanResult]:
    limits = context.limits
    remaining = limits.nested_budget_bytes - context.nested_used
    if remaining <= 0:
        return []
    cap = min(limits.nested_prefix_bytes, remaining)
    context.deadline.check()
    if fmt == "gzip":
        data = gzipfmt.decompress_prefix(fp, size, cap, context.deadline)
    elif fmt == "bzip2":
        data = bzip2fmt.decompress_prefix(fp, size, cap, context.deadline)
    else:
        data = xzfmt.decompress_prefix(
            fp,
            size,
            cap,
            context.deadline,
            fmt=fmt,
            memlimit=limits.max_decoder_memory,
        )
    if not data:
        return []
    context.spend(len(data))
    if context.nested_archives >= limits.max_nested_archives:
        parent.notes.append("nested archive limit reached; stopping inspection")
        return []
    if not detect.looks_like_archive(data[:1024], ""):
        return []
    return [
        _scan_bytes_nested(
            data,
            _nested_name(parent, "<decompressed>"),
            context,
            depth + 1,
            truncated=len(data) >= cap,
        )
    ]


def _scan_bytes_nested(
    data: bytes,
    name: str,
    context: _Context,
    depth: int,
    truncated: bool,
) -> ScanResult:
    if context.nested_archives >= context.limits.max_nested_archives:
        return ScanResult(
            path=name,
            size=len(data),
            error="nested archive limit reached",
            unknown=True,
            depth=depth,
        )
    context.nested_archives += 1
    fp = io.BytesIO(data)
    try:
        return _scan_stream(fp, len(data), name, context, depth, truncated=truncated)
    except ScanTimeout:
        raise
    except ScanBudget:
        return ScanResult(
            path=name,
            size=len(data),
            error="nested inspection budget exhausted",
            unknown=True,
            depth=depth,
        )
    except FormatError as exc:
        return ScanResult(
            path=name,
            size=len(data),
            error=str(exc),
            unknown=True,
            depth=depth,
        )
