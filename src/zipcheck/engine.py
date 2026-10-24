"""Scan orchestration: metadata parsers, policy rules and nested archives."""

from __future__ import annotations

import io
import os
import time
from dataclasses import dataclass
from typing import BinaryIO, List, Optional

from . import detect
from .decrypt import (
    DECRYPTABLE_METHODS,
    DecryptionError,
    ZipDecryptor,
    open_zip_decryptor,
)
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
from .formats.zipfmt import member_image, member_prefix, member_probe
from .limits import Limits
from .model import (
    EntryInfo,
    Facts,
    Finding,
    ScanResult,
    Severity,
    result_from_facts,
)
from .reader import Deadline, FormatError, ScanBudget, ScanTimeout, read_at
from .verify import Verification, verify_archive

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
    nested_verify_used: int = 0

    def spend(self, amount: int) -> None:
        if self.nested_used + amount > self.limits.nested_budget_bytes:
            raise ScanBudget("nested inspection budget exhausted")
        self.nested_used += amount


def scan_file(path: str, limits: Optional[Limits] = None) -> ScanResult:
    """Scan one archive without extracting it.

    Only metadata regions are read.  Nested archives are decompressed by at
    most ``limits.nested_capture_bytes`` into memory and never written to disk.
    """

    limits = limits or Limits()
    started = time.monotonic()
    size = 0
    context = _Context(limits=limits, deadline=Deadline(limits.timeout))
    try:
        # Open first, then stat the same descriptor.  Statting a path before
        # opening it allows a file swap between check and use.
        with open(path, "rb") as fp:
            size = os.fstat(fp.fileno()).st_size
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

    if limits.password is not None and fmt != "zip" and facts.encrypted:
        facts.notes.append(
            f"a password was supplied, but {fmt} decryption is not supported; "
            "encrypted members remain opaque"
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
            _mark_incomplete(
                result, limits, "nested inspection stopped: budget exhausted"
            )
        except ScanTimeout:
            raise
        except (OSError, ValueError) as exc:
            _mark_incomplete(
                result, limits, f"nested inspection failed: {exc}"
            )
    elif facts.entries:
        _mark_incomplete(
            result,
            limits,
            f"nested inspection limited to depth {limits.max_depth}",
        )

    if limits.verify:
        if depth == 0 or not truncated:
            _run_verification(
                fp, size, result, limits, context.deadline, context, depth
            )
        else:
            result.verified = False
            result.verification_detail = (
                "nested archive was only partially captured"
            )
            result.notes.append(
                "nested archive verification skipped: only a prefix was available"
            )

    _apply_rules(result, facts, limits)
    _apply_nested_rules(result, limits)
    _apply_nested_verification(result, limits)
    return result


def _mark_incomplete(result: ScanResult, limits: Limits, why: str) -> None:
    """Record that some nested archive data could not be inspected.

    Without content verification the honest verdict is *unknown*: the part that
    was skipped is exactly where a bomb can hide.  Verification mode keeps its
    existing contract (suspicious unless ``require_verified`` turns it unknown).
    """

    result.nested_unverified = True
    if why not in result.notes:
        result.notes.append(why)
    if limits.verify:
        return
    result.unknown = True
    if any(f.code == "INSPECTION_INCOMPLETE" for f in result.findings):
        return
    result.findings.append(
        Finding(
            code="INSPECTION_INCOMPLETE",
            severity=Severity.MEDIUM,
            title="Nested archive inspection was incomplete",
            detail=(
                "zipcheck could not inspect every nested archive in this file, "
                "so a bomb may be hidden in the part that was not examined. The "
                "file is reported as unknown rather than clean."
            ),
            evidence={"reason": why},
        )
    )


def _run_verification(
    fp: BinaryIO,
    size: int,
    result: ScanResult,
    limits: Limits,
    deadline: Deadline,
    context: _Context,
    depth: int,
) -> None:
    budget = limits.verify_limit
    if depth > 0:
        remaining = limits.nested_verify_limit - context.nested_verify_used
        if remaining <= 0:
            verification = Verification(
                supported=True,
                verified=False,
                output_bytes=0,
                declared_bytes=result.declared_uncompressed,
                capped=True,
                detail="nested verification budget exhausted",
                findings=[
                    Finding(
                        code="VERIFICATION_LIMIT",
                        severity=Severity.HIGH,
                        title="Nested verification budget exhausted",
                        detail=(
                            "Deep verification stopped before this nested "
                            "archive could be measured. Its true expansion is "
                            "unknown; treat it as dangerous."
                        ),
                        evidence={
                            "nested_verify_limit": limits.nested_verify_limit,
                        },
                    )
                ],
                notes=["nested archive content was not verified"],
            )
            _finish_verification(verification, result, limits)
            return
        budget = min(budget, remaining)

    try:
        verification = verify_archive(
            fp, size, result, limits, deadline, budget=budget
        )
    except ScanTimeout:
        raise
    except Exception as exc:  # fail closed: never trust an unverified archive
        result.unknown = True
        verification = Verification(
            supported=False,
            verified=False,
            output_bytes=0,
            declared_bytes=result.declared_uncompressed,
            capped=False,
            detail=f"verification failed: {exc}",
            findings=[
                Finding(
                    code="VERIFICATION_FAILED",
                    severity=Severity.MEDIUM,
                    title="Content verification failed",
                    detail=(
                        "The verifier could not complete; the archive must not "
                        "be treated as verified."
                    ),
                    evidence={"error": str(exc)},
                )
            ],
            notes=[
                "content verification raised an error; treat the result as unverified"
            ],
        )
    if depth > 0:
        context.nested_verify_used += verification.output_bytes
    _finish_verification(verification, result, limits)


def _finish_verification(
    verification: Verification, result: ScanResult, limits: Limits
) -> None:
    result.verified = verification.verified
    result.verified_uncompressed = verification.output_bytes
    result.verification_capped = verification.capped
    result.verification_detail = verification.detail
    result.findings.extend(verification.findings)
    result.notes.extend(verification.notes)

    if not verification.verified:
        codes = {f.code for f in result.findings}
        if "UNVERIFIED" not in codes:
            result.findings.append(
                Finding(
                    code="UNVERIFIED",
                    severity=Severity.MEDIUM,
                    title="Archive could not be fully content-verified",
                    detail=(
                        f"{verification.detail}. Verification was requested but "
                        "did not cover the whole archive; do not treat it as "
                        "clean."
                    ),
                    evidence={
                        "verified": verification.verified,
                        "supported": verification.supported,
                        "capped": verification.capped,
                    },
                )
            )
        if limits.require_verified:
            result.unknown = True


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
        probe_output = (
            facts.probe_output if facts.probe_output is not None else total
        )
        probe_input = facts.probe_input or size
        probe_ratio = (
            probe_output / probe_input
            if probe_output and probe_input
            else None
        )
        if probe_ratio is not None and probe_ratio >= limits.dangerous_ratio:
            result.findings.append(
                Finding(
                    code="PROBE_LIMIT_EXCEEDED",
                    severity=Severity.HIGH,
                    title="Bounded decompression hit its cap with a high ratio",
                    detail=(
                        f"At least {probe_output} bytes were produced from "
                        f"{probe_input} compressed bytes ({probe_ratio:,.0f}:1) "
                        f"before the probe stopped at {limits.probe_limit} bytes."
                    ),
                    evidence={
                        "probe_output": probe_output,
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
                        f"Probe produced {probe_output} bytes from {probe_input} "
                        f"compressed bytes ({probe_ratio:,.0f}:1) before stopping."
                    ),
                    evidence={
                        "probe_output": probe_output,
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


def _apply_nested_rules(result: ScanResult, limits: Limits) -> None:
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
        elif child.verdict == "unknown":
            _mark_incomplete(
                result,
                limits,
                f"nested archive {child.path!r} could not be fully inspected",
            )


def _apply_nested_verification(result: ScanResult, limits: Limits) -> None:
    """Fail closed when any nested archive was not fully verified."""

    if not limits.verify:
        return
    unverified = result.nested_unverified or any(
        child.verified is not True for child in result.nested
    )
    if not unverified:
        return

    result.nested_unverified = True
    result.verified = False
    if not result.verification_detail:
        result.verification_detail = "one or more nested archives were not verified"
    codes = {f.code for f in result.findings}
    if "UNVERIFIED" not in codes:
        result.findings.append(
            Finding(
                code="UNVERIFIED",
                severity=Severity.MEDIUM,
                title="Nested archive content could not be verified",
                detail=(
                    "At least one archive nested inside this file was only "
                    "partially inspected or could not be decoded. A bomb can be "
                    "hidden at a deeper level, so the file must not be treated "
                    "as verified."
                ),
                evidence={
                    "nested_unverified": True,
                },
            )
        )
    if limits.require_verified:
        result.unknown = True


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
    elif fmt in ("7z", "rar4", "rar5"):
        if facts.nested_archive_names:
            _mark_incomplete(
                parent,
                context.limits,
                f"{fmt} member(s) look like nested archives but their data "
                "cannot be decoded without the format's decoder: "
                + ", ".join(repr(name) for name in facts.nested_archive_names[:3]),
            )
        elif facts.entry_count or facts.declared_uncompressed:
            parent.notes.append(
                f"nested archives inside {fmt} are not inspected statically"
            )
    elif fmt == "zstd" and (facts.entry_count or facts.declared_uncompressed):
        parent.notes.append("nested archives inside zstd are not inspected statically")
    return children


def _nested_name(parent: ScanResult, member: str) -> str:
    return f"{parent.path}!{member}"


def _remaining_archive_hint(
    entries: List[EntryInfo], start: int, password_supplied: bool = False
) -> bool:
    return any(
        not entry.is_dir
        and (
            detect.extension_suggests_archive(entry.name)
            or (password_supplied and entry.encrypted)
        )
        for entry in entries[start:]
    )


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
    capture_cap = (
        limits.nested_capture_bytes
        if limits.verify
        else limits.nested_prefix_bytes
    )

    decryptor: Optional[ZipDecryptor] = None
    decrypt_error: Optional[str] = None
    if limits.password is not None and any(entry.encrypted for entry in facts.entries):
        if facts.complete:
            try:
                decryptor = open_zip_decryptor(fp, facts.entries, limits.password)
            except DecryptionError as exc:
                decrypt_error = str(exc)
        else:
            decrypt_error = (
                "encrypted members were not decrypted because the ZIP metadata "
                "was only partially parsed"
            )
        # A supplied password signals that encrypted content matters.  If the
        # decryptor could not be opened, fail closed once for the whole
        # archive instead of trusting names that do not look like archives.
        if decrypt_error is not None:
            _mark_incomplete(
                parent,
                limits,
                f"encrypted members were not decrypted: {decrypt_error}",
            )

    def mark_unverified(entry: object, why: str) -> None:
        _mark_incomplete(
            parent,
            limits,
            f"nested archive {getattr(entry, 'name', '?')!r} not inspected: {why}",
        )

    try:
        for index, entry in enumerate(facts.entries):
            if inspected >= limits.max_nested_candidates:
                if limits.verify or _remaining_archive_hint(
                    facts.entries, index, limits.password is not None
                ):
                    _mark_incomplete(
                        parent,
                        limits,
                        "nested candidate limit reached; not every member was inspected",
                    )
                else:
                    parent.notes.append(
                        "nested candidate limit reached; remaining members do not "
                        "look like archives"
                    )
                break
            if examined >= limits.max_nested_examined:
                if limits.verify or _remaining_archive_hint(
                    facts.entries, index, limits.password is not None
                ):
                    _mark_incomplete(
                        parent,
                        limits,
                        "nested candidate scan limit reached; not every member was "
                        "inspected",
                    )
                else:
                    parent.notes.append(
                        "nested candidate scan limit reached; remaining members do "
                        "not look like archives"
                    )
                break
            if entry.is_dir:
                continue
            archive_hint = detect.extension_suggests_archive(entry.name)
            if entry.encrypted:
                if decryptor is None:
                    if decrypt_error is None and archive_hint:
                        mark_unverified(
                            entry,
                            "encrypted member was not inspected; supply a "
                            "password to decrypt it",
                        )
                    continue
                if entry.method not in DECRYPTABLE_METHODS:
                    mark_unverified(
                        entry,
                        f"encrypted member uses unsupported method {entry.method}",
                    )
                    continue
            elif (
                not entry.csize
                or entry.data_offset is None
                or entry.method not in ("stored", "deflate", "bzip2", "lzma")
            ):
                if archive_hint:
                    mark_unverified(
                        entry, "unsupported compression method or missing data"
                    )
                continue
            if not entry.csize or entry.data_offset is None:
                if archive_hint:
                    mark_unverified(entry, "member has no readable data range")
                continue
            if entry.csize > limits.max_nested_compressed:
                if archive_hint:
                    mark_unverified(
                        entry, "compressed member exceeds the nested scan cap"
                    )
                elif limits.verify and not entry.encrypted:
                    probe = member_probe(
                        fp,
                        entry,
                        1024,
                        limits.nested_prefix_bytes,
                        limits.max_decoder_memory,
                        context.deadline,
                    )
                    if detect.looks_like_archive(probe, ""):
                        mark_unverified(
                            entry,
                            "archive is too large to capture for deep verification",
                        )
                continue
            if entry.data_offset + entry.csize > size:
                if archive_hint:
                    mark_unverified(
                        entry, "member data extends past the end of the file"
                    )
                continue
            examined += 1
            context.deadline.check()
            try:
                if entry.encrypted:
                    assert decryptor is not None
                    head, _ = decryptor.read_image(
                        index,
                        entry,
                        1024 if limits.verify else 64,
                        context.deadline,
                    )
                else:
                    head = member_prefix(
                        fp,
                        entry,
                        1024 if limits.verify else 64,
                        limits.max_nested_compressed,
                        limits.max_decoder_memory,
                        context.deadline,
                    )
            except DecryptionError as exc:
                mark_unverified(entry, f"decryption failed: {exc}")
                continue
            except (OSError, ValueError):
                continue
            if not detect.looks_like_archive(
                head, entry.name, allow_extension=False
            ):
                continue
            if context.nested_archives >= limits.max_nested_archives:
                _mark_incomplete(
                    parent,
                    limits,
                    "nested archive limit reached; stopping inspection",
                )
                break
            if context.nested_used >= limits.nested_budget_bytes:
                _mark_incomplete(
                    parent,
                    limits,
                    "nested inspection budget reached; stopping inspection",
                )
                break

            if limits.verify:
                try:
                    if entry.encrypted:
                        assert decryptor is not None
                        data, complete = decryptor.read_image(
                            index, entry, capture_cap, context.deadline
                        )
                    else:
                        data, complete = member_image(
                            fp,
                            size,
                            entry,
                            capture_cap,
                            limits.max_nested_compressed,
                            limits.max_decoder_memory,
                            context.deadline,
                        )
                except DecryptionError as exc:
                    mark_unverified(entry, f"decryption failed: {exc}")
                    continue
                truncated = not complete
                if not complete:
                    mark_unverified(
                        entry, "member exceeds the nested verification capture cap"
                    )
            else:
                cap = min(
                    entry.usize
                    if entry.usize is not None
                    else limits.nested_prefix_bytes,
                    limits.nested_prefix_bytes,
                )
                if cap <= 0:
                    continue
                if context.nested_used + cap > limits.nested_budget_bytes:
                    _mark_incomplete(
                        parent,
                        limits,
                        "nested inspection budget reached; stopping inspection",
                    )
                    break
                try:
                    if entry.encrypted:
                        assert decryptor is not None
                        data, complete = decryptor.read_image(
                            index, entry, cap, context.deadline
                        )
                        truncated = not complete
                    else:
                        data = member_prefix(
                            fp,
                            entry,
                            cap,
                            limits.max_nested_compressed,
                            limits.max_decoder_memory,
                            context.deadline,
                        )
                        truncated = (
                            entry.usize is not None and len(data) < entry.usize
                        )
                except DecryptionError as exc:
                    mark_unverified(entry, f"decryption failed: {exc}")
                    continue
                except (OSError, ValueError):
                    continue
                if truncated:
                    mark_unverified(
                        entry, "member exceeds the static nested prefix cap"
                    )
            if not data:
                continue
            context.spend(len(data))
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
    finally:
        if decryptor is not None:
            decryptor.close()
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
    capture_cap = (
        limits.nested_capture_bytes
        if limits.verify
        else limits.nested_prefix_bytes
    )

    def mark_unverified(entry: object, why: str) -> None:
        _mark_incomplete(
            parent,
            limits,
            f"nested archive {getattr(entry, 'name', '?')!r} not inspected: {why}",
        )

    for index, entry in enumerate(facts.entries):
        if (
            inspected >= limits.max_nested_candidates
            or examined >= limits.max_nested_examined
        ):
            if limits.verify or _remaining_archive_hint(facts.entries, index):
                _mark_incomplete(
                    parent,
                    limits,
                    "nested candidate limit reached; not every member was inspected",
                )
            else:
                parent.notes.append(
                    "nested candidate limit reached; remaining members do not "
                    "look like archives"
                )
            break
        if (
            entry.is_dir
            or entry.sparse
            or entry.data_offset is None
            or not entry.usize
        ):
            if detect.extension_suggests_archive(entry.name):
                mark_unverified(entry, "member cannot be read as a regular file")
            continue
        if entry.data_offset + min(entry.usize, 8) > size:
            if detect.extension_suggests_archive(entry.name):
                mark_unverified(entry, "member data extends past the end of the file")
            continue
        examined += 1
        head = read_at(fp, entry.data_offset, 1024 if limits.verify else 16)
        if not detect.looks_like_archive(
            head, entry.name, allow_extension=False
        ):
            continue
        if context.nested_archives >= limits.max_nested_archives:
            _mark_incomplete(
                parent,
                limits,
                "nested archive limit reached; stopping inspection",
            )
            break
        cap = min(entry.usize, capture_cap)
        if context.nested_used + cap > limits.nested_budget_bytes:
            _mark_incomplete(
                parent,
                limits,
                "nested inspection budget reached; stopping inspection",
            )
            break
        data = read_at(fp, entry.data_offset, cap)
        truncated = entry.usize > len(data)
        if truncated:
            mark_unverified(entry, "member exceeds the nested capture cap")
        if not data:
            continue
        context.spend(len(data))
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
    capture_cap = (
        limits.nested_capture_bytes
        if limits.verify
        else limits.nested_prefix_bytes
    )
    remaining = limits.nested_budget_bytes - context.nested_used
    if remaining <= 0:
        _mark_incomplete(
            parent,
            limits,
            "nested inspection budget exhausted; compressed content was not inspected",
        )
        return []
    cap = min(capture_cap, remaining)
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
    complete = len(data) < cap
    if context.nested_archives >= limits.max_nested_archives:
        _mark_incomplete(
            parent,
            limits,
            "nested archive limit reached; stopping inspection",
        )
        return []
    if not detect.looks_like_archive(data[:1024], ""):
        context.spend(len(data))
        return []
    if not complete:
        _mark_incomplete(
            parent,
            limits,
            "compressed member exceeds the nested capture cap; deeper content "
            "was only partially inspected",
        )
    context.spend(len(data))
    return [
        _scan_bytes_nested(
            data,
            _nested_name(parent, "<decompressed>"),
            context,
            depth + 1,
            truncated=not complete,
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
