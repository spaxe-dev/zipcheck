"""Data model shared by every archive parser.

The scanner deliberately keeps a strict separation between *facts* read from
archive metadata and *findings* derived from those facts.  A parser never
decides that a file is malicious; it only reports declared sizes, entry counts
and format-specific anomalies.  The engine applies the policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional


class Severity(IntEnum):
    """Ordered severity of a single finding."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "info",
            Severity.LOW: "low",
            Severity.MEDIUM: "medium",
            Severity.HIGH: "high",
            Severity.CRITICAL: "critical",
        }[self]


@dataclass
class Finding:
    code: str
    severity: Severity
    title: str
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.label,
            "severity_value": int(self.severity),
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
        }


@dataclass
class EntryInfo:
    """One archive member, as declared by the archive metadata."""

    name: str
    usize: Optional[int] = None
    csize: Optional[int] = None
    method: Optional[str] = None
    is_dir: bool = False
    encrypted: bool = False
    sparse: bool = False
    data_offset: Optional[int] = None

    @property
    def ratio(self) -> Optional[float]:
        if self.usize is None or not self.csize:
            return None
        return self.usize / self.csize

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "usize": self.usize,
            "csize": self.csize,
            "ratio": self.ratio,
            "method": self.method,
            "is_dir": self.is_dir,
            "encrypted": self.encrypted,
            "sparse": self.sparse,
        }


@dataclass
class Facts:
    """What was learned from the metadata of one archive image."""

    format: str
    detail: str = ""
    declared_uncompressed: Optional[int] = None
    declared_compressed: Optional[int] = None
    entry_count: Optional[int] = None
    entries: List[EntryInfo] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    complete: bool = True
    unknown: bool = False
    encrypted: bool = False
    measured: bool = False
    probe_capped: bool = False
    probe_input: Optional[int] = None
    sparse_total: int = 0


@dataclass
class ScanResult:
    """Final result for one path (or one nested archive)."""

    path: str
    size: int
    format: str = "unknown"
    detail: str = ""
    declared_uncompressed: Optional[int] = None
    declared_compressed: Optional[int] = None
    entry_count: Optional[int] = None
    entries: List[EntryInfo] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    nested: List[ScanResult] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    error: Optional[str] = None
    unknown: bool = False
    complete: bool = True
    depth: int = 0
    duration_ms: float = 0.0

    @property
    def ratio(self) -> Optional[float]:
        if self.declared_uncompressed is None or self.size <= 0:
            return None
        return self.declared_uncompressed / self.size

    @property
    def severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    @property
    def verdict(self) -> str:
        # Positive evidence outranks incompleteness: a partially readable
        # archive that already declares terabytes is still dangerous.
        if self.severity >= Severity.HIGH:
            return "dangerous"
        if self.error or self.unknown:
            return "unknown"
        if self.severity >= Severity.MEDIUM:
            return "suspicious"
        return "clean"

    def all_findings(self) -> List[Finding]:
        out = list(self.findings)
        for child in self.nested:
            out.extend(child.all_findings())
        return out

    def to_dict(self, sample_entries: int = 25) -> Dict[str, Any]:
        entries = self.entries[:sample_entries]
        return {
            "path": self.path,
            "size": self.size,
            "format": self.format,
            "detail": self.detail,
            "declared_uncompressed": self.declared_uncompressed,
            "declared_compressed": self.declared_compressed,
            "ratio": self.ratio,
            "entry_count": self.entry_count,
            "verdict": self.verdict,
            "severity": self.severity.label,
            "severity_value": int(self.severity),
            "complete": self.complete,
            "error": self.error,
            "notes": self.notes,
            "entries": [e.to_dict() for e in entries],
            "entries_truncated": len(self.entries) > sample_entries,
            "findings": [f.to_dict() for f in self.findings],
            "nested": [n.to_dict(sample_entries=10) for n in self.nested],
            "duration_ms": round(self.duration_ms, 3),
        }


@dataclass
class ArchiveFacts(Facts):
    """Alias retained for readability in parser signatures."""


def result_from_facts(
    path: str, size: int, facts: Facts, depth: int = 0
) -> ScanResult:
    return ScanResult(
        path=path,
        size=size,
        format=facts.format,
        detail=facts.detail,
        declared_uncompressed=facts.declared_uncompressed,
        declared_compressed=facts.declared_compressed,
        entry_count=facts.entry_count,
        entries=facts.entries,
        findings=list(facts.findings),
        notes=list(facts.notes),
        unknown=facts.unknown,
        complete=facts.complete,
        depth=depth,
    )
