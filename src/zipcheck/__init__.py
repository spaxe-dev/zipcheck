"""zipcheck: static archive-bomb detection without extraction."""

from __future__ import annotations

from .engine import scan_bytes, scan_file
from .engine import scan_file as scan
from .limits import Limits
from .model import EntryInfo, Finding, ScanResult, Severity

__all__ = [
    "EntryInfo",
    "Finding",
    "Limits",
    "ScanResult",
    "Severity",
    "scan",
    "scan_bytes",
    "scan_file",
]

__version__ = "0.2.0"
