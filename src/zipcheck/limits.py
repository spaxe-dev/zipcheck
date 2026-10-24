"""Policy thresholds and hard resource limits.

Every value is a *defensive* limit: the parsers are written so that even a
malicious header cannot make them allocate memory proportional to a declared
size.  The thresholds only affect the verdict, not memory safety.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Limits:
    # --- static parsing limits (never allocate based on declared sizes) ---
    max_entries: int = 100_000
    max_entries_parse: int = 100_000
    max_cd_bytes: int = 64 * 1024 * 1024
    max_header_bytes: int = 32 * 1024 * 1024
    max_name_bytes: int = 64 * 1024
    max_pax_bytes: int = 1024 * 1024

    # --- nested archive inspection limits ---
    max_depth: int = 6
    max_nested_candidates: int = 128
    # Prefix examinations are cheap, so this is effectively aligned with the
    # entry parse cap; the candidate caps above still bound real inspection.
    max_nested_examined: int = 100_000
    max_nested_archives: int = 128
    max_nested_compressed: int = 8 * 1024 * 1024
    nested_prefix_bytes: int = 1024 * 1024
    nested_capture_bytes: int = 8 * 1024 * 1024
    nested_budget_bytes: int = 64 * 1024 * 1024
    max_decoder_memory: int = 128 * 1024 * 1024

    # --- bounded decompression probe (size-less formats and ZIP tails) ---
    probe: bool = True
    probe_limit: int = 64 * 1024 * 1024
    # Static ZIP tail check: probe members whose data leaves an unexplained
    # gap before the next structure.  Bounded so a normal static scan never
    # decompresses a whole archive.
    stream_probe_max_entries: int = 256
    stream_probe_max_compressed: int = 64 * 1024
    stream_probe_max_output: int = 1024 * 1024
    stream_probe_total_output: int = 4 * 1024 * 1024

    # --- password-based ZIP inspection ---
    # Kept out of repr/equality so a Limits object can be logged safely.
    password: Optional[bytes] = field(default=None, repr=False, compare=False)

    # --- content verification: actually decompress into a counting sink ---
    verify: bool = False
    verify_limit: int = 512 * 1024 * 1024
    # Output budget for recursively verifying archives found *inside* another
    # archive.  Kept separate so a large outer archive cannot starve the deep
    # scan (and so the total work remains bounded).
    nested_verify_limit: int = 256 * 1024 * 1024
    require_verified: bool = False

    # --- verdict policy ---
    min_expansion_bytes: int = 16 * 1024 * 1024
    suspicious_ratio: float = 100.0
    dangerous_ratio: float = 1000.0
    critical_ratio: float = 100_000.0
    total_medium: int = 1 * 1024**3
    total_high: int = 10 * 1024**3
    total_critical: int = 1 * 1024**4
    entry_count_medium: int = 10_000
    entry_count_high: int = 100_000

    # --- wall clock guard (per file) ---
    timeout: float = 60.0

    # Deflate cannot expand beyond roughly 1032:1.  A larger declared ratio is
    # a strong sign of overlapping entries or a lying central directory.
    deflate_max_ratio: float = 1032.0
