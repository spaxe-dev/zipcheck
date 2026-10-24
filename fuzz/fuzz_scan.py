#!/usr/bin/env python3
"""Coverage-guided fuzzing for the scanner's parsers and verifier.

Linux only: Atheris uses libFuzzer. Every input is scanned with tight resource
limits so the fuzzer explores parser branches without producing gigabytes of
decompressed data.

    python fuzz/fuzz_scan.py fuzz/corpus -max_total_time=120
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from zipcheck import Limits, scan_bytes

LIMITS = Limits(
    max_entries=2_000,
    max_entries_parse=2_000,
    max_cd_bytes=1024 * 1024,
    max_header_bytes=1024 * 1024,
    max_depth=3,
    max_nested_candidates=8,
    max_nested_archives=16,
    max_nested_compressed=256 * 1024,
    nested_prefix_bytes=128 * 1024,
    nested_capture_bytes=256 * 1024,
    nested_budget_bytes=1024 * 1024,
    nested_verify_limit=512 * 1024,
    max_decoder_memory=16 * 1024 * 1024,
    probe_limit=256 * 1024,
    verify=True,
    verify_limit=1024 * 1024,
    timeout=5.0,
)


def test_one_input(data: bytes) -> None:
    scan_bytes(data, name="<fuzz>", limits=LIMITS)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
