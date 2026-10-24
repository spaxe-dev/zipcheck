#!/usr/bin/env python3
"""Benchmark zipcheck in one process and report peak RSS.

Usage:
    PYTHONPATH=src python3 tools/benchmark.py ARCHIVE...
"""

from __future__ import annotations

import json
import resource
import sys
import time

from zipcheck import scan_file


def main() -> int:
    paths = sys.argv[1:]
    if not paths:
        print(__doc__)
        return 2
    started = time.monotonic()
    results = [scan_file(path) for path in paths]
    elapsed = time.monotonic() - started
    rss_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    summary = {"clean": 0, "suspicious": 0, "dangerous": 0, "unknown": 0}
    for result in results:
        summary[result.verdict] += 1
        print(f"{result.verdict:10} {result.path}  {result.format:7} {result.size:>10} bytes")
    print(
        json.dumps(
            {
                "files": len(results),
                "summary": summary,
                "elapsed_seconds": round(elapsed, 4),
                "peak_rss_mib": round(rss_kib / 1024, 2),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
