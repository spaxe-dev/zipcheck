"""Bounded, in-memory decompression used as a last resort.

Only formats that do not declare an uncompressed size (bzip2, bare LZMA with
an unknown size, and gzip whose ISIZE wrapped to zero) are probed.  The
amount of output is capped, it stays in memory, and nothing is written to
disk.  This is a *measurement*, not extraction.
"""

from __future__ import annotations

from typing import BinaryIO, Callable, Tuple

from ..reader import Deadline


def bounded_probe(
    fp: BinaryIO,
    offset: int,
    factory: Callable[[], object],
    cap: int,
    deadline: Deadline,
    chunk_size: int = 64 * 1024,
) -> Tuple[int, int, bool, bool]:
    """Return ``(output_bytes, input_bytes, capped, eof)``.

    ``output_bytes`` never exceeds ``cap``.  ``input_bytes`` is an estimate of
    consumed compressed bytes (over-read is discounted when the decompressor
    exposes ``unused_data`` / ``unconsumed_tail``).
    """

    try:
        decompressor = factory()
    except Exception:
        return 0, 0, False, False
    fp.seek(offset)
    output = 0
    consumed = 0
    capped = False
    eof = False
    while output < cap:
        deadline.check()
        chunk = fp.read(min(chunk_size, cap - output + chunk_size))
        if not chunk:
            break
        consumed += len(chunk)
        try:
            produced = decompressor.decompress(chunk, cap - output)  # type: ignore[call-arg]
        except Exception:
            break
        output += len(produced)
        if getattr(decompressor, "eof", False):
            eof = True
            break
        if not produced and not chunk:
            break
    unused = len(getattr(decompressor, "unused_data", b"")) + len(
        getattr(decompressor, "unconsumed_tail", b"")
    )
    consumed = max(0, consumed - unused)
    if output >= cap and not eof:
        capped = True
    return output, consumed, capped, eof
