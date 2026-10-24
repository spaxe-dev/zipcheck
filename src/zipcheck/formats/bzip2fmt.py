"""bzip2 metadata.

bzip2 has no uncompressed-size field at all.  The only static signal is the
compressed size, so a bounded in-memory decompression probe is used to measure
how far a small file actually expands.
"""

from __future__ import annotations

import bz2
from typing import BinaryIO, Optional

from ..limits import Limits
from ..model import Facts
from ..reader import Deadline, FormatError, read_at

MAGIC = b"BZh"


def scan(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    deadline.check()
    head = read_at(fp, 0, 4)
    if len(head) < 4 or not head.startswith(MAGIC) or not (0x31 <= head[3] <= 0x39):
        raise FormatError("not a bzip2 stream")

    notes = ["bzip2 does not store an uncompressed size"]
    declared: Optional[int] = None
    measured = False
    capped = False
    probe_input: Optional[int] = None

    if limits.probe:
        from .probe import bounded_probe

        output, consumed, capped, eof = bounded_probe(
            fp,
            0,
            lambda: bz2.BZ2Decompressor(),
            limits.probe_limit,
            deadline,
        )
        declared = output
        measured = True
        probe_input = consumed
        if eof:
            notes.append("size measured by bounded decompression")
        elif capped:
            notes.append(
                f"probe stopped at {limits.probe_limit} bytes of output; the real "
                "size is larger"
            )
        else:
            notes.append("probe could not decode the stream; size is unknown")
    else:
        notes.append("probing disabled; bzip2 expansion cannot be measured statically")

    return Facts(
        format="bzip2",
        detail="bzip2",
        declared_uncompressed=declared,
        declared_compressed=size,
        measured=measured,
        probe_capped=capped,
        probe_input=probe_input,
        notes=notes,
        unknown=declared is None or capped,
    )


def decompress_prefix(
    fp: BinaryIO, size: int, cap: int, deadline: Deadline
) -> bytes:
    decompressor = bz2.BZ2Decompressor()
    fp.seek(0)
    out = bytearray()
    while len(out) < cap:
        deadline.check()
        chunk = fp.read(64 * 1024)
        if not chunk:
            break
        data = chunk
        while len(out) < cap:
            try:
                produced = decompressor.decompress(data, cap - len(out))
            except OSError:
                return bytes(out)
            out.extend(produced)
            if decompressor.eof:
                return bytes(out)
            if decompressor.needs_input:
                break
            data = b""
            if not produced:
                break
    return bytes(out)
