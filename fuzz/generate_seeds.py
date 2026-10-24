#!/usr/bin/env python3
"""Generate small, metadata-only seed archives for the fuzz corpus.

    python fuzz/generate_seeds.py fuzz/corpus
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct
import sys
import tarfile
import zipfile
import zlib
from pathlib import Path


def tar_header(name: str, size: int, typeflag: bytes = b"0") -> bytes:
    block = bytearray(512)
    raw = name.encode()
    block[: len(raw)] = raw
    block[100:108] = b"0000644\0"
    block[108:116] = b"0000000\0"
    block[116:124] = b"0000000\0"
    block[124:136] = f"{size:011o}".encode() + b"\0"
    block[136:148] = b"00000000000\0"
    block[156:157] = typeflag
    block[257:263] = b"ustar\0"
    block[263:265] = b"00"
    block[148:156] = b" " * 8
    block[148:156] = f"{sum(block):06o}".encode() + b"\0 "
    return bytes(block)


def local_header(name: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            0,
            0,
            0,
            0,
            crc,
            len(data),
            len(data),
            len(name),
            0,
        )
        + name
        + data
    )


def central_header(name: bytes, offset: int, size: int) -> bytes:
    return (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            0,
            0,
            0,
            0,
            zlib.crc32(b"") & 0xFFFFFFFF,
            size,
            size,
            len(name),
            0,
            0,
            0,
            0,
            0,
            offset,
        )
        + name
    )


def overlap_zip() -> bytes:
    data = b"A" * 4096
    local = local_header(b"a.dat", data)
    central = central_header(b"a.dat", 0, len(data)) + central_header(
        b"b.dat", 0, len(data)
    )
    eocd = struct.pack(
        "<IHHHHIIH", 0x06054B50, 0, 0, 2, 2, len(central), len(local), 0
    )
    return local + central + eocd


def forged_zip() -> bytes:
    payload = b"\0" * (64 * 1024)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("payload.bin", payload)
    data = bytearray(buffer.getvalue())
    central = data.rfind(b"PK\x01\x02")
    struct.pack_into("<I", data, 18, 1)
    struct.pack_into("<I", data, 22, 1)
    struct.pack_into("<I", data, central + 20, 1)
    struct.pack_into("<I", data, central + 24, 1)
    return bytes(data)


def clean_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("docs/readme.txt", b"hello" * 100)
        archive.writestr("../escape.txt", b"nope")
        archive.writestr("empty/", b"")
    return buffer.getvalue()


def clean_tar() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("hello.txt")
        info.size = 5
        archive.addfile(info, io.BytesIO(b"hello"))
    return buffer.getvalue()


def unknown_size_lzma() -> bytes:
    data = bytearray(lzma.compress(b"hello" * 1000, format=lzma.FORMAT_ALONE))
    struct.pack_into("<Q", data, 5, 0xFFFFFFFFFFFFFFFF)
    return bytes(data)


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)

    seeds = {
        "clean.zip": clean_zip(),
        "forged-size.zip": forged_zip(),
        "overlap.zip": overlap_zip(),
        "clean.tar": clean_tar(),
        "truncated.tar": tar_header("huge.bin", 20 * 1024**3) + b"\0" * 512,
        "hello.gz": gzip.compress(b"hello" * 100, 9),
        "multi-member.gz": gzip.compress(b"hello" * 100, 9)
        + gzip.compress(b"world" * 100, 9),
        "hello.bz2": bz2.compress(b"hello" * 100, 9),
        "hello.xz": lzma.compress(b"hello" * 100, preset=9),
        "unknown-size.lzma": unknown_size_lzma(),
        "sevenzip.7z": b"7z\xbc\xaf\x27\x1c\x00\x04" + b"\0" * 64,
        "rar4.rar": b"Rar!\x1a\x07\x00" + b"\0" * 64,
        "rar5.rar": b"Rar!\x1a\x07\x01\x00" + b"\0" * 64,
        "frame.zst": b"\x28\xb5\x2f\xfd\x20\x00" + b"\0" * 64,
    }
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w") as archive:
        archive.writestr("inner.zip", seeds["clean.zip"])
    seeds["nested.zip"] = nested.getvalue()

    for name, data in seeds.items():
        (out / name).write_bytes(data)
    print(f"wrote {len(seeds)} seeds to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
