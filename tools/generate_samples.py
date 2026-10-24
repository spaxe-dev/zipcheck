#!/usr/bin/env python3
"""Generate archive test corpus (including real decompression bombs).

WARNING: this writes files that expand to a lot of data if extracted.  The
files themselves are small.  Never extract them on a machine you care about.
Run generation inside a disposable VM/container, e.g. the project's sandbox.

The scanner never extracts these; it only reads metadata.
"""

from __future__ import annotations

import argparse
import bz2
import gzip
import lzma
import os
import shutil
import struct
import subprocess
import time
import zipfile
import zlib

CHUNK = b"\0" * (1024 * 1024)


def zeros(out, size):
    with open(out, "wb") as fh:
        for _ in range(size // len(CHUNK)):
            fh.write(CHUNK)
        fh.write(CHUNK[: size % len(CHUNK)])


def make_zip(out, zeros_path):
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        with zf.open("zeros.bin", "w") as handle:
            with open(zeros_path, "rb") as source:
                shutil.copyfileobj(source, handle, 1024 * 1024)


def make_gzip(out, zeros_path):
    with open(zeros_path, "rb") as source, gzip.open(out, "wb", compresslevel=9) as target:
        shutil.copyfileobj(source, target, 1024 * 1024)


def make_bzip2(out, zeros_path):
    with open(zeros_path, "rb") as source, bz2.open(out, "wb", compresslevel=9) as target:
        shutil.copyfileobj(source, target, 1024 * 1024)


def make_xz(out, zeros_path):
    with open(zeros_path, "rb") as source, lzma.open(out, "wb", preset=9) as target:
        shutil.copyfileobj(source, target, 1024 * 1024)


def make_nested(out, inner_path):
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.write(inner_path, "inner.zip")


def _local_header(name, data, usize, csize, method, flags=0):
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            20,
            flags,
            method,
            0,
            0,
            crc,
            csize,
            usize,
            len(name),
            0,
        )
        + name
        + data
    )


def _central(name, offset, usize, csize, method, flags=0):
    crc = zlib.crc32(b"") & 0xFFFFFFFF
    return (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            20,
            20,
            flags,
            method,
            0,
            0,
            crc,
            csize,
            usize,
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


def make_overlap(out):
    data = b"A" * 4096
    local = _local_header(b"a.dat", data, len(data), len(data), 0)
    first = _central(b"a.dat", 0, len(data), len(data), 0)
    second = _central(b"b.dat", 0, len(data), len(data), 0)
    cd = first + second
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 2, 2, len(cd), len(local), 0)
    with open(out, "wb") as fh:
        fh.write(local + cd + eocd)


def _tar_number(value):
    if value < 8**11:
        return f"{value:011o}".encode() + b"\0"
    raw = value.to_bytes(12, "big")
    return bytes([raw[0] | 0x80]) + raw[1:]


def tar_header(name, size, typeflag=b"0", realsize=None):
    block = bytearray(512)
    raw = name.encode()
    block[: len(raw)] = raw
    block[100:108] = b"0000644\0"
    block[108:116] = b"0000000\0"
    block[116:124] = b"0000000\0"
    block[124:136] = _tar_number(size)
    block[136:148] = b"00000000000\0"
    block[156:157] = typeflag
    block[257:263] = b"ustar\0"
    block[263:265] = b"00"
    if realsize is not None:
        block[483:495] = _tar_number(realsize)
    block[148:156] = b" " * 8
    block[148:156] = f"{sum(block):06o}".encode() + b"\0 "
    return bytes(block)


def make_truncated_tar(out, size=20 * 1024**3):
    with open(out, "wb") as fh:
        fh.write(tar_header("huge.bin", size))
        fh.write(b"\0" * 1024)


def make_sparse_tar(out, size=1 * 1024**4):
    tar = shutil.which("tar")
    if not tar or not shutil.which("truncate"):
        return False
    raw = out + ".sparse"
    subprocess.run(["truncate", "-s", "1T", raw], check=True)
    try:
        subprocess.run(
            [tar, "--sparse", "-cf", out, os.path.basename(raw)],
            cwd=os.path.dirname(out),
            check=True,
        )
    except subprocess.CalledProcessError:
        return False
    finally:
        os.unlink(raw)
    return True


def make_rar(out, zeros_path, rar):
    subprocess.run(
        [rar, "a", "-m5", "-idq", out, zeros_path],
        check=True,
        cwd=os.path.dirname(out),
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    parser.add_argument("--size", type=int, default=1024**3)
    parser.add_argument("--small-size", type=int, default=256 * 1024**2)
    parser.add_argument("--rar", default=None)
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    zeros_path = os.path.join(args.output, "zeros.bin")
    small_path = os.path.join(args.output, "small.bin")
    t0 = time.time()
    zeros(zeros_path, args.size)
    print(f"zeros.bin {os.path.getsize(zeros_path)} bytes in {time.time() - t0:.1f}s")
    if args.small_size != args.size:
        zeros(small_path, args.small_size)
    else:
        small_path = zeros_path

    steps = [
        ("zip-deflate.zip", lambda p: make_zip(p, zeros_path)),
        ("gzip.gz", lambda p: make_gzip(p, zeros_path)),
        ("bzip2.bz2", lambda p: make_bzip2(p, small_path)),
        ("xz.xz", lambda p: make_xz(p, small_path)),
        ("truncated.tar", lambda p: make_truncated_tar(p)),
        ("overlap.zip", lambda p: make_overlap(p)),
    ]
    for name, fn in steps:
        out = os.path.join(args.output, name)
        t = time.time()
        fn(out)
        print(f"{name} {os.path.getsize(out)} bytes in {time.time() - t:.1f}s")

    nested = os.path.join(args.output, "nested.zip")
    make_nested(nested, os.path.join(args.output, "zip-deflate.zip"))
    print(f"nested.zip {os.path.getsize(nested)} bytes")

    if make_sparse_tar(os.path.join(args.output, "sparse.tar")):
        print("sparse.tar created")
    if args.rar:
        rar_out = os.path.join(args.output, "rar5.rar")
        try:
            make_rar(rar_out, small_path, args.rar)
            print(f"rar5.rar {os.path.getsize(rar_out)} bytes")
        except subprocess.CalledProcessError as exc:
            print(f"rar failed: {exc}")

    if small_path != zeros_path:
        os.unlink(small_path)
    os.unlink(zeros_path)
    print("done")


if __name__ == "__main__":
    main()
