"""Test helpers that build archives with *declared* sizes.

Most fixtures are tiny on disk: they contain a valid local header whose
metadata claims an enormous uncompressed size.  No test ever extracts or runs
a real bomb.
"""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import struct
import tarfile
import zipfile
import zlib

try:
    import pyzipper
except ImportError:  # optional extra; only encrypted fixtures need it
    pyzipper = None

# ---------------------------------------------------------------------------
# ZIP
# ---------------------------------------------------------------------------


def make_zip(path, members, method=zipfile.ZIP_DEFLATED):
    with zipfile.ZipFile(path, "w", method) as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def make_encrypted_zip(path, members, password, method=zipfile.ZIP_DEFLATED):
    """Create a WinZip AES-256 archive; requires the optional pyzipper."""
    if pyzipper is None:
        raise RuntimeError("pyzipper is required to build encrypted fixtures")
    with pyzipper.AESZipFile(
        path, "w", compression=method, encryption=pyzipper.WZ_AES
    ) as zf:
        zf.setpassword(password)
        for name, data in members.items():
            zf.writestr(name, data)
    return path


def make_zip_bomb(path, size=64 * 1024 * 1024, name="zeros.bin"):
    chunk = b"\0" * (1024 * 1024)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        with zf.open(name, "w") as handle:
            for _ in range(size // len(chunk)):
                handle.write(chunk)
    return path


def _local_header(name, data, usize, csize, method, crc=None, flags=0):
    raw_name = name.encode()
    if crc is None:
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
            len(raw_name),
            0,
        )
        + raw_name
        + data
    )


def _central_entry(name, local_offset, usize, csize, method, crc=0, flags=0):
    raw_name = name.encode()
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
            len(raw_name),
            0,
            0,
            0,
            0,
            0,
            local_offset,
        )
        + raw_name
    )


def build_single_entry_zip(path, usize, csize=80, method=8, name="bomb.bin"):
    if method == 8:
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
        data = compressor.compress(b"\0" * 1024) + compressor.flush()
        data = data[:csize]
    else:
        data = b"\0" * csize
    local = _local_header(name, data, usize, len(data), method)
    central = _central_entry(name, 0, usize, len(data), method)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    with open(path, "wb") as fh:
        fh.write(local + central + eocd)
    return path


def build_overlap_zip(path):
    name = "a.txt"
    data = b"A" * 512
    local = _local_header(name, data, 512, 512, 0)
    first = _central_entry("a.txt", 0, 512, 512, 0, zlib.crc32(data))
    second = _central_entry("b.txt", 0, 512, 512, 0, zlib.crc32(data))
    central = first + second
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 2, 2, len(central), len(local), 0)
    with open(path, "wb") as fh:
        fh.write(local + central + eocd)
    return path


def forged_zip_sizes(path, usize=1, csize=1):
    """Rewrite the first member's local and central sizes to ``usize``/``csize``.

    The encoded stream is left untouched, so this simulates an attacker who
    understates metadata while shipping much more real data.
    """
    data = bytearray(path.read_bytes())
    central = data.rfind(b"PK\x01\x02")
    if central < 0:
        raise ValueError("central directory not found")
    struct.pack_into("<I", data, 18, csize)
    struct.pack_into("<I", data, 22, usize)
    struct.pack_into("<I", data, central + 20, csize)
    struct.pack_into("<I", data, central + 24, usize)
    path.write_bytes(data)
    return path


def build_forged_bomb_zip(path, size=32 * 1024 * 1024):
    """A real DEFLATE bomb whose local and central headers claim one byte."""
    make_zip_bomb(path, size=size)
    return forged_zip_sizes(path)


def build_header_mismatch_zip(path, local_usize=3 * 1024**3):
    """A clean archive whose local header claims a different size than the CD."""
    make_zip(path, {"a.txt": b"hello"})
    data = bytearray(path.read_bytes())
    struct.pack_into("<I", data, 22, local_usize)
    path.write_bytes(data)
    return path


def build_encryption_flag_mismatch_zip(path):
    """Local header says encrypted; the central directory says plaintext."""
    make_zip(path, {"a.txt": b"hello"})
    data = bytearray(path.read_bytes())
    struct.pack_into("<H", data, 6, 1)
    path.write_bytes(data)
    return path


def build_hidden_cd_entries_zip(path):
    """Two central-directory entries behind an EOCD that counts only one."""
    make_zip(path, {"a.txt": b"a", "b.txt": b"b"})
    data = bytearray(path.read_bytes())
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise ValueError("EOCD not found")
    struct.pack_into("<H", data, eocd + 8, 1)
    struct.pack_into("<H", data, eocd + 10, 1)
    path.write_bytes(data)
    return path


def build_nested_forged_bomb_zip(path, size=32 * 1024 * 1024):
    """A stored outer ZIP containing a forged-size bomb.

    Static metadata looks small at every level; only content verification
    reveals the inner bomb.
    """
    inner = build_forged_bomb_zip(path.with_name("inner-" + path.name), size=size)
    return make_zip(path, {"inner.zip": inner.read_bytes()}, method=zipfile.ZIP_STORED)


def build_gzip_with_nested_bomb(path, size=32 * 1024 * 1024):
    """A gzip stream wrapping a forged-size ZIP bomb."""
    inner = build_forged_bomb_zip(path.with_name("inner-" + path.name), size=size)
    with gzip.open(path, "wb", compresslevel=9) as handle:
        handle.write(inner.read_bytes())
    return path


def build_split_gzip_with_nested_bomb(path, size=32 * 1024 * 1024):
    """A nested bomb split across two concatenated gzip members."""
    inner = build_forged_bomb_zip(path.with_name("inner-" + path.name), size=size)
    data = inner.read_bytes()
    middle = len(data) // 2
    with open(path, "wb") as handle:
        handle.write(gzip.compress(data[:middle], 9))
        handle.write(gzip.compress(data[middle:], 9))
    return path


def build_encrypted_archive_member_zip(path):
    """An encrypted ZIP whose member is itself named like an archive."""
    name = "lib0.zip"
    data = b"\0" * 32
    local = _local_header(name, data, 34902, len(data), 8, flags=1)
    central = _central_entry(name, 0, 34902, len(data), 8, flags=1)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(central), len(local), 0)
    with open(path, "wb") as fh:
        fh.write(local + central + eocd)
    return path


def build_zip_with_zip64_size(path, usize=10 * 1024**3):
    """A ZIP64 entry whose classic usize field is the 0xFFFFFFFF sentinel."""
    name = b"big.bin"
    data = b"\0" * 16
    # local header with ZIP64 extra that carries the real uncompressed size
    local_extra = struct.pack("<HHQ", 0x0001, 8, usize)
    local = (
        struct.pack(
            "<IHHHHHIIIHH",
            0x04034B50,
            45,
            0,
            8,
            0,
            0,
            zlib.crc32(data) & 0xFFFFFFFF,
            len(data),
            0xFFFFFFFF,
            len(name),
            len(local_extra),
        )
        + name
        + local_extra
        + data
    )
    cd_extra = struct.pack("<HHQQ", 0x0001, 16, usize, len(data))
    cd = (
        struct.pack(
            "<IHHHHHHIIIHHHHHII",
            0x02014B50,
            45,
            45,
            0,
            8,
            0,
            0,
            zlib.crc32(data) & 0xFFFFFFFF,
            len(data),
            0xFFFFFFFF,
            len(name),
            len(cd_extra),
            0,
            0,
            0,
            0,
            0,
        )
        + name
        + cd_extra
    )
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 1, 1, len(cd), len(local), 0)
    with open(path, "wb") as fh:
        fh.write(local + cd + eocd)
    return path


# ---------------------------------------------------------------------------
# TAR
# ---------------------------------------------------------------------------


def _octal(value, width):
    return f"{value:0{width}o}".encode()


def _tar_number(value, width=12):
    """Octal when it fits, otherwise GNU base-256 (high bit set)."""
    if value < 8 ** (width - 1):
        return f"{value:0{width - 1}o}".encode() + b"\0"
    raw = value.to_bytes(width, "big")
    return bytes([raw[0] | 0x80]) + raw[1:]


def tar_header(name, size, typeflag=b"0", realsize=None, magic=b"ustar\x00"):
    block = bytearray(512)
    raw_name = name.encode()
    block[0 : len(raw_name)] = raw_name
    block[100:108] = _octal(0o644, 7) + b"\0"
    block[108:116] = _octal(0, 7) + b"\0"
    block[116:124] = _octal(0, 7) + b"\0"
    block[124:136] = _tar_number(size)
    block[136:148] = _octal(0, 11) + b"\0"
    block[156:157] = typeflag
    block[257:263] = magic
    block[263:265] = b"00"
    if realsize is not None:
        block[483:495] = _tar_number(realsize)
    block[148:156] = b" " * 8
    checksum = sum(block)
    block[148:156] = f"{checksum:06o}".encode() + b"\0 "
    return bytes(block)


def build_tar(path, members):
    with tarfile.open(path, "w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def build_sparse_tar(path, realsize=1 * 1024**4):
    header = tar_header("sparse.bin", 0, typeflag=b"S", realsize=realsize)
    with open(path, "wb") as fh:
        fh.write(header)
        fh.write(b"\0" * 1024)
    return path


def build_truncated_tar(path, size=20 * 1024**3):
    header = tar_header("huge.bin", size)
    with open(path, "wb") as fh:
        fh.write(header)
        fh.write(b"\0" * 1024)
    return path


# ---------------------------------------------------------------------------
# gzip / bzip2 / xz
# ---------------------------------------------------------------------------


def make_compressed_bomb(path, fmt, size=64 * 1024 * 1024):
    chunk = b"\0" * (1024 * 1024)
    if fmt == "gzip":
        with gzip.open(path, "wb", compresslevel=9) as fh:
            for _ in range(size // len(chunk)):
                fh.write(chunk)
    elif fmt == "bzip2":
        with bz2.open(path, "wb", compresslevel=9) as fh:
            for _ in range(size // len(chunk)):
                fh.write(chunk)
    elif fmt == "xz":
        with lzma.open(path, "wb", preset=9) as fh:
            for _ in range(size // len(chunk)):
                fh.write(chunk)
    else:
        raise ValueError(fmt)
    return path


# ---------------------------------------------------------------------------
# zstd / 7z / RAR (metadata-only fixtures)
# ---------------------------------------------------------------------------


def build_zstd_declared(path, content_size=1 * 1024**4):
    # single-segment frame with an 8-byte content size
    descriptor = (3 << 6) | (1 << 5)
    header = b"\x28\xb5\x2f\xfd" + bytes([descriptor]) + content_size.to_bytes(8, "little")
    with open(path, "wb") as fh:
        fh.write(header)
    return path


def seven_num(value):
    if value < 0:
        raise ValueError("negative")
    for extra in range(8):
        capacity = 7 * (extra + 1)
        if value < (1 << capacity):
            low = value & ((1 << (8 * extra)) - 1)
            high = (value >> (8 * extra)) & ((1 << (7 - extra)) - 1)
            first = ((0xFF << (8 - extra)) & 0xFF) | high
            return bytes([first]) + low.to_bytes(extra, "little")
    raise ValueError("too large")


def build_7z_declared(path, folder_size=1 * 1024**4, name="bomb.bin"):
    header = bytearray()
    header += b"\x01"  # kHeader
    header += b"\x04"  # kMainStreamsInfo
    header += b"\x06" + seven_num(0) + seven_num(1) + b"\x09" + seven_num(100) + b"\x00"
    header += b"\x07\x0b" + seven_num(1) + b"\x00"
    header += seven_num(1) + b"\x01" + b"\x21"  # one LZMA2 coder, no props
    header += b"\x0c" + seven_num(folder_size) + b"\x00"
    header += b"\x00"  # end StreamsInfo
    header += b"\x05" + seven_num(1)
    raw_name = name.encode("utf-16-le") + b"\x00\x00"
    header += b"\x11" + seven_num(1 + len(raw_name)) + b"\x00" + raw_name
    header += b"\x00"  # end FilesInfo
    header += b"\x00"  # end Header

    next_crc = zlib.crc32(header) & 0xFFFFFFFF
    tail = struct.pack("<QQI", 0, len(header), next_crc)
    start_crc = zlib.crc32(tail) & 0xFFFFFFFF
    start = b"7z\xbc\xaf\x27\x1c" + b"\x00\x04" + struct.pack("<I", start_crc) + tail
    with open(path, "wb") as fh:
        fh.write(start + header)
    return path


def rar5_vint(value):
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def rar5_block(block_type, flags, body=b"", extra=b"", data_size=0):
    header = bytearray()
    header += rar5_vint(block_type)
    header += rar5_vint(flags)
    if flags & 0x0001:
        header += rar5_vint(len(extra))
    if flags & 0x0002:
        header += rar5_vint(data_size)
    header += body
    header += extra
    crc = zlib.crc32(header) & 0xFFFFFFFF
    return struct.pack("<I", crc) + rar5_vint(len(header)) + bytes(header)


def build_rar5_declared(path, unp_size=1 * 1024**4, name="bomb.bin"):
    body = bytearray()
    body += rar5_vint(0)  # file flags: no time, no crc
    body += rar5_vint(unp_size)
    body += rar5_vint(0)  # attributes
    body += rar5_vint(0)  # compression info
    body += rar5_vint(0)  # host OS
    raw_name = name.encode()
    body += rar5_vint(len(raw_name)) + raw_name
    main = rar5_block(1, 0, body=rar5_vint(0))
    file_block = rar5_block(2, 0, body=bytes(body))
    end = rar5_block(5, 0)
    with open(path, "wb") as fh:
        fh.write(b"Rar!\x1a\x07\x01\x00" + main + file_block + end)
    return path


def build_rar4_declared(path, unp_size=3 * 1024**3):
    name = b"bomb.bin"
    head_size = 32 + len(name)
    file_header = bytearray()
    file_header += struct.pack("<BHH", 0x74, 0, head_size)
    file_header += struct.pack("<II", 16, unp_size)
    file_header += struct.pack("<BII", 0, 0, 0)  # host, crc, mtime
    file_header += struct.pack("<BBH", 20, 0x30, len(name))  # ver, method, name len
    file_header += struct.pack("<I", 0)  # attributes
    file_header += name
    block = struct.pack("<H", 0) + bytes(file_header)
    main = struct.pack("<HBHH", 0, 0x73, 0, 13) + b"\0" * 6
    end = struct.pack("<HBHH", 0, 0x7B, 0, 7)
    with open(path, "wb") as fh:
        fh.write(b"Rar!\x1a\x07\x00" + main + block + end)
    return path
