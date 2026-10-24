from __future__ import annotations

import gzip
import lzma
import struct
import zipfile

from zipcheck import Limits, scan_file

from .helpers import (
    build_encrypted_archive_member_zip,
    build_forged_bomb_zip,
    build_gzip_with_nested_bomb,
    build_nested_forged_bomb_zip,
    build_split_gzip_with_nested_bomb,
    make_zip,
    make_zip_bomb,
)


def _patch(path, local_offset, value, central_offset):
    data = bytearray(path.read_bytes())
    struct.pack_into("<I", data, local_offset, value)
    central = data.find(b"PK\x01\x02")
    assert central >= 0
    struct.pack_into("<I", data, central + central_offset, value)
    path.write_bytes(data)
    return path


def _understate_zip(path, value=1):
    return _patch(path, 22, value, 24)


def _understate_gzip(path, value=1):
    data = bytearray(path.read_bytes())
    struct.pack_into("<I", data, len(data) - 4, value)
    path.write_bytes(data)
    return path


def test_verified_clean_zip(tmp_path):
    path = make_zip(tmp_path / "clean.zip", {"a.txt": b"hello" * 100})
    result = scan_file(str(path), Limits(verify=True))
    assert result.verdict == "clean"
    assert result.verified is True
    assert result.verified_uncompressed == 500


def test_understated_zip_is_dangerous_only_with_verification(tmp_path):
    path = make_zip_bomb(tmp_path / "bomb.zip", size=32 * 1024 * 1024)
    _understate_zip(path)
    static = scan_file(str(path))
    assert static.verdict == "clean"

    verified = scan_file(str(path), Limits(verify=True, verify_limit=64 * 1024 * 1024))
    assert verified.verified is False
    assert verified.verified_uncompressed == 32 * 1024 * 1024
    assert verified.verdict == "dangerous"
    assert "METADATA_UNDERSTATED" in {f.code for f in verified.findings}


def test_understated_gzip_no_longer_scans_clean(tmp_path):
    path = tmp_path / "bomb.gz"
    with gzip.open(path, "wb", compresslevel=9) as handle:
        handle.write(b"\0" * (32 * 1024 * 1024))
    _understate_gzip(path)
    static = scan_file(str(path))
    assert static.verdict == "unknown"
    # zlib drops the output slice that hits the forged trailer, so the static
    # measurement is a lower bound within one probe slice of the real size.
    assert static.declared_uncompressed is not None
    assert static.declared_uncompressed >= 31 * 1024 * 1024

    verified = scan_file(str(path), Limits(verify=True, verify_limit=64 * 1024 * 1024))
    assert verified.verified is False
    assert verified.verified_uncompressed == 32 * 1024 * 1024
    # The static probe already measured the real size, so verification now
    # fails on the forged trailer rather than on a declared-size mismatch.
    assert "UNVERIFIED" in {f.code for f in verified.findings}


def test_verification_limit_is_dangerous(tmp_path):
    path = make_zip_bomb(tmp_path / "bomb.zip", size=32 * 1024 * 1024)
    _understate_zip(path)
    result = scan_file(
        str(path), Limits(verify=True, verify_limit=1024 * 1024)
    )
    assert result.verification_capped is True
    assert result.verified is False
    assert result.verdict == "dangerous"
    assert "VERIFICATION_LIMIT" in {f.code for f in result.findings}


def test_require_verified_rejects_unverifiable_archive(tmp_path):
    path = build_encrypted_archive_member_zip(tmp_path / "encrypted.zip")
    result = scan_file(
        str(path), Limits(verify=True, require_verified=True)
    )
    assert result.verified is False
    assert result.verdict == "unknown"
    assert "UNVERIFIED" in {f.code for f in result.findings}


def test_require_verified_accepts_clean_zip(tmp_path):
    path = make_zip(tmp_path / "clean.zip", {"a.txt": b"hello"})
    result = scan_file(
        str(path), Limits(verify=True, require_verified=True)
    )
    assert result.verified is True
    assert result.verdict == "clean"


def test_understated_compressed_size_is_dangerous(tmp_path):
    path = build_forged_bomb_zip(tmp_path / "forged.zip")
    static = scan_file(str(path))
    assert static.verdict == "dangerous"
    assert "UNDERSTATED_COMPRESSED_SIZE" in {f.code for f in static.findings}

    verified = scan_file(str(path), Limits(verify=True))
    codes = {f.code for f in verified.findings}
    assert verified.verified is False
    assert verified.verdict == "dangerous"
    assert "UNDERSTATED_COMPRESSED_SIZE" in codes


def test_verify_only_flags_unverifiable_encrypted_archive(tmp_path):
    path = build_encrypted_archive_member_zip(tmp_path / "encrypted.zip")
    result = scan_file(str(path), Limits(verify=True))
    codes = {f.code for f in result.findings}
    assert result.verified is False
    assert result.verdict == "suspicious"
    assert "UNVERIFIED" in codes


def test_verify_detects_forged_nested_zip_bomb(tmp_path):
    path = build_nested_forged_bomb_zip(tmp_path / "outer.zip")
    static = scan_file(str(path))
    assert static.verdict == "dangerous"
    assert "NESTED_BOMB" in {f.code for f in static.findings}

    verified = scan_file(str(path), Limits(verify=True))
    codes = {f.code for f in verified.findings}
    assert verified.verdict == "dangerous"
    assert "NESTED_BOMB" in codes
    assert verified.verified is False


def test_verify_detects_forged_bomb_in_gzip(tmp_path):
    path = build_gzip_with_nested_bomb(tmp_path / "outer.gz")
    static = scan_file(str(path))
    assert static.verdict == "dangerous"
    assert "NESTED_BOMB" in {f.code for f in static.findings}

    verified = scan_file(str(path), Limits(verify=True))
    codes = {f.code for f in verified.findings}
    assert verified.verdict == "dangerous"
    assert "NESTED_BOMB" in codes


def test_verify_detects_bomb_split_across_gzip_members(tmp_path):
    path = build_split_gzip_with_nested_bomb(tmp_path / "split.gz")
    static = scan_file(str(path))
    assert static.verdict == "dangerous"
    assert "NESTED_BOMB" in {f.code for f in static.findings}

    verified = scan_file(str(path), Limits(verify=True))
    codes = {f.code for f in verified.findings}
    assert verified.verdict == "dangerous"
    assert "NESTED_BOMB" in codes


def test_verify_detects_forged_bomb_inside_xz(tmp_path):
    inner = build_forged_bomb_zip(tmp_path / "inner.zip")
    outer = tmp_path / "outer.xz"
    with lzma.open(outer, "wb", preset=9) as handle:
        handle.write(inner.read_bytes())

    verified = scan_file(str(outer), Limits(verify=True))
    codes = {f.code for f in verified.findings}
    assert verified.verdict == "dangerous"
    assert "NESTED_BOMB" in codes


def test_verify_detects_forged_bomb_in_zip_lzma_member(tmp_path):
    inner = build_forged_bomb_zip(tmp_path / "inner.zip")
    outer = tmp_path / "outer.zip"
    with zipfile.ZipFile(outer, "w", zipfile.ZIP_LZMA) as zf:
        zf.writestr("inner.zip", inner.read_bytes())
    static = scan_file(str(outer))
    assert static.verdict == "dangerous"
    assert "NESTED_BOMB" in {f.code for f in static.findings}

    verified = scan_file(str(outer), Limits(verify=True))
    codes = {f.code for f in verified.findings}
    assert verified.verdict == "dangerous"
    assert "NESTED_BOMB" in codes


def test_xz_verification_drains_buffered_output(tmp_path):
    path = tmp_path / "zeros.xz"
    with lzma.open(path, "wb", preset=9) as handle:
        handle.write(b"\0" * (2 * 1024 * 1024))
    result = scan_file(str(path), Limits(verify=True))
    codes = {f.code for f in result.findings}
    assert result.verified is True
    assert result.verified_uncompressed == 2 * 1024 * 1024
    assert "METADATA_OVERSTATED" not in codes


def test_nested_capture_cap_fails_closed(tmp_path):
    inner = make_zip(
        tmp_path / "inner.zip", {"a.txt": b"a" * 4096}, method=0
    )
    outer = make_zip(
        tmp_path / "outer.zip",
        {"inner.zip": inner.read_bytes()},
        method=0,
    )
    result = scan_file(
        str(outer),
        Limits(
            verify=True,
            require_verified=True,
            nested_capture_bytes=1024,
        ),
    )
    assert result.nested_unverified is True
    assert result.verified is False
    assert result.verdict == "unknown"
