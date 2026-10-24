from __future__ import annotations

from zipcheck import Limits, scan_file

from .helpers import (
    build_7z_declared,
    build_rar4_declared,
    build_rar5_declared,
    build_zstd_declared,
    make_compressed_bomb,
)


def test_gzip_bomb(tmp_path):
    path = make_compressed_bomb(tmp_path / "zeros.gz", "gzip", 32 * 1024 * 1024)
    result = scan_file(str(path))
    assert result.format == "gzip"
    assert result.declared_uncompressed == 32 * 1024 * 1024
    assert result.verdict == "suspicious"


def test_bzip2_probe(tmp_path):
    path = make_compressed_bomb(tmp_path / "zeros.bz2", "bzip2", 32 * 1024 * 1024)
    result = scan_file(str(path))
    assert result.format == "bzip2"
    assert result.declared_uncompressed == 32 * 1024 * 1024
    assert result.verdict == "dangerous"
    assert any("bounded" in note for note in result.notes)


def test_bzip2_without_probe_is_unknown(tmp_path):
    path = make_compressed_bomb(tmp_path / "zeros.bz2", "bzip2", 1 * 1024 * 1024)
    result = scan_file(str(path), Limits(probe=False))
    assert result.verdict == "unknown"
    assert result.declared_uncompressed is None


def test_xz_bomb(tmp_path):
    path = make_compressed_bomb(tmp_path / "zeros.xz", "xz", 32 * 1024 * 1024)
    result = scan_file(str(path))
    assert result.format == "xz"
    assert result.declared_uncompressed == 32 * 1024 * 1024
    assert result.verdict == "suspicious"


def test_zstd_declared_size(tmp_path):
    path = build_zstd_declared(tmp_path / "bomb.zst", 1 * 1024**4)
    result = scan_file(str(path))
    assert result.format == "zstd"
    assert result.declared_uncompressed == 1 * 1024**4
    assert result.verdict == "dangerous"


def test_7z_declared_size(tmp_path):
    path = build_7z_declared(tmp_path / "bomb.7z", 1 * 1024**4)
    result = scan_file(str(path))
    assert result.format == "7z"
    assert result.error is None
    assert result.declared_uncompressed == 1 * 1024**4
    assert result.verdict == "dangerous"


def test_rar5_declared_size(tmp_path):
    path = build_rar5_declared(tmp_path / "bomb.rar", 1 * 1024**4)
    result = scan_file(str(path))
    assert result.format == "rar5"
    assert result.error is None
    assert result.declared_uncompressed == 1 * 1024**4
    assert result.verdict == "dangerous"


def test_rar4_declared_size(tmp_path):
    path = build_rar4_declared(tmp_path / "bomb4.rar", 3 * 1024**3)
    result = scan_file(str(path))
    assert result.format == "rar4"
    assert result.error is None
    assert result.declared_uncompressed == 3 * 1024**3
    assert result.verdict == "dangerous"


def test_unknown_file(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("this is not an archive\n")
    result = scan_file(str(path))
    assert result.verdict == "unknown"
    assert result.format == "unknown"
