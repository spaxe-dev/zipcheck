from __future__ import annotations

import gzip

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


def test_gzip_multi_member_total_is_measured(tmp_path):
    path = tmp_path / "multi.gz"
    path.write_bytes(
        gzip.compress(b"\0" * (1024 * 1024), 9) + gzip.compress(b"\0" * 1024, 9)
    )
    result = scan_file(str(path), Limits(min_expansion_bytes=1))
    assert result.declared_uncompressed == 1024 * 1024 + 1024
    assert "ISIZE_UNDERSTATED" in {f.code for f in result.findings}
    assert result.verdict == "suspicious"


def test_gzip_probe_cap_is_unknown(tmp_path):
    path = make_compressed_bomb(tmp_path / "zeros.gz", "gzip", 4 * 1024 * 1024)
    result = scan_file(str(path), Limits(probe_limit=1024 * 1024))
    assert result.verdict == "unknown"
    assert any("probe stopped" in note for note in result.notes)
    probe = [f for f in result.findings if f.code == "PROBE_HIGH_RATIO"]
    assert probe and probe[0].evidence["probe_output"] == 1024 * 1024


def test_gzip_probe_cap_keeps_isize_for_severity(tmp_path):
    path = make_compressed_bomb(tmp_path / "zeros.gz", "gzip", 32 * 1024 * 1024)
    limits = Limits(
        probe_limit=1024 * 1024,
        total_medium=16 * 1024 * 1024,
        total_high=64 * 1024 * 1024,
        total_critical=128 * 1024 * 1024,
    )
    result = scan_file(str(path), limits)
    assert result.declared_uncompressed == 32 * 1024 * 1024
    assert result.verdict == "dangerous"
    assert "EXTREME_EXPANSION" in {f.code for f in result.findings}
    assert any("ISIZE claims" in note for note in result.notes)


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


def test_7z_nested_archive_member_fails_closed(tmp_path):
    path = build_7z_declared(
        tmp_path / "nested.7z", folder_size=512, name="inner.7z"
    )
    result = scan_file(str(path))
    assert result.verdict == "unknown"
    assert "INSPECTION_INCOMPLETE" in {f.code for f in result.findings}


def test_7z_regular_member_is_not_penalized(tmp_path):
    path = build_7z_declared(
        tmp_path / "plain.7z", folder_size=512, name="data.bin"
    )
    result = scan_file(str(path))
    assert result.verdict == "clean"


def test_rar5_declared_size(tmp_path):
    path = build_rar5_declared(tmp_path / "bomb.rar", 1 * 1024**4)
    result = scan_file(str(path))
    assert result.format == "rar5"
    assert result.error is None
    assert result.declared_uncompressed == 1 * 1024**4
    assert result.verdict == "dangerous"


def test_rar5_nested_archive_member_fails_closed(tmp_path):
    path = build_rar5_declared(
        tmp_path / "nested.rar", unp_size=512, name="inner.rar"
    )
    result = scan_file(str(path))
    assert result.verdict == "unknown"
    assert "INSPECTION_INCOMPLETE" in {f.code for f in result.findings}


def test_rar5_regular_member_is_not_penalized(tmp_path):
    path = build_rar5_declared(
        tmp_path / "plain.rar", unp_size=512, name="data.bin"
    )
    result = scan_file(str(path))
    assert result.verdict == "clean"


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
