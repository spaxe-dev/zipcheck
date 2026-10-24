from __future__ import annotations

import zipfile

from zipcheck import Limits, scan_file
from zipcheck.model import Severity

from .helpers import (
    build_encrypted_archive_member_zip,
    build_overlap_zip,
    build_single_entry_zip,
    build_zip_with_zip64_size,
    make_zip,
    make_zip_bomb,
)


def test_clean_zip(tmp_path):
    path = make_zip(tmp_path / "clean.zip", {"hello.txt": b"hello world\n"})
    result = scan_file(str(path))
    assert result.verdict == "clean"
    assert result.format == "zip"
    assert result.entry_count == 1
    assert result.declared_uncompressed == 12


def test_sfx_with_prepended_stub(tmp_path):
    inner = make_zip(tmp_path / "inner.zip", {"a.txt": b"hello"})
    path = tmp_path / "sfx.zip"
    path.write_bytes(b"MZ" + b"\x90" * 2046 + inner.read_bytes())
    result = scan_file(str(path))
    assert result.verdict == "clean"
    assert result.entry_count == 1


def test_forced_zip64_local_header(tmp_path):
    path = tmp_path / "zip64.zip"
    with zipfile.ZipFile(path, "w") as zf:
        with zf.open(zipfile.ZipInfo("big.txt"), "w", force_zip64=True) as handle:
            handle.write(b"hello world")
    result = scan_file(str(path))
    assert result.verdict == "clean"
    assert result.declared_uncompressed == 11


def test_many_entries_triggers_zip64_eocd(tmp_path):
    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        for index in range(66000):
            zf.writestr(f"f{index:05d}.txt", b"")
    result = scan_file(str(path))
    assert result.error is None
    assert result.entry_count == 66000
    assert "MANY_ENTRIES" in {f.code for f in result.findings}
    assert result.verdict == "suspicious"


def test_declared_petabyte_is_critical(tmp_path):
    path = build_single_entry_zip(
        tmp_path / "declared.zip", usize=3 * 1024**3, csize=80
    )
    result = scan_file(str(path))
    codes = {f.code for f in result.findings}
    assert result.verdict == "dangerous"
    assert "EXTREME_EXPANSION" in codes
    assert result.severity == Severity.CRITICAL


def test_real_deflate_bomb_is_suspicious(tmp_path):
    path = make_zip_bomb(tmp_path / "zeros.zip", size=32 * 1024 * 1024)
    result = scan_file(str(path))
    assert result.verdict == "suspicious"
    assert result.declared_uncompressed == 32 * 1024 * 1024
    assert result.ratio is not None and result.ratio >= 100


def test_overlapping_entries(tmp_path):
    path = build_overlap_zip(tmp_path / "overlap.zip")
    result = scan_file(str(path))
    codes = {f.code for f in result.findings}
    assert result.verdict == "dangerous"
    assert "OVERLAPPING_DATA" in codes
    assert "OVERLAPPING_ENTRIES" in codes


def test_zip64_declared_size(tmp_path):
    path = build_zip_with_zip64_size(tmp_path / "zip64.zip", usize=10 * 1024**3)
    result = scan_file(str(path))
    assert result.declared_uncompressed == 10 * 1024**3
    assert result.verdict == "dangerous"


def test_nested_zip_bomb(tmp_path):
    inner = build_single_entry_zip(tmp_path / "inner.zip", usize=3 * 1024**3)
    outer = make_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()})
    result = scan_file(str(outer))
    assert result.nested, "nested member should have been inspected"
    assert "NESTED_BOMB" in {f.code for f in result.findings}
    assert result.verdict == "dangerous"


def test_deep_nested_zip_bomb(tmp_path):
    current = build_single_entry_zip(tmp_path / "leaf.zip", usize=3 * 1024**3)
    for level in range(6):
        wrapper = tmp_path / f"level{level}.zip"
        make_zip(wrapper, {"inner.zip": current.read_bytes()})
        current = wrapper
    result = scan_file(str(current))
    assert result.verdict == "dangerous"
    assert "NESTED_BOMB" in {f.code for f in result.findings}


def test_zip_depth_limit(tmp_path):
    inner = build_single_entry_zip(tmp_path / "inner.zip", usize=3 * 1024**3)
    outer = make_zip(tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()})
    result = scan_file(str(outer), Limits(max_depth=0))
    assert result.verdict == "clean"
    assert any("depth" in note.lower() for note in result.notes)


def test_empty_zip_is_clean(tmp_path):
    path = tmp_path / "empty.zip"
    with zipfile.ZipFile(path, "w"):
        pass
    result = scan_file(str(path))
    assert result.verdict == "clean"
    assert result.entry_count == 0


def test_encrypted_nested_archive_is_suspicious(tmp_path):
    path = build_encrypted_archive_member_zip(tmp_path / "encrypted.zip")
    result = scan_file(str(path))
    assert result.verdict == "suspicious"
    assert "ENCRYPTED_NESTED_ARCHIVE" in {f.code for f in result.findings}


def test_directory_entry_is_ignored_for_ratio(tmp_path):
    path = tmp_path / "dirs.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("folder/", b"")
        zf.writestr("folder/a.txt", b"a")
    result = scan_file(str(path))
    assert result.verdict == "clean"
    assert result.entry_count == 2
