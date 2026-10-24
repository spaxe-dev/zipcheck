from __future__ import annotations

import io
import tarfile

from zipcheck import scan_file

from .helpers import build_sparse_tar, build_tar, build_truncated_tar


def test_clean_tar(tmp_path):
    path = build_tar(tmp_path / "clean.tar", {"a.txt": b"hello\n"})
    result = scan_file(str(path))
    assert result.verdict == "clean"
    assert result.format == "tar"
    assert result.declared_uncompressed == 6


def test_empty_tar_is_clean(tmp_path):
    path = tmp_path / "empty.tar"
    path.write_bytes(b"\0" * 1024)
    result = scan_file(str(path))
    assert result.format == "tar"
    assert result.verdict == "clean"
    assert result.declared_uncompressed == 0


def test_sparse_tar_is_dangerous(tmp_path):
    path = build_sparse_tar(tmp_path / "sparse.tar", realsize=1 * 1024**4)
    result = scan_file(str(path))
    assert result.format == "tar"
    assert result.declared_uncompressed == 1 * 1024**4
    assert "SPARSE_MEMBERS" in {f.code for f in result.findings}
    assert result.verdict == "dangerous"


def test_truncated_tar_with_huge_declared_size(tmp_path):
    path = build_truncated_tar(tmp_path / "huge.tar", size=20 * 1024**3)
    result = scan_file(str(path))
    assert result.declared_uncompressed == 20 * 1024**3
    assert result.verdict == "dangerous"


def test_tar_nested_archive(tmp_path):
    inner = build_sparse_tar(tmp_path / "inner.tar", realsize=1 * 1024**4)
    outer = build_tar(tmp_path / "outer.tar", {"inner.tar": inner.read_bytes()})
    result = scan_file(str(outer))
    assert result.nested
    assert "NESTED_BOMB" in {f.code for f in result.findings}
    assert result.verdict == "dangerous"


def test_tar_pax_long_name(tmp_path):
    long_name = "deep/" + "x" * 180 + ".txt"
    data = b"hello pax"
    path = tmp_path / "pax.tar"
    with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as tf:
        info = tarfile.TarInfo(long_name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    result = scan_file(str(path))
    assert result.verdict == "clean"
    assert result.entries[0].name == long_name
    assert result.declared_uncompressed == len(data)
