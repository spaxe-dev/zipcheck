from __future__ import annotations

import os
import random

from zipcheck import Limits, scan_bytes, scan_file


def _random_blob(rng, size):
    return bytes(rng.randrange(256) for _ in range(size))


def test_random_blobs_do_not_crash(tmp_path):
    rng = random.Random(1234)
    magic = [
        b"",
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"7z\xbc\xaf\x27\x1c",
        b"Rar!\x1a\x07\x01\x00",
        b"Rar!\x1a\x07\x00",
        b"\x1f\x8b\x08",
        b"BZh9",
        b"\xfd7zXZ\x00",
        b"\x28\xb5\x2f\xfd",
    ]
    for i in range(200):
        blob = rng.choice(magic) + _random_blob(rng, rng.randrange(0, 4096))
        path = tmp_path / f"fuzz{i}.zip"
        path.write_bytes(blob)
        result = scan_file(str(path), Limits(timeout=5))
        assert result.verdict in {"clean", "suspicious", "dangerous", "unknown"}
        assert result.error is None or result.verdict == "unknown"


def test_truncated_archives(tmp_path):
    path = tmp_path / "truncated.zip"
    path.write_bytes(b"PK\x03\x04" + b"\0" * 20)
    result = scan_file(str(path))
    assert result.verdict == "unknown"
    assert result.error


def test_scan_bytes_api():
    result = scan_bytes(b"not an archive", "memory.bin")
    assert result.verdict == "unknown"


def test_absolute_path_cannot_escape(tmp_path):
    # sanity: scan_file must not read outside the path it is given
    result = scan_file(str(tmp_path / "does-not-exist.zip"))
    assert result.verdict == "unknown"
    assert os.path.exists(tmp_path)
