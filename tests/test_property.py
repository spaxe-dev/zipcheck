from __future__ import annotations

import gzip
import io
import lzma
import zipfile

from hypothesis import given, settings
from hypothesis import strategies as st

from zipcheck import Limits, scan_bytes

VERDICTS = {"clean", "suspicious", "dangerous", "unknown"}
MAGICS = [
    b"PK\x03\x04",
    b"\x1f\x8b\x08",
    b"BZh9",
    b"\xfd7zXZ\x00",
    b"\x5d\x00\x00",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07\x00",
    b"Rar!\x1a\x07\x01\x00",
    b"\x28\xb5\x2f\xfd",
]

LIMITS = Limits(
    max_entries=2_000,
    max_entries_parse=2_000,
    max_cd_bytes=1024 * 1024,
    max_header_bytes=1024 * 1024,
    max_depth=3,
    max_nested_candidates=8,
    max_nested_archives=16,
    max_nested_compressed=256 * 1024,
    nested_prefix_bytes=128 * 1024,
    nested_capture_bytes=256 * 1024,
    nested_budget_bytes=1024 * 1024,
    nested_verify_limit=512 * 1024,
    max_decoder_memory=16 * 1024 * 1024,
    probe_limit=256 * 1024,
    verify=True,
    verify_limit=256 * 1024,
    timeout=5.0,
)


def _clean_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("readme.txt", b"hello" * 100)
    return buffer.getvalue()


MUTATION_TARGETS = [
    _clean_zip(),
    gzip.compress(b"hello" * 100),
    lzma.compress(b"hello" * 100),
]


@settings(max_examples=50, deadline=None)
@given(st.binary(max_size=4096))
def test_arbitrary_bytes_never_escape(data):
    result = scan_bytes(data, name="<fuzz>", limits=LIMITS)
    assert result.verdict in VERDICTS
    assert result.path == "<fuzz>"


@settings(max_examples=100, deadline=None)
@given(st.sampled_from(MAGICS), st.binary(max_size=8192))
def test_magic_prefixed_bytes_never_escape(magic, tail):
    result = scan_bytes(magic + tail, name="<fuzz>", limits=LIMITS)
    assert result.verdict in VERDICTS


@settings(max_examples=100, deadline=None)
@given(st.sampled_from(MUTATION_TARGETS), st.data())
def test_single_byte_mutations_never_escape(target, data):
    index = data.draw(st.integers(min_value=0, max_value=len(target) - 1))
    value = data.draw(st.integers(min_value=0, max_value=255))
    mutated = bytearray(target)
    mutated[index] = value
    result = scan_bytes(bytes(mutated), name="<fuzz>", limits=LIMITS)
    assert result.verdict in VERDICTS
