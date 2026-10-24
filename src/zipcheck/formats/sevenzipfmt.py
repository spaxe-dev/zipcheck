"""7-Zip metadata parser.

7z stores sizes in a header that may itself be LZMA-compressed (an "encoded
header").  This module parses the container and, for encoded headers, decodes
only the header -- capped in both input and output -- so file sizes can be
summed without touching member data.  No file data is decoded.
"""

from __future__ import annotations

import lzma
import zlib
from dataclasses import dataclass, field
from typing import BinaryIO, List, Tuple

from ..limits import Limits
from ..model import Facts, Finding, Severity
from ..reader import ByteReader, Deadline, FormatError, read_at, u32le, u64le

MAGIC = b"7z\xbc\xaf\x27\x1c"

K_END = 0x00
K_HEADER = 0x01
K_ARCHIVE_PROPERTIES = 0x02
K_ADDITIONAL_STREAMS_INFO = 0x03
K_MAIN_STREAMS_INFO = 0x04
K_FILES_INFO = 0x05
K_PACK_INFO = 0x06
K_UNPACK_INFO = 0x07
K_SUBSTREAMS_INFO = 0x08
K_SIZE = 0x09
K_CRC = 0x0A
K_FOLDER = 0x0B
K_CODERS_UNPACK_SIZE = 0x0C
K_NUM_UNPACK_STREAM = 0x0D
K_EMPTY_STREAM = 0x0E
K_EMPTY_FILE = 0x0F
K_ANTI = 0x10
K_NAME = 0x11
K_ENCODED_HEADER = 0x17

AES_CODER_ID = b"\x06\xf1\x07\x01"


@dataclass
class Coder:
    coder_id: bytes
    props: bytes
    num_in: int
    num_out: int


@dataclass
class Folder:
    coders: List[Coder] = field(default_factory=list)
    unpack_sizes: List[int] = field(default_factory=list)
    num_out_streams: int = 0

    @property
    def final_size(self) -> int:
        return self.unpack_sizes[-1] if self.unpack_sizes else 0


@dataclass
class Streams:
    pack_pos: int = 0
    pack_sizes: List[int] = field(default_factory=list)
    folders: List[Folder] = field(default_factory=list)


def _parse_pack_info(r: ByteReader, st: Streams) -> None:
    st.pack_pos = r.num()
    count = r.num()
    while True:
        pid = r.u8()
        if pid == K_END:
            break
        if pid == K_SIZE:
            st.pack_sizes = [r.num() for _ in range(count)]
        elif pid == K_CRC:
            for _ in range(count):
                r.skip(4)
        else:
            raise FormatError(f"unexpected 7z PackInfo property 0x{pid:02x}")
    if not st.pack_sizes:
        st.pack_sizes = [0] * count


def _parse_folder(r: ByteReader) -> Folder:
    folder = Folder()
    num_coders = r.num()
    total_in = total_out = 0
    for _ in range(num_coders):
        flags = r.u8()
        id_size = flags & 0x0F
        coder_id = r.take(id_size)
        if flags & 0x10:
            num_in = r.num()
            num_out = r.num()
        else:
            num_in = num_out = 1
        total_in += num_in
        total_out += num_out
        props = b""
        if flags & 0x20:
            props = r.take(r.num())
        folder.coders.append(Coder(coder_id, props, num_in, num_out))
    folder.num_out_streams = total_out
    for _ in range(max(0, total_out - 1)):
        r.num()  # input stream index
        r.num()  # output stream index
    packed_streams = total_in - max(0, total_out - 1)
    for _ in range(max(0, packed_streams - 1)):
        r.num()
    return folder


def _parse_unpack_info(r: ByteReader, st: Streams) -> None:
    if r.u8() != K_FOLDER:
        raise FormatError("7z UnPackInfo does not start with kFolder")
    num_folders = r.num()
    external = r.u8()
    if external:
        raise FormatError("external 7z folder data is not supported")
    for _ in range(num_folders):
        st.folders.append(_parse_folder(r))
    if r.u8() != K_CODERS_UNPACK_SIZE:
        raise FormatError("7z UnPackInfo has no kCodersUnPackSize")
    for folder in st.folders:
        folder.unpack_sizes = [r.num() for _ in range(folder.num_out_streams)]
    # Optional CRCs.
    while True:
        pid = r.u8()
        if pid == K_END:
            break
        if pid == K_CRC:
            all_defined = r.u8()
            defined = num_folders
            if not all_defined:
                bitmap = r.take((num_folders + 7) // 8)
                defined = sum(bin(byte).count("1") for byte in bitmap)
            for _ in range(defined):
                r.skip(4)
        else:
            raise FormatError(f"unexpected 7z UnPackInfo property 0x{pid:02x}")


def _parse_substreams_info(r: ByteReader, st: Streams) -> None:
    counts = [1] * len(st.folders)
    total_substreams = len(st.folders)
    while True:
        pid = r.u8()
        if pid == K_END:
            break
        if pid == K_NUM_UNPACK_STREAM:
            counts = [r.num() for _ in st.folders]
            total_substreams = sum(counts)
        elif pid == K_SIZE:
            for _ in range(max(0, total_substreams - len(st.folders))):
                r.num()
        elif pid == K_CRC:
            defined = r.u8()
            if not defined:
                r.skip((total_substreams + 7) // 8)
                # all defined digests follow, but count is unknown here; headers
                # using an all-zero bitmap are rare.  Refuse rather than guess.
                raise FormatError("7z substream CRC bitmap is not supported")
            for _ in range(total_substreams):
                r.skip(4)
        else:
            raise FormatError(f"unexpected 7z SubStreamsInfo property 0x{pid:02x}")


def _parse_streams(r: ByteReader) -> Streams:
    st = Streams()
    while True:
        pid = r.u8()
        if pid == K_END:
            break
        if pid == K_PACK_INFO:
            _parse_pack_info(r, st)
        elif pid == K_UNPACK_INFO:
            _parse_unpack_info(r, st)
        elif pid == K_SUBSTREAMS_INFO:
            _parse_substreams_info(r, st)
        else:
            raise FormatError(f"unexpected 7z StreamsInfo property 0x{pid:02x}")
    return st


def _parse_files_info(r: ByteReader, limits: Limits) -> Tuple[int, List[str], bool]:
    num_files = r.num()
    names: List[str] = []
    complete = True
    while True:
        pid = r.u8()
        if pid == K_END:
            break
        size = r.num()
        data = r.take(size)
        if pid == K_EMPTY_STREAM:
            pass  # bitmap of empty streams; not needed for size totals
        elif pid == K_NAME:
            if not data or data[0] != 0:
                raise FormatError("external 7z file names are not supported")
            raw = data[1:]
            if len(raw) % 2:
                raw = raw[:-1]
            try:
                decoded = raw.decode("utf-16-le", "replace")
            except UnicodeDecodeError:  # pragma: no cover
                decoded = raw.decode("utf-16-le", "replace")
            names = [n for n in decoded.split("\x00") if n]
        # kEmptyFile, kAnti, kCTime/kATime/kMTime, kWinAttributes and
        # kStartPos are not needed for expansion analysis.
    if num_files > limits.max_entries_parse:
        complete = False
    return num_files, names, complete


def _parse_header(data: bytes, limits: Limits) -> Tuple[Streams, int, List[str], bool]:
    r = ByteReader(data)
    if r.u8() != K_HEADER:
        raise FormatError("7z header does not start with kHeader")
    main = Streams()
    num_files = 0
    names: List[str] = []
    complete = True
    while not r.eof():
        pid = r.u8()
        if pid == K_END:
            break
        if pid == K_ARCHIVE_PROPERTIES:
            r.skip(r.num())
        elif pid == K_ADDITIONAL_STREAMS_INFO:
            _parse_streams(r)
        elif pid == K_MAIN_STREAMS_INFO:
            main = _parse_streams(r)
        elif pid == K_FILES_INFO:
            num_files, names, files_complete = _parse_files_info(r, limits)
            complete = complete and files_complete
        else:
            raise FormatError(f"unexpected 7z header property 0x{pid:02x}")
    return main, num_files, names, complete


def _decode_coder(
    coder: Coder, packed: bytes, output_cap: int, memlimit: int
) -> bytes:
    if coder.coder_id == b"\x03\x01\x01":
        if len(coder.props) < 5:
            raise FormatError("short LZMA properties in 7z header")
        prop0 = coder.props[0]
        lc = prop0 % 9
        rest = prop0 // 9
        lp = rest % 5
        pb = rest // 5
        dict_size = u32le(coder.props, 1)
        if dict_size > memlimit:
            raise FormatError("7z header dictionary exceeds the safety cap")
        filters = [
            {
                "id": lzma.FILTER_LZMA1,
                "lc": lc,
                "lp": lp,
                "pb": pb,
                "dict_size": max(dict_size, 4096),
            }
        ]
    elif coder.coder_id == b"\x21":
        if not coder.props:
            raise FormatError("missing LZMA2 properties in 7z header")
        p = coder.props[0]
        dict_size = 0xFFFFFFFF if p == 40 else (2 | (p & 1)) << (p // 2 + 11)
        if dict_size > memlimit:
            raise FormatError("7z header dictionary exceeds the safety cap")
        filters = [{"id": lzma.FILTER_LZMA2, "dict_size": dict_size}]
    else:
        if coder.coder_id == AES_CODER_ID:
            raise FormatError("7z header is encrypted")
        raise FormatError(
            "unsupported encoded-header coder "
            + coder.coder_id.hex()
            + " (only LZMA/LZMA2 are supported)"
        )
    decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
    out = bytearray()
    try:
        out.extend(decompressor.decompress(packed, output_cap))
    except lzma.LZMAError as exc:
        raise FormatError(f"cannot decode 7z header: {exc}") from exc
    if len(out) >= output_cap and not decompressor.eof:
        raise FormatError("7z encoded header exceeds the safety cap")
    return bytes(out)


def scan(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    deadline.check()
    start = read_at(fp, 0, 32)
    if len(start) < 32 or not start.startswith(MAGIC):
        raise FormatError("not a 7-Zip archive")
    start_crc = u32le(start, 8)
    calculated = zlib.crc32(start[12:32]) & 0xFFFFFFFF
    next_offset = u64le(start, 12)
    next_size = u64le(start, 20)
    next_crc = u32le(start, 28)
    notes: List[str] = []
    findings: List[Finding] = []
    if start_crc != calculated:
        findings.append(
            Finding(
                code="HEADER_CRC_MISMATCH",
                severity=Severity.LOW,
                title="7-Zip start-header CRC mismatch",
                detail="The 32-byte start header does not match its CRC32.",
                evidence={"expected": start_crc, "calculated": calculated},
            )
        )
    if next_size == 0:
        return Facts(format="7z", detail="7-Zip, empty archive", notes=notes)
    if next_size > limits.max_header_bytes:
        raise FormatError("7z header is larger than the configured safety cap")
    if 32 + next_offset + next_size > size:
        raise FormatError("7z header points outside the file")
    header = read_at(fp, 32 + next_offset, next_size)
    if len(header) < next_size:
        raise FormatError("truncated 7z header")
    if (zlib.crc32(header) & 0xFFFFFFFF) != next_crc:
        notes.append("7z next-header CRC mismatch")

    decoded_note = ""
    if header[:1] == bytes([K_ENCODED_HEADER]):
        r = ByteReader(header, 1)
        st = _parse_streams(r)
        if len(st.folders) != 1 or len(st.folders[0].coders) != 1:
            raise FormatError("unsupported 7z encoded-header coder chain")
        folder = st.folders[0]
        packed_size = sum(st.pack_sizes)
        if packed_size > limits.max_header_bytes:
            raise FormatError("7z encoded header input exceeds the safety cap")
        packed = read_at(fp, 32 + st.pack_pos, packed_size)
        if len(packed) < packed_size:
            raise FormatError("truncated 7z encoded header")
        header = _decode_coder(
            folder.coders[0],
            packed,
            limits.max_header_bytes,
            limits.max_decoder_memory,
        )
        decoded_note = "encoded header decoded"
        if header[:1] != bytes([K_HEADER]):
            raise FormatError("decoded 7z header is malformed")
    elif header[:1] != bytes([K_HEADER]):
        raise FormatError("unknown 7z header type")

    main, num_files, _names, complete = _parse_header(header, limits)
    declared = sum(f.final_size for f in main.folders)
    compressed = sum(main.pack_sizes)
    encrypted = any(
        coder.coder_id == AES_CODER_ID
        for folder in main.folders
        for coder in folder.coders
    )
    if decoded_note:
        notes.append(decoded_note)
    if encrypted:
        notes.append("7-Zip member data is encrypted")
    notes.append("7-Zip member data is never decoded")
    if any(len(f.coders) > 1 for f in main.folders):
        notes.append("multi-coder 7z folders: final output stream size is used")

    return Facts(
        format="7z",
        detail=f"7-Zip, {num_files} file(s)",
        declared_uncompressed=declared,
        declared_compressed=compressed,
        entry_count=num_files,
        findings=findings,
        notes=notes,
        complete=complete,
        encrypted=encrypted,
    )
