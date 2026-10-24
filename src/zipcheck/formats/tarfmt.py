"""TAR metadata parser.

TAR is not compressed, so a normal TAR rarely expands more than its own size.
The interesting cases are (a) GNU/PAX sparse members, whose apparent size is
stored in metadata while the archive only holds the non-zero fragments, and
(b) TAR files nested inside compressed streams (handled by the engine).
"""

from __future__ import annotations

from typing import BinaryIO, Dict, List, Optional

from ..limits import Limits
from ..model import EntryInfo, Facts, Finding, Severity
from ..reader import Deadline, FormatError, read_at, round_up

BLOCK = 512

TYPE_REGULAR = (b"0", b"\x00", b"7")
TYPE_HARDLINK = b"1"
TYPE_SYMLINK = b"2"
TYPE_CHAR = b"3"
TYPE_BLOCK = b"4"
TYPE_DIR = b"5"
TYPE_FIFO = b"6"
TYPE_GNU_SPARSE = b"S"
TYPE_PAX = b"x"
TYPE_PAX_GLOBAL = b"g"
TYPE_GNU_LONGNAME = b"L"
TYPE_GNU_LONGLINK = b"K"


def _tar_number(field: bytes) -> int:
    if not field:
        return 0
    if field[0] & 0x80:
        # GNU base-256: the high bit marks the encoding; trailing NULs are
        # significant, so do not strip before decoding.
        return int.from_bytes(bytes([field[0] & 0x7F]) + field[1:], "big")
    field = field.rstrip(b"\x00 ")
    if not field:
        return 0
    try:
        return int(field, 8)
    except ValueError as exc:
        raise FormatError(f"invalid octal field {field!r}") from exc


def _checksum_ok(block: bytes) -> bool:
    try:
        stored = _tar_number(block[148:156])
    except FormatError:
        return False
    unsigned = sum(block[:148]) + 8 * 0x20 + sum(block[156:])
    if stored == unsigned:
        return True
    signed = sum(b - 256 if b > 127 else b for b in block[:148]) + 8 * 0x20
    signed += sum(b - 256 if b > 127 else b for b in block[156:])
    return stored == signed


def _decode(raw: bytes) -> str:
    return raw.rstrip(b"\x00").decode("utf-8", "replace")


def _pax_records(data: bytes) -> Dict[str, str]:
    out: Dict[str, str] = {}
    pos = 0
    while pos < len(data):
        space = data.find(b" ", pos)
        if space < 0:
            break
        try:
            length = int(data[pos:space])
        except ValueError:
            break
        if length <= 0 or pos + length > len(data):
            break
        record = data[space + 1 : pos + length]
        if record.endswith(b"\n"):
            record = record[:-1]
        key, sep, value = record.partition(b"=")
        if sep:
            out[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
        pos += length
    return out


def scan(fp: BinaryIO, size: int, limits: Limits, deadline: Deadline) -> Facts:
    offset = 0
    entries: List[EntryInfo] = []
    findings: List[Finding] = []
    notes: List[str] = []
    total_usize = 0
    total_stored = 0
    sparse_total = 0
    sparse_count = 0
    pending_name: Optional[str] = None
    pending_size: Optional[int] = None
    pending_sparse: Optional[int] = None
    global_pax: Dict[str, str] = {}
    complete = True
    seen_headers = 0
    saw_end_marker = False

    while offset + BLOCK <= size:
        deadline.check()
        block = read_at(fp, offset, BLOCK)
        if len(block) < BLOCK:
            notes.append("truncated TAR header block")
            complete = False
            break
        if block == b"\x00" * BLOCK:
            saw_end_marker = True
            break

        magic = block[257:263]
        if not (magic.startswith(b"ustar") or _checksum_ok(block)):
            if seen_headers == 0:
                raise FormatError("not a TAR archive (bad header checksum)")
            notes.append("invalid TAR header checksum; stopping")
            complete = False
            break
        seen_headers += 1
        if seen_headers > limits.max_entries_parse:
            notes.append(f"entry limit {limits.max_entries_parse} reached; totals are partial")
            complete = False
            break

        name = _decode(block[0:100])
        prefix = _decode(block[345:500])
        if prefix:
            name = f"{prefix}/{name}"
        typeflag = block[156:157]
        stored_size = _tar_number(block[124:136])
        next_offset = offset + BLOCK

        if typeflag in (TYPE_PAX, TYPE_PAX_GLOBAL):
            read_len = min(stored_size, limits.max_pax_bytes)
            pax_data = read_at(fp, next_offset, read_len)
            records = _pax_records(pax_data)
            if stored_size > limits.max_pax_bytes:
                notes.append("oversized PAX header was truncated for safety")
            if typeflag == TYPE_PAX_GLOBAL:
                global_pax.update(records)
            else:
                pax = {**global_pax, **records}
                sparse_name = pax.get("GNU.sparse.name") or pax.get("path")
                if sparse_name:
                    pending_name = sparse_name
                if "size" in pax:
                    try:
                        pending_size = int(pax["size"])
                    except ValueError:
                        notes.append("invalid PAX size value")
                for key in ("GNU.sparse.realsize", "GNU.sparse.size"):
                    if key in pax:
                        try:
                            pending_sparse = int(pax[key])
                        except ValueError:
                            notes.append("invalid PAX sparse size")
                        break
            offset = next_offset + round_up(stored_size, BLOCK)
            continue

        if typeflag == TYPE_GNU_LONGNAME:
            read_len = min(stored_size, limits.max_name_bytes)
            pending_name = _decode(read_at(fp, next_offset, read_len))
            offset = next_offset + round_up(stored_size, BLOCK)
            continue

        if typeflag == TYPE_GNU_LONGLINK:
            offset = next_offset + round_up(stored_size, BLOCK)
            continue

        if pending_name is not None:
            name = pending_name
            pending_name = None

        data_offset = next_offset
        is_sparse = False
        usize = pending_size if pending_size is not None else stored_size
        if pending_sparse is not None:
            is_sparse = True
            usize = pending_sparse
            pending_sparse = None

        if typeflag == TYPE_GNU_SPARSE:
            is_sparse = True
            try:
                real = _tar_number(block[483:495])
            except FormatError:
                real = stored_size
            if real:
                usize = real
            is_extended = block[482] == 1
            while is_extended:
                ext = read_at(fp, data_offset, BLOCK)
                if len(ext) < BLOCK:
                    notes.append("truncated GNU sparse extension block")
                    complete = False
                    break
                is_extended = ext[504] == 1
                data_offset += BLOCK

        pending_size = None
        pending_sparse = None

        is_dir = typeflag == TYPE_DIR
        if not is_dir and typeflag not in (
            TYPE_HARDLINK,
            TYPE_SYMLINK,
            TYPE_CHAR,
            TYPE_BLOCK,
            TYPE_FIFO,
        ):
            entry = EntryInfo(
                name=name,
                usize=usize,
                csize=stored_size,
                method="stored",
                is_dir=is_dir,
                sparse=is_sparse,
                data_offset=None if is_sparse else data_offset,
            )
            entries.append(entry)
            total_usize += usize
            total_stored += stored_size
            if is_sparse:
                sparse_total += usize
                sparse_count += 1

        data_end = data_offset + round_up(stored_size, BLOCK)
        if data_end > size:
            notes.append(
                f"member {name!r} extends past EOF; archive appears truncated"
            )
            complete = False
            offset = data_end
            break
        offset = data_end

    if not entries and not (seen_headers or saw_end_marker):
        raise FormatError("TAR archive contains no regular file members")
    if sparse_count:
        findings.append(
            Finding(
                code="SPARSE_MEMBERS",
                severity=Severity.INFO,
                title="Sparse members present",
                detail=(
                    f"{sparse_count} sparse member(s) declare "
                    f"{sparse_total} apparent bytes. Sparse files can have a huge "
                    "logical size while occupying almost no archive space."
                ),
                evidence={"count": sparse_count, "apparent_size": sparse_total},
            )
        )

    return Facts(
        format="tar",
        detail=f"TAR, {len(entries)} file members",
        declared_uncompressed=total_usize,
        declared_compressed=total_stored,
        entry_count=len(entries),
        entries=entries,
        findings=findings,
        notes=notes,
        complete=complete,
        sparse_total=sparse_total,
    )
