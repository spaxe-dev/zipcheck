# Where archives keep their real size

This is the byte-level companion to the README. `zipcheck` reads these fields
directly; it does not decompress an archive to learn how large it will become.
Static decompression is limited to small bounded consistency probes.

All offsets are decimal bytes from the start of the relevant structure unless
stated otherwise. Multi-byte integers are little-endian unless noted.

---

## ZIP

### Local file header (at the offset stored in the central directory)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | signature `50 4B 03 04` (`PK\x03\x04`) |
| 4 | 2 | version needed |
| 6 | 2 | general-purpose flags (bit 0 = encrypted, bit 3 = data descriptor, bit 11 = UTF-8) |
| 8 | 2 | compression method (0 stored, 8 deflate, 12 bzip2, 14 LZMA, 93 zstd, 95 xz, 99 AES) |
| 10 | 2 | modification time |
| 12 | 2 | modification date |
| 14 | 4 | CRC-32 |
| 18 | 4 | compressed size (may be `0xFFFFFFFF` → ZIP64) |
| 22 | 4 | uncompressed size (may be `0xFFFFFFFF` → ZIP64) |
| 26 | 2 | file name length |
| 28 | 2 | extra field length |
| 30 | … | name, then extra fields, then data |

### Central directory entry (`PK\x01\x02`)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | signature |
| 4 | 2 | version made by |
| 6 | 2 | version needed |
| 8 | 2 | flags |
| 10 | 2 | method |
| 12 | 2 | time |
| 14 | 2 | date |
| 16 | 4 | CRC-32 |
| 20 | 4 | compressed size |
| 24 | 4 | **uncompressed size** |
| 28 | 2 | name length |
| 30 | 2 | extra length |
| 32 | 2 | comment length |
| 34 | 2 | disk start |
| 36 | 2 | internal attributes |
| 38 | 4 | external attributes |
| 42 | 4 | **local header offset** |
| 46 | … | name, extra, comment |

The `0x0001` ZIP64 extra field carries 8-byte values **only for the fields that
were `0xFFFFFFFF`/`0xFFFF`**, in this order: uncompressed size, compressed size,
local header offset, disk number.

### End of central directory (`PK\x05\x06`)

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | signature |
| 4 | 2 | this disk |
| 6 | 2 | central-directory disk |
| 8 | 2 | entries on this disk |
| 10 | 2 | **total entries** |
| 12 | 4 | central-directory size |
| 16 | 4 | central-directory offset |
| 20 | 2 | comment length |

ZIP64 adds a 56-byte ZIP64 EOCD record (`PK\x06\x06`) with 8-byte counts,
directory size and offset, preceded by a locator (`PK\x06\x07`). A self-
extracting archive prepends a stub, so the central-directory offset is shifted;
zipcheck computes the shift from the EOCD position.

### The non-recursive bomb trick

A normal member's data range is `[local + 30 + name_len + extra_len,
  + compressed_size)`. Two central-directory entries may point at the same
local header, or their ranges may overlap. The same compressed bytes then count
as output for multiple members. Because each member's declared uncompressed
size can still be huge, this produces an enormous expansion from a tiny file
without any recursion. It is detected as `OVERLAPPING_ENTRIES` /
`OVERLAPPING_DATA`.

A related giveaway: DEFLATE's maximum theoretical expansion is about
**1032:1**. A declared ratio beyond that cannot be produced by ordinary DEFLATE
and implies overlap or a lying directory.

### Forged compressed sizes and the tail probe

Both copies of a size can be forged consistently, so the ratio arithmetic sees
an innocent 1:1 member. One static signal remains: layout. If the declared data
range ends before the next local header or the central directory, the bytes in
between are unexplained. zipcheck decodes at most 64 KiB of that member's
declared compressed bytes (256 members and 4 MiB of total output per archive)
and asks whether the stream ends at the declared compressed size. If it does
not, the result is `UNDERSTATED_COMPRESSED_SIZE` (HIGH). Output larger than the
declared `usize` produces `METADATA_UNDERSTATED` (HIGH). This catches the crude
forged-size class without decompressing normal archives. A forgery arranged to
look contiguous, or one outside the probe caps, remains invisible until
`--verify`.

---

## TAR

Each member starts with a 512-byte header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 100 | name |
| 100 | 8 | mode |
| 108 | 8 | uid |
| 116 | 8 | gid |
| 124 | 12 | **size (octal, or base-256 if the high bit is set)** |
| 136 | 12 | mtime |
| 148 | 8 | checksum (spaces while computing) |
| 156 | 1 | typeflag (`0` file, `5` directory, `x` PAX, `L` GNU long name, `S` GNU sparse) |
| 157 | 100 | link name |
| 257 | 6 | magic `ustar\0` (not always present) |
| 263 | 2 | version |
| 345 | 155 | prefix |
| 386 | 96 | old-GNU sparse map (4 × 24-byte entries) |
| 482 | 1 | old-GNU sparse extended flag |
| 483 | 12 | **old-GNU sparse real size** |
| 495 | 17 | padding |

Data follows the header, padded to a multiple of 512. A PAX `x` header contains
`<length> <key>=<value>\n` records and overrides the next header's `path`,
`size`, `GNU.sparse.realsize` and `GNU.sparse.name`.

A plain TAR cannot be smaller than the data it stores. The dangerous case is a
**sparse** member: the header's apparent size is terabytes while the archive
only stores the non-hole fragments. A 10 KiB TAR can legally declare a 1 TiB
file.

---

## gzip

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | `1F` |
| 1 | 1 | `8B` |
| 2 | 1 | compression method (8 = deflate) |
| 3 | 1 | flags (bit 1 FHCRC, 2 FEXTRA, 3 FNAME, 4 FCOMMENT) |
| 4 | 4 | mtime |
| 8 | 1 | XFL |
| 9 | 1 | OS |
| 10 | … | optional extra/name/comment/header-CRC |

The last 8 bytes of a member are:

| Offset | Size | Field |
|---:|---:|---|
| -8 | 4 | CRC-32 of the uncompressed data |
| -4 | 4 | **ISIZE: uncompressed size modulo 2³²** |

So a 1 GiB zero file can be recognised from its final four bytes
(`00 00 00 40`) without decompressing anything. `ISIZE` is ambiguous for exact
multiples of 4 GiB and describes only the final member, so `zipcheck` counts
every concatenated member with a bounded probe (64 MiB cap).

Multiple gzip members can be concatenated; each has its own trailer. Only the
final member's `ISIZE` is visible at the end of the file, which is why a
metadata-only reading can understate the output arbitrarily. If the probe
reaches its cap the result is `unknown`; if the measured total exceeds the
trailer, `ISIZE_UNDERSTATED` (LOW) is reported.

---

## bzip2

`BZh` followed by a level digit (`1`–`9`). There is **no uncompressed-size
field** anywhere in the format. Blocks start with `31 41 59 26 53 59` and the
stream ends with `17 72 45 38 50 90` plus a combined CRC, but sizes are not
stored.

The only static options are the compressed size and a bounded decompression.
That is why bzip2 gets a probe by default: zipcheck decompresses into a counter,
never storing the output, and stops at 64 MiB.

---

## xz

The last 12 bytes are the stream footer:

| Offset from end | Size | Field |
|---:|---:|---|
| -12 | 4 | CRC-32 of the footer |
| -8 | 4 | backward size = `(index_size / 4) - 1` |
| -4 | 2 | stream flags |
| -2 | 2 | `YZ` (`59 5A`) |

The index sits immediately before the footer. It starts with `00`, then a
variable-length record count, then pairs of variable-length integers:

```
unpadded_size, uncompressed_size
```

Summing the uncompressed sizes gives the exact expansion without touching block
data. Concatenated streams each have their own index/footer; zipcheck reads the
final one.

Bare LZMA (`.lzma`) has no index. Its 13-byte header is:
1 byte properties, 4 bytes dictionary size, 8 bytes uncompressed size
(`FF FF FF FF FF FF FF FF` means unknown).

---

## Zstandard

A frame begins with:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `28 B5 2F FD` |
| 4 | 1 | frame header descriptor |
| 5 | 0/1 | window descriptor (if not single-segment) |
| … | 0/1/2/4 | dictionary ID |
| … | 0/1/2/4/8 | **frame content size** |

Descriptor bits:

- bits 7–6: content-size flag (`0`: 1 byte if single-segment else absent,
  `1`: 2 bytes, `2`: 4 bytes, `3`: 8 bytes);
- bit 5: single-segment;
- bit 4: unused;
- bit 3: reserved;
- bit 2: content checksum;
- bits 1–0: dictionary-ID size code.

A 2-byte content size is stored as `value - 256`. If the content size is absent,
the frame's expansion cannot be known without decompression, so the scan is
reported as `unknown`. Skippable frames (`50 2A 4D 18`–`5F 2A 4D 18`) have a
4-byte little-endian payload size after the magic and are skipped.

---

## 7-Zip

Start header (32 bytes):

| Offset | Size | Field |
|---:|---:|---|
| 0 | 6 | `37 7A BC AF 27 1C` |
| 6 | 2 | version |
| 8 | 4 | start-header CRC-32 (covers bytes 12–31) |
| 12 | 8 | **next-header offset** (relative to byte 32) |
| 20 | 8 | **next-header size** |
| 28 | 4 | next-header CRC-32 |

The next header is at `32 + offset`. Its first byte is `01` for a plain header
or `17` for an encoded (compressed) header. Encoded headers are followed by a
`StreamsInfo` structure describing packed streams, folders and coders; the most
common coder is LZMA (`03 01 01`) or LZMA2 (`21`).

zipcheck decodes only that header (maximum 32 MiB in, 32 MiB out), then parses:

- `kPackInfo (06)` → packed sizes;
- `kUnPackInfo (07)` → folders and `kCodersUnPackSize (0C)`, the uncompressed
  size of each folder's output;
- `kFilesInfo (05)` → number of files and names.

The sum of folder output sizes is the total expansion. Member data is never
decoded.

7-Zip numbers use a prefix-coded variable-length integer: the number of leading
one-bits in the first byte says how many extra bytes follow; the remaining bits
of the first byte are the high part.

---

## RAR 5

Signature: `52 61 72 21 1A 07 01 00` (`Rar!\x1A\x07\x01\x00`).

Each block:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | header CRC-32 |
| 4 | varint | header size (from the type field to the end of the header) |
| … | varint | block type (1 main, 2 file, 4 encryption, 5 end) |
| … | varint | header flags (bit 0 extra area, bit 1 data area) |
| … | varint | extra area size (if flag 0) |
| … | varint | data area size (if flag 1) |
| … | … | type-specific fields |

A file block (`type 2`) then has: file flags, **unpacked size**, attributes,
optional mtime/CRC, compression info, host OS, name length, name. The header
CRC covers the size varint plus the header (not the CRC itself). File
encryption is recorded as a type-1 record in the extra area.

## RAR 4

Signature: `52 61 72 21 1A 07 00` (`Rar!\x1A\x07\x00`).

Each block: CRC-16 (2), type (1), flags (2), header size (2), optional data
size (4, if flag `0x8000`), then the body. A file header (`0x74`) contains:
packed size (4), **unpacked size (4)**, host OS (1), CRC (4), mtime (4), version
(1), method (1), name length (2), attributes (4), name. The `0x0100` flag adds
8-byte high packed/unpacked sizes; `0x0004` marks an encrypted file.

---

## Why a magic signature cannot work

All of the structures above are valid for both benign and malicious archives.
There is no reserved field, flag, or byte sequence that means "bomb". The only
reliable signal is arithmetic: declared output versus on-disk input, structure
overlaps, sparse logical sizes, and nesting. That arithmetic is what a static
detector can check — and what a sufficiently clever attacker can falsify. Treat
the result as risk evidence, not proof.
