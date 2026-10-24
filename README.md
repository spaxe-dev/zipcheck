# zipcheck

**Static zip-bomb / archive-bomb detection that never extracts anything.**

[![PyPI](https://img.shields.io/pypi/v/zipcheck)](https://pypi.org/project/zipcheck/)
[![Python versions](https://img.shields.io/pypi/pyversions/zipcheck)](https://pypi.org/project/zipcheck/)
[![CI](https://github.com/spaxe-dev/zipcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/spaxe-dev/zipcheck/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`zipcheck` reads the *metadata* of an archive — central directories, member
headers, indexes and trailers — and decides whether extracting it is likely to
exhaust your disk, memory or patience. It does not unpack files, does not write
temporary data, and does not run archive tools.

> **"Without opening" means without unpacking.** zipcheck opens the file
> read-only and seeks through header structures. It never decompresses members
> to disk, never writes extracted data, and never executes an archive.
>
> **For production upload pipelines, static metadata alone is not a security
> boundary.** Headers can understate sizes. Use `--production` (which implies
> `--verify --require-verified`) and, more importantly, extract in an isolated
> worker with OS quotas. See [docs/production.md](docs/production.md).

```
$ zipcheck suspicious.zip
  DANGEROUS  suspicious.zip
    format:    zip (ZIP, 1 parsed entries)
    on disk:   1019 KiB
    declared:  1.00 GiB  (1,029:1)
    members:   1
    [HIGH] EXTREME_EXPANSION: Declared expansion is unusually large
            The archive declares 1073741824 bytes of output from 1043746 bytes
            on disk (1,029:1). Extract it only inside a resource-limited sandbox.
```

---

## Table of contents

- [There is no magic "zip bomb signature"](#there-is-no-magic-zip-bomb-signature)
- [What it detects](#what-it-detects)
- [Install](#install)
- [Usage](#usage)
- [Detection rules](#detection-rules)
- [Content verification](#content-verification)
- [How each format is measured](#how-each-format-is-measured)
- [Nested archives and deep bombs](#nested-archives-and-deep-bombs)
- [Safety model](#safety-model)
- [Production deployment](#production-deployment)
- [Validation against real bombs](#validation-against-real-bombs)
- [Limitations and honest caveats](#limitations-and-honest-caveats)
- [JSON output](#json-output)
- [Development](#development)
- [License](#license)

---

## There is no magic "zip bomb signature"

This is the most important thing to understand about the project.

A zip bomb has no special magic bytes. It is a **structurally valid archive**.
File signatures (`PK\x03\x04`, `BZh`, `\xfd7zXZ`, …) tell you the *format*, not
the *intent*. A `.zip` containing your holiday photos and a `.zip` that expands to
4 petabytes start with exactly the same bytes and have the same layout.

What differs is the numbers in the metadata:

| Format | Where the uncompressed size lives | Decompression needed? |
|---|---|---|
| ZIP / ZIP64 | Central directory, 4 or 8 bytes per member, plus the local header | No |
| TAR | 12-byte size field in each 512-byte header; PAX `size`/`GNU.sparse.realsize` overrides | No |
| gzip | `ISIZE` in the last 4 bytes of each member (mod 2³²) | No |
| bzip2 | Nowhere. Must decompress (bounded) to measure | Bounded probe |
| xz | Index at the end: uncompressed size of every block | No |
| LZMA-alone | 8-byte size in the 13-byte header (may be "unknown") | No / probe |
| Zstandard | Frame header content-size field (optional) | No |
| 7-Zip | `kCodersUnPackSize` in the header, possibly LZMA-compressed itself | Header only |
| RAR 4/5 | Unpacked size in each file header | No |

`zipcheck` treats these numbers as untrusted. The "signatures" it looks for are
structural anomalies that bombs cannot easily hide:

- an enormous declared output size or expansion ratio;
- a DEFLATE ratio beyond the format's theoretical maximum (~1032:1), which
  implies overlapping entries or a lying directory;
- multiple members sharing one local header, or overlapping data ranges — the
  classic **non-recursive** (quine) zip bomb;
- sparse TAR members whose logical size is terabytes while the archive is tiny;
- an absurd number of members (inode/time exhaustion);
- an archive inside an archive, recursively, with a bomb at the bottom.

That is what `zipcheck` automates. See
[docs/metadata-map.md](docs/metadata-map.md) for byte offsets and hex-dump
examples.

---

## What it detects

- **ZIP / ZIP64** — declared expansion, per-entry impossible ratios, overlapping
  or shared entries, encrypted archive members, member count, contradictory
  local/central headers and entries hidden from the EOCD count.
- **TAR** — huge declared members, sparse members, truncated archives, PAX and
  GNU long names, nested archives.
- **gzip** — `ISIZE` ratio, >4 GiB wrap handled with a bounded probe, nested
  TAR/ZIP inside the gzip stream.
- **bzip2** — no size field, so a bounded in-memory probe measures the expansion.
- **xz / LZMA** — xz index, LZMA-alone header, bounded probe when the size is
  unknown.
- **Zstandard** — frame-header content size (reports `unknown` if omitted).
- **7-Zip** — plain and LZMA/LZMA2-compressed headers, folder unpack sizes,
  member count.
- **RAR 4 / RAR 5** — per-file unpacked sizes; encrypted headers reported as
  unknown.
- **Nested archives** — ZIP, TAR, gzip, bzip2 and xz are followed up to a
  configurable depth.
- **Content verification** — optional bounded decompression to a counting sink
  catches headers that understate the real size (ZIP stored/deflate/bzip2/LZMA,
  gzip, bzip2, xz/LZMA; TAR plan validation).

Every result is one of: `clean`, `suspicious`, `dangerous`, `unknown`.
**`unknown` is not a safe verdict** — it means the scanner could not prove
anything either way.

> Static-only results are **declared** sizes. They are useful for fast triage
> but can be forged. Use `--verify` to measure actual output, and
> `--require-verified` to reject anything that cannot be measured. Even then,
> the real boundary is a sandboxed extractor — see
> [docs/production.md](docs/production.md).

---

## Install

Requires Python 3.10+. No runtime dependencies.

```bash
pip install zipcheck

# isolated CLI install (recommended for command-line use)
pipx install zipcheck
# or
uv tool install zipcheck

# Arch Linux
yay -S zipcheck
```

From a checkout:

```bash
git clone https://github.com/spaxe-dev/zipcheck
cd zipcheck
python -m pip install .
PYTHONPATH=src python -m zipcheck file.rar   # run without installing
```

Container:

```bash
docker build -t zipcheck .
docker run --rm -v "$PWD:/data:ro" zipcheck /data/file.zip
```

PyPI and AUR releases are built from the same sdist; the Dockerfile is provided
for local or downstream container builds. See
[CONTRIBUTING.md](CONTRIBUTING.md#releasing).

---

## Usage

```bash
# human-readable
zipcheck archive.zip

# several files
zipcheck one.zip two.7z three.tar.gz

# machine-readable
zipcheck --json archive.rar > report.json

# CI: fail on suspicious or worse (default), dangerous only, or never
zipcheck --fail-on suspicious downloads/
zipcheck --fail-on dangerous downloads/
zipcheck --fail-on none archive.zip

# recurse into a directory, scanning known archive extensions
zipcheck -r ~/Downloads

# show thresholds, notes and member samples
zipcheck -v archive.7z

# production pre-flight: measure real output and fail closed
zipcheck --production --verify-limit 256MiB --timeout 30 --json upload.zip
```

Options:

| Option | Default | Meaning |
|---|---|---|
| `--json` | off | Emit a JSON report (see below) |
| `-r, --recursive` | off | Walk directories, scanning archive extensions |
| `--fail-on {none,suspicious,dangerous}` | `suspicious` | Lowest verdict that causes a non-zero exit |
| `--depth N` | `6` | Maximum nested archive depth |
| `--timeout SECONDS` | `60` | Per-file wall-clock budget (`0` disables) |
| `--no-probe` | probe on | Skip bounded decompression for bzip2/size-less formats |
| `--probe-limit SIZE` | `64MiB` | Maximum output produced by a bounded probe |
| `--verify` | off | Decompress supported content into a counting sink |
| `--verify-limit SIZE` | `512MiB` | Maximum output produced by verification |
| `--require-verified` | off | Make unverifiable files `unknown` (implies `--verify`) |
| `--production` | off | Fail-closed preset: implies `--verify --require-verified` |
| `--ratio FLOAT` | `100` | Expansion ratio considered suspicious |
| `--dangerous-ratio FLOAT` | `1000` | Expansion ratio considered dangerous |
| `--min-size SIZE` | `16MiB` | Ignore ratios below this declared output |
| `--entries N` | `10` | Member samples shown in human output |
| `--quiet` | off | One line per file |
| `--no-color` | off | Disable ANSI colors |

Sizes accept `KiB`, `MiB`, `GiB`, `TiB`, `KB`, `MB`, … or plain bytes.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | No verdict at or above `--fail-on` |
| `1` | `suspicious` found (when `--fail-on=suspicious`) |
| `2` | `dangerous` found |
| `3` | At least one file was `unknown` / unscannable |
| `4` | Invocation or I/O error |

---

## Detection rules

Findings are emitted with a code and severity. The worst finding defines the
verdict; `HIGH`/`CRITICAL` → *dangerous*, `MEDIUM` → *suspicious*.

| Code | Severity | Trigger |
|---|---|---|
| `EXTREME_EXPANSION` | HIGH / CRITICAL | Declared output ≥ 1 GiB and ratio ≥ 1000 (critical at ≥ 100 000) |
| `HIGH_EXPANSION` | MEDIUM | Declared output above `--min-size` and ratio ≥ 100 |
| `ABSOLUTE_EXPANSION` | MEDIUM / HIGH / CRITICAL | Declared output ≥ 1 GiB / 10 GiB / 1 TiB and more than 2× the file size |
| `IMPOSSIBLE_DEFLATE_RATIO` | HIGH | A DEFLATE member claims > 1032:1 |
| `STORED_SIZE_MISMATCH` | HIGH | A stored member claims to expand |
| `OVERLAPPING_ENTRIES` | HIGH | Several directory entries share one local header |
| `OVERLAPPING_DATA` | HIGH | Two members' compressed data ranges intersect |
| `INCONSISTENT_TOTALS` | MEDIUM | Sum of compressed sizes exceeds the file |
| `MANY_ENTRIES` / `ENTRY_COUNT_BOMB` | MEDIUM / HIGH | ≥ 10 000 / ≥ 100 000 members |
| `SPARSE_MEMBERS` | INFO | TAR sparse files are present (their size feeds the expansion rules) |
| `PROBE_LIMIT_EXCEEDED` | HIGH | Bounded decompression hit its cap at a ratio ≥ 1000 |
| `PROBE_HIGH_RATIO` | MEDIUM | Probe hit its cap at a ratio ≥ 100 |
| `HEADER_MISMATCH` | HIGH / MEDIUM | A local header disagrees with the central directory (HIGH for method/size) |
| `ENTRY_COUNT_MISMATCH` | HIGH / MEDIUM | The central directory contains more (HIGH) or fewer (MEDIUM) entries than the EOCD counts |
| `NESTED_BOMB` / `NESTED_SUSPICIOUS` | HIGH / MEDIUM | A nested archive has that verdict |
| `ENCRYPTED_NESTED_ARCHIVE` | MEDIUM | Encrypted members look like archives and cannot be recursed into |
| `METADATA_UNDERSTATED` | HIGH (ZIP) / MEDIUM (streams) | Real decompressed output exceeds the declared size |
| `METADATA_OVERSTATED` | MEDIUM | Declared size exceeds the real output |
| `UNDERSTATED_COMPRESSED_SIZE` | HIGH | A compressed stream continues past the size declared for it |
| `OVERSTATED_COMPRESSED_SIZE` | MEDIUM | A compressed stream ends before its declared compressed size |
| `VERIFIED_EXPANSION` | MEDIUM / HIGH / CRITICAL | Actual measured output is dangerous even though metadata hid it |
| `VERIFICATION_LIMIT` | HIGH | Verified output reached `--verify-limit` |
| `VERIFICATION_FAILED` | MEDIUM | The verifier raised an error; the result is untrusted |
| `UNVERIFIED` | MEDIUM | Verification was requested but could not cover the whole archive |
| `UNSAFE_PATH` | LOW | Absolute path or `..` in a member name |
| `UNRECOGNIZED_FORMAT` | INFO | Not an archive format zipcheck knows |

Thresholds are deliberately conservative. A legitimate archive of highly
compressible data (logs, zeros, sparse disk images, columnar data) can trip the
ratio rules — that is the point. The scanner reports *potential expansion*, not
malice. Tune the thresholds for your environment.

---

## Content verification

Static metadata is attacker-controlled. `--verify` therefore decodes supported
content into a **counting sink**: output is counted and discarded, never written
to disk, with a hard `--verify-limit` and the per-file timeout.

- If real output **exceeds** the declared size → `METADATA_UNDERSTATED` (HIGH).
- If a compressed stream **continues past** its declared compressed size →
  `UNDERSTATED_COMPRESSED_SIZE` (HIGH). This is the classic trick of declaring
  a one-byte member while shipping a large encoded stream.
- If a stream ends early → `OVERSTATED_COMPRESSED_SIZE` (MEDIUM).
- The measured bytes also feed the expansion policy (`VERIFIED_EXPANSION`).

Verification recurses into archives nested inside the file. Each nested image is
captured in memory up to 8 MiB (and 8 MiB compressed) and recursively verified,
with a shared 256 MiB nested-output budget. A nested archive that cannot be
captured or decoded marks the whole file unverified rather than clean.

When verification was requested but did not cover the whole file, an `UNVERIFIED`
(MEDIUM) finding is always added; the result is at best `suspicious`.

- `--verify` → unverifiable content is `suspicious`.
- `--require-verified` → unverifiable content is `unknown`.
- `--production` → shorthand for `--verify --require-verified`.

This measures content; it is **not** a sandbox. The capped decompression still
runs inside your process and consumes CPU and memory. Encrypted members, 7z/RAR
member data, and methods without a stdlib decoder remain unverifiable and fail
closed. The enforceable production boundary is still isolated extraction with
OS quotas — see [docs/production.md](docs/production.md).

---

## How each format is measured

### ZIP / ZIP64

The end-of-central-directory record is located by scanning the tail, ZIP64
records are followed, and every central-directory entry is parsed. Uncompressed
and compressed sizes come from the directory; member data offsets come from the
local headers. No member is decompressed at this stage.

The parser accounts for archives with prepended data (self-extracting stubs) by
adjusting offsets if the central directory does not end where the EOCD says it
should. Overlapping ranges and shared local headers are detected directly.

The EOCD entry count is treated as a claim, not a stopping condition: the
central directory is parsed to its declared end, and leftover entries yield
`ENTRY_COUNT_MISMATCH` (HIGH). Every central entry is also cross-checked against
its local header; conflicting method or size fields yield `HEADER_MISMATCH`
(HIGH), because extractors disagree about which copy is authoritative.

### TAR

Walks 512-byte headers, validates checksums, applies GNU long-name and PAX
overrides, and understands GNU sparse (`S`) plus PAX `GNU.sparse.*` members.
Sparse files are the dangerous case: a 10 KiB TAR can declare a 1 TiB file.
Normal TAR files cannot expand beyond their own size, so ratio rules only fire
when the declared size exceeds the file size (sparse/truncated cases).

### gzip

Reads the last 4 bytes (`ISIZE`) and compares with the compressed size. If
`ISIZE` is zero — empty file, or a size that wrapped at a multiple of 4 GiB — a
bounded decompression probe distinguishes the cases. Nested TAR/ZIP data is
discovered by decompressing at most 1 MiB into memory, following the gzip rule
that concatenated members form one output stream.

*Limitation:* for multi-member gzip, only the final member's `ISIZE` is read.
Verification decodes every member and compares total output with that final
`ISIZE`; a mismatch marks the file unverified.

### bzip2

bzip2 stores no uncompressed size. With probing enabled (default), zipcheck
decompresses up to 64 MiB into a counted sink (nothing is stored) and compares
output to consumed input. A 256 MiB zero file compresses to ~200 bytes and is
flagged immediately.

### xz / LZMA

xz ends with a footer pointing at an index that records every block's
uncompressed size; zipcheck parses it without decompressing. Bare `.lzma` has an
8-byte size field; when it is the "unknown" sentinel, a bounded probe runs.

*Limitation:* concatenated xz streams are not summed; only the final stream's
index is read.

### Zstandard

Parses the frame header, including the optional content-size field. If the
producer omitted it, the result is `unknown` rather than a false `clean`.

### 7-Zip

Parses the 32-byte start header, then the next header. 7-Zip often compresses
that header with LZMA/LZMA2; zipcheck decodes **only the header**, with caps on
both input (32 MiB) and output (32 MiB), then sums the folder unpack sizes. No
member data is decoded.

*Limitation:* encoded headers using BCJ/other coder chains are reported as
unknown.

### RAR 4 / RAR 5

Walks the block structure and reads the unpacked size from every file header.
RAR rarely needs any decompression for size analysis. Encrypted headers are
reported as `unknown`; encrypted archive members are noted.

---

## Nested archives and deep bombs

Classic bombs such as `42.zip` are *recursive*: the outer archive contains ZIPs
whose metadata looks innocent. The only way to catch them statically is to
follow the chain.

zipcheck inspects each member that looks like an archive (ZIP, TAR, gzip,
bzip2, xz, 7z, RAR) and recurses while:

- depth < `--depth` (default 6),
- fewer than 32 candidates per archive and 128 nested archives overall,
- total nested inspection output stays below 64 MiB,
- compressed member input stays below 8 MiB.

Without `--verify`, only a bounded prefix (up to 1 MiB) of each candidate is
decoded, so a bomb hidden below that prefix is not seen. With `--verify`, the
whole nested image is captured up to 8 MiB and passed through the same content
verification as a top-level file, recursively. Archive-like members that cannot
be captured in full are probed, reported as unverified, and fail closed.

When a nested bomb is found, scanning stops early and the parent is marked
`NESTED_BOMB` (`HIGH`). Paths use `!` to show the chain:

```
download.zip!lib0.zip!lib1.zip!...!payload.bin
```

This is enough to catch 42.zip-style chains that are not encrypted. Encrypted
bombs remain opaque; see below.

---

## Safety model

`zipcheck` is built so that a hostile archive cannot make it extract data or
allocate an attacker-controlled amount of memory.

- **No extraction.** Nothing is written to disk, and no external program
  (`unzip`, `7z`, `tar`, `rar`) is executed.
- **Random access, small reads.** Parsers seek directly to metadata. Central
  directories are capped at 64 MiB, headers at 32 MiB, names at 64 KiB and
  entries at 100 000.
- **Never trust declared sizes.** Memory is never allocated from a size field.
  Static nested inspection stops at 1 MiB of output per member and 64 MiB total;
  verification captures at most 8 MiB per nested member and shares a 256 MiB
  nested-output budget across the whole scan.
- **Global verification cap.** `--verify-limit` bounds total decoded output,
  even when metadata claims a small size.
- **LZMA decoder caps.** The xz path sets a 128 MiB decoder memory limit, so a
  malicious dictionary size cannot force a huge allocation.
- **Wall-clock limit.** 60 seconds per file by default (`--timeout`).
- **No recursion into data formats.** 7z and RAR member data is never decoded,
  so a solid archive cannot be used to burn CPU during a scan.
- **No stat-then-open race.** The path is opened and `fstat`ed on the same file
  descriptor, so a file swap between check and scan cannot change what is read.

Defense in depth still applies: parsers are software and may contain bugs. If
you handle untrusted archives routinely, scan them in a disposable container
with no network and read-only mounts. A `Dockerfile` is included; see
[Install](#install) for the commands.

Do not rely on any scanner — including this one — as the only boundary between
an untrusted archive and your data. Extract into a sandbox with quotas.

---

## Validation against real bombs

The test suite runs on Windows, macOS and Linux; CI covers Python 3.10–3.14. In
addition, the scanner was exercised against real bombs generated in a
disposable remote sandbox (the bombs were never extracted, and the host was not
used):

| Sample | On disk | Declared output | Verdict |
|---|---:|---:|---|
| ZIP, 1 GiB of zeros | 1.0 MiB | 1.00 GiB | dangerous |
| gzip, 1 GiB of zeros | 1.0 MiB | 1.00 GiB | dangerous |
| bzip2, 256 MiB of zeros | 208 B | ≥ 64 MiB (probe cap) | dangerous |
| xz, 256 MiB of zeros | 38 KiB | 256 MiB | suspicious |
| nested ZIP (bomb inside ZIP) | 2.0 KiB | 1.00 GiB | dangerous |
| forged ZIP sizes (1 B declared, 1 GiB real) | 1.0 MiB | 1 B (forged) | clean → dangerous |
| forged bomb in nested ZIP | 1.0 MiB | hidden | clean → dangerous |
| forged bomb in gzip, xz, bzip2 or split gzip | 323 B – 2.0 KiB | hidden | clean → dangerous |
| forged bomb in ZIP-LZMA member | 509 B | hidden | clean → dangerous |
| ZIP entries hidden from the EOCD count | 196 B | 2 B | dangerous |
| ZIP local/central header mismatch | 113 B | 5 B | dangerous |
| six-level nested ZIP | 917 B | 1.00 GiB | dangerous |
| sparse TAR (1 TiB hole) | 10 KiB | 1.00 TiB | dangerous |
| gzip-compressed sparse TAR | 142 B | 1.00 TiB (inner TAR) | dangerous |
| non-recursive overlap ZIP | 4.2 KiB | 8 KiB | dangerous |
| RAR 5, 256 MiB of zeros | 11 KiB | 256 MiB | suspicious |
| real `42.zip` (AES-encrypted) | 41.8 KiB | opaque | suspicious |
| 7-Zip encoded header, 50 files | 729 B | 790 B | clean (correct) |
| real RAR 4 archive | 336 B | 48 B | clean (correct) |

The forged-metadata rows are deliberately clean under static analysis; production
mode (`--verify --require-verified`) decompresses the content and rejects them.
In the same sandbox, `--production` exit codes were `0` for a clean archive, `2`
for a forged bomb, and `3` for an archive using a method the verifier cannot
decode. An xz file declaring 256 MiB honestly is verified byte-for-byte and
reported `suspicious`, not `unknown`.

A mixed corpus of 17 files — including six levels of nested ZIPs, a
gzip-compressed sparse TAR, and the real 42.zip — scanned in ~0.19 seconds with
~146 MiB peak RSS (the xz decoder's 64 MiB dictionary dominates). Reproduce
with `tools/generate_samples.py` and `tools/benchmark.py` inside a VM/container.

---

## Limitations and honest caveats

- **Encrypted archives are opaque.** zipcheck cannot decrypt AES or password-
  protected members. Encrypted members named like archives produce a
  `suspicious` finding ("cannot rule out a nested bomb"), not a proof. The real
  42.zip is exactly this case.
- **Headers can lie.** A static scan can be fooled by understated sizes, entries
  hidden from the EOCD count, or conflicting local/central headers. zipcheck
  flags those specific tricks, and `--verify` measures supported content, but
  formats the verifier cannot decode (7z, RAR, encrypted members) remain opaque
  and fail closed.
- **Nested verification has a capture cap.** Archive-like members whose captured
  image or compressed size exceeds 8 MiB are probed for archive magic and marked
  unverified, not decoded in full. This fails closed, but may reject large
  legitimate nested archives; raise the internal `Limits` if that matters.
- **Unknown formats are not scanned.** ISO, CAB, ARJ, CPIO, `.parquet`, `.gz`
  variants without magic, disk images, etc. are reported as `unknown`.
- **Multi-member gzip:** only the last member's `ISIZE` is used.
- **bzip2 larger than `--probe-limit`:** the probe stops at the cap, so the
  result is `unknown` unless the measured ratio is already dangerous; raise the
  limit for a complete measurement.
- **Concatenated xz:** only the last stream's index is used.
- **Zstandard without a content-size field:** `unknown` (no decompression).
- **7z encoded headers** with coders other than LZMA/LZMA2: `unknown`.
- **RAR volumes / nested RAR / nested 7z:** member data is not decoded, so
  nested archives inside them are not followed.
- **Depth and budget limits** can be evaded by a sufficiently deep or wide
  nesting bomb. Raise `--depth` and the internal limits if you need more.
- **Legitimate high-ratio data** triggers findings. That is intentional:
  "dangerous" means "extraction may exhaust resources", not "this file is
  malicious".
- **TAR with normal (non-sparse) huge files** is not a compression bomb; if the
  file is genuinely 20 GiB, the archive is 20 GiB. Absolute rules only fire when
  declared output is more than twice the on-disk size.

If you find a bypass, please open an issue with a minimal, non-destructive
sample or a hex description — see [SECURITY.md](SECURITY.md).

---

## JSON output

```json
{
  "tool": "zipcheck",
  "version": "0.1.0",
  "elapsed_ms": 3.1,
  "summary": {"clean": 0, "suspicious": 0, "dangerous": 1, "unknown": 0},
  "results": [
    {
      "path": "bomb.zip",
      "size": 1043754,
      "format": "zip",
      "detail": "ZIP, 1 parsed entries",
      "declared_uncompressed": 1073741824,
      "declared_compressed": 1043746,
      "ratio": 1029.1,
      "entry_count": 1,
      "verdict": "dangerous",
      "severity": "high",
      "severity_value": 3,
      "complete": true,
      "error": null,
      "verified": true,
      "verified_uncompressed": 1073741824,
      "verification_capped": false,
      "verification_detail": "verified 1073741824 bytes across 1 member(s)",
      "nested_unverified": false,
      "notes": [],
      "entries": [
        {"name": "zeros.bin", "usize": 1073741824, "csize": 1043746,
         "ratio": 1029.1, "method": "deflate", "is_dir": false,
         "encrypted": false, "sparse": false}
      ],
      "findings": [
        {"code": "EXTREME_EXPANSION", "severity": "high", "severity_value": 3,
         "title": "Declared expansion is unusually large",
         "detail": "...", "evidence": {}}
      ],
      "nested": []
    }
  ]
}
```

`entries` is truncated to a sample; `entries_truncated` tells you whether more
exist. `nested` contains child reports recursively. The schema is version 1 and
will remain backward compatible within 0.x.

---

## Development

```bash
python -m pip install -e .[dev]
python -m pytest
ruff check src tests tools
```

Layout:

```
src/zipcheck/
  engine.py           # orchestration, policy, nested inspection
  verify.py           # bounded content verification (counting sink)
  model.py            # facts/findings/results
  limits.py           # caps and thresholds
  detect.py           # magic/extension routing
  reader.py           # bounds-checked binary helpers
  formats/zipfmt.py
  formats/tarfmt.py
  formats/gzipfmt.py
  formats/bzip2fmt.py
  formats/xzfmt.py
  formats/zstdfmt.py
  formats/sevenzipfmt.py
  formats/rarfmt.py
tests/                # crafted metadata bombs + real-format tests
tools/generate_samples.py
tools/benchmark.py
docs/metadata-map.md
```

The tests generate archives with declared sizes only (tiny on disk). To test
against real expansion bombs, use `tools/generate_samples.py` in a disposable
VM/container:

```bash
python tools/generate_samples.py --output /tmp/bombs \
    --size 1073741824 --small-size 268435456 --rar /path/to/rar
PYTHONPATH=src python tools/benchmark.py /tmp/bombs/*
```

**Never extract the generated files on a machine you care about.**

---

## License

MIT. See [LICENSE](LICENSE).
