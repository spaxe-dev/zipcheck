"""Format identification.

Magic bytes identify the *container format*, not whether it is a bomb.  There
is no universal "zip bomb signature": every bomb is a structurally valid
archive whose declared expansion is enormous.  This module therefore only
routes a file to the right metadata parser.  Extensions are used as a fallback
for formats with weak or optional magic (notably tar and bare LZMA).
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
RAR4_MAGIC = b"Rar!\x1a\x07\x00"
RAR5_MAGIC = b"Rar!\x1a\x07\x01\x00"
SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
GZIP_MAGIC = b"\x1f\x8b"
BZIP2_MAGIC = b"BZh"
XZ_MAGIC = b"\xfd7zXZ\x00"
LZMA_MAGIC = b"\x5d\x00\x00"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
ZSTD_SKIPPABLE_MASK = 0xFFFFFFF0
ZSTD_SKIPPABLE_BASE = 0x184D2A50

ZIP_EXTENSIONS = {
    ".zip",
    ".zipx",
    ".jar",
    ".war",
    ".apk",
    ".epub",
    ".whl",
    ".xpi",
    ".crx",
    ".cbz",
    ".docx",
    ".xlsx",
    ".pptx",
    ".odt",
    ".ods",
    ".odp",
}
TAR_EXTENSIONS = {".tar", ".tarx", ".pax", ".cpio"}
SEVENZIP_EXTENSIONS = {".7z"}
RAR_EXTENSIONS = {".rar", ".rev"}
GZIP_EXTENSIONS = {".gz", ".gzip", ".tgz", ".z"}
BZIP2_EXTENSIONS = {".bz2", ".bzip2", ".tbz2", ".tbz"}
XZ_EXTENSIONS = {".xz", ".txz"}
LZMA_EXTENSIONS = {".lzma"}
ZSTD_EXTENSIONS = {".zst", ".zstd", ".tzst"}

ARCHIVE_EXTENSIONS = (
    ZIP_EXTENSIONS
    | TAR_EXTENSIONS
    | SEVENZIP_EXTENSIONS
    | RAR_EXTENSIONS
    | GZIP_EXTENSIONS
    | BZIP2_EXTENSIONS
    | XZ_EXTENSIONS
    | LZMA_EXTENSIONS
    | ZSTD_EXTENSIONS
)


def _extension(path: str) -> str:
    base = os.path.basename(path).lower()
    # .tar.gz, .tar.bz2, ... -> outer format is what we can inspect first.
    if base.endswith(".tar.gz"):
        return ".gz"
    if base.endswith(".tar.bz2"):
        return ".bz2"
    if base.endswith(".tar.xz"):
        return ".xz"
    if base.endswith(".tar.zst"):
        return ".zst"
    return os.path.splitext(base)[1]


def extension_suggests_archive(path: str) -> bool:
    return _extension(path) in ARCHIVE_EXTENSIONS


def sniff(
    head: bytes, path: str = "", allow_extension: bool = True
) -> Tuple[Optional[str], str]:
    """Return ``(format_key, why)`` or ``(None, "")``.

    ``head`` needs only the first ~512 bytes plus (for ZIP) the extension.
    ``allow_extension=False`` is used for readable archive members: a member
    named ``notes.zip`` that contains text is data, not a nested archive.  The
    exception is tar and bare LZMA, whose magic is weak or optional.
    """

    ext = _extension(path)

    if head.startswith(ZIP_MAGICS):
        return "zip", "ZIP local header magic"
    if head.startswith(RAR5_MAGIC):
        return "rar5", "RAR 5 signature"
    if head.startswith(RAR4_MAGIC):
        return "rar4", "RAR 4 signature"
    if head.startswith(SEVENZIP_MAGIC):
        return "7z", "7-Zip signature"
    if head.startswith(GZIP_MAGIC) and len(head) >= 3 and head[2] == 0x08:
        return "gzip", "gzip magic"
    if head.startswith(BZIP2_MAGIC) and len(head) >= 4 and 0x31 <= head[3] <= 0x39:
        return "bzip2", "bzip2 magic"
    if head.startswith(XZ_MAGIC):
        return "xz", "xz magic"
    if head.startswith(ZSTD_MAGIC):
        return "zstd", "Zstandard frame magic"
    if len(head) >= 512 and head[257:262] == b"ustar":
        return "tar", "ustar header at offset 257"

    if allow_extension:
        # Fallbacks for weak/optional magic.
        if ext in ZIP_EXTENSIONS:
            return "zip", "ZIP extension"
        if ext in TAR_EXTENSIONS:
            return "tar", "tar extension"
        if ext in SEVENZIP_EXTENSIONS:
            return "7z", "7-Zip extension"
        if ext in RAR_EXTENSIONS:
            return "rar5" if head.startswith(RAR5_MAGIC) else "rar4", "RAR extension"
        if ext in GZIP_EXTENSIONS:
            return "gzip", "gzip extension"
        if ext in BZIP2_EXTENSIONS:
            return "bzip2", "bzip2 extension"
        if ext in XZ_EXTENSIONS:
            return "xz", "xz extension"
        if ext in LZMA_EXTENSIONS:
            return "lzma", "LZMA extension"
        if ext in ZSTD_EXTENSIONS:
            return "zstd", "Zstandard extension"
    else:
        # Self-extracting ZIPs carry a stub before the signature.
        if ext in ZIP_EXTENSIONS and any(sig in head for sig in ZIP_MAGICS):
            return "zip", "ZIP signature inside member"
        if ext in TAR_EXTENSIONS:
            return "tar", "tar extension"
        if ext in LZMA_EXTENSIONS:
            return "lzma", "LZMA extension"

    if len(head) >= 3 and head.startswith(LZMA_MAGIC):
        return "lzma", "LZMA-alone magic"
    return None, ""


def looks_like_archive(
    head: bytes, path: str = "", allow_extension: bool = True
) -> bool:
    fmt, _ = sniff(head, path, allow_extension)
    return fmt is not None
