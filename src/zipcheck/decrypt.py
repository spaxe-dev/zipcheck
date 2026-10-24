"""Bounded decryption of encrypted ZIP members.

ZIP encryption leaves names, sizes and methods in the central directory, so
static metadata checks never need this module.  It is used only when a password
is available and the engine wants to inspect or verify encrypted member data.

The optional ``pyzipper`` dependency provides WinZip AES support.  Legacy
ZipCrypto archives work through the standard library.  Every read is bounded by
the caller's byte cap and the scan deadline; nothing is written to disk.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from typing import Any, BinaryIO, Optional, Sequence, Tuple

from .model import EntryInfo
from .reader import Deadline, ScanTimeout

try:
    import pyzipper  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - depends on the optional extra
    pyzipper = None

CHUNK = 64 * 1024
DECRYPTABLE_METHODS = frozenset({"aes", "stored", "deflate", "bzip2", "lzma"})


class DecryptionError(Exception):
    """Base class for encrypted-member failures."""


class DecryptionUnavailable(DecryptionError):
    """No available backend can decode this member."""


class DecryptionFailed(DecryptionError):
    """The password was rejected or the encrypted payload is unusable."""


@dataclass
class Counted:
    total: int
    eof: bool
    error: Optional[str]
    capped: bool


class ZipDecryptor:
    """Reads encrypted members from one ZIP central directory."""

    def __init__(
        self, archive: Any, entries: Sequence[EntryInfo], password: bytes
    ) -> None:
        self._archive = archive
        self._password = password
        self._infos = archive.infolist()
        self._entries = entries

    def close(self) -> None:
        self._archive.close()

    def _info(self, index: int, entry: EntryInfo) -> Any:
        infos = self._infos
        if index < len(infos):
            candidate = infos[index]
            if (
                candidate.filename == entry.name
                and bool(candidate.flag_bits & 1) == entry.encrypted
            ):
                return candidate
        for candidate in infos:
            if (
                candidate.filename == entry.name
                and bool(candidate.flag_bits & 1) == entry.encrypted
            ):
                return candidate
        return None

    def read_image(
        self, index: int, entry: EntryInfo, cap: int, deadline: Deadline
    ) -> Tuple[bytes, bool]:
        """Read at most ``cap`` decompressed bytes of one member.

        ``complete`` is true only when the member ended within the cap and the
        stream reached EOF, so a truncated capture can be treated as unknown.
        """

        info = self._info(index, entry)
        if info is None:
            raise DecryptionFailed(
                "member is not present in the ZIP central directory"
            )
        expected = int(info.file_size)
        out = bytearray()
        eof = False
        try:
            with self._archive.open(
                info, "r", pwd=self._password if info.flag_bits & 1 else None
            ) as stream:
                while len(out) < cap:
                    deadline.check()
                    chunk = stream.read(min(CHUNK, cap - len(out)))
                    if not chunk:
                        eof = True
                        break
                    out.extend(chunk)
        except (ScanTimeout, MemoryError):
            raise
        except Exception as exc:
            raise DecryptionFailed(str(exc)) from exc
        return bytes(out), eof and len(out) == expected

    def count_member(
        self, index: int, entry: EntryInfo, budget: int, deadline: Deadline
    ) -> Counted:
        """Count decompressed bytes without storing them."""

        info = self._info(index, entry)
        if info is None:
            return Counted(0, False, "member is not present in the ZIP directory", False)
        total = 0
        eof = False
        try:
            with self._archive.open(
                info, "r", pwd=self._password if info.flag_bits & 1 else None
            ) as stream:
                while total < budget:
                    deadline.check()
                    chunk = stream.read(min(CHUNK, budget - total))
                    if not chunk:
                        eof = True
                        break
                    total += len(chunk)
        except (ScanTimeout, MemoryError):
            raise
        except Exception as exc:
            return Counted(total, False, str(exc), False)
        return Counted(total, eof, None, total >= budget)


def open_zip_decryptor(
    fp: BinaryIO, entries: Sequence[EntryInfo], password: bytes
) -> ZipDecryptor:
    """Open ``fp`` for password-based member reads.

    Raises ``DecryptionUnavailable`` when an AES member is present but the
    optional backend is not installed.
    """

    encrypted = [entry for entry in entries if entry.encrypted]
    if not encrypted:
        raise DecryptionFailed("archive has no encrypted members")
    needs_aes = any(entry.method == "aes" for entry in encrypted)
    if needs_aes and pyzipper is None:
        raise DecryptionUnavailable(
            "AES-encrypted ZIP support requires the optional 'pyzipper' "
            "package; install 'zipcheck[aes]'"
        )
    try:
        archive: Any = (
            pyzipper.AESZipFile(fp, "r")
            if pyzipper is not None
            else zipfile.ZipFile(fp, "r")
        )
    except Exception as exc:
        raise DecryptionFailed(f"cannot read ZIP directory: {exc}") from exc
    return ZipDecryptor(archive, entries, password)
