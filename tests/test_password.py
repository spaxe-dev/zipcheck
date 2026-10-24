from __future__ import annotations

import json

import pytest

from zipcheck import Limits, scan_file
from zipcheck.cli import main
from zipcheck.decrypt import DecryptionFailed, open_zip_decryptor

from .helpers import (
    build_encrypted_archive_member_zip,
    build_single_entry_zip,
    make_encrypted_zip,
    make_zip,
)

try:
    import pyzipper  # noqa: F401
except ImportError:  # pragma: no cover - base install without the extra
    pyzipper = None

pytestmark = pytest.mark.skipif(
    pyzipper is None, reason="pyzipper is not installed"
)

PASSWORD = b"correct horse"


def _encrypted_bomb(tmp_path):
    inner = build_single_entry_zip(tmp_path / "inner.zip", usize=3 * 1024**3)
    return make_encrypted_zip(
        tmp_path / "outer.zip", {"inner.zip": inner.read_bytes()}, PASSWORD
    )


def test_password_reveals_nested_bomb(tmp_path):
    outer = _encrypted_bomb(tmp_path)
    result = scan_file(str(outer), Limits(password=PASSWORD))
    assert result.verdict == "dangerous"
    assert any(child.verdict == "dangerous" for child in result.nested)
    codes = {finding.code for finding in result.all_findings()}
    assert "EXTREME_EXPANSION" in codes


def test_without_password_stays_unknown(tmp_path):
    outer = _encrypted_bomb(tmp_path)
    result = scan_file(str(outer))
    assert result.verdict == "unknown"


def test_wrong_password_stays_unknown(tmp_path):
    outer = _encrypted_bomb(tmp_path)
    result = scan_file(str(outer), Limits(password=b"wrong"))
    assert result.verdict == "unknown"
    assert any("decryption failed" in note for note in result.notes)


def test_verify_counts_decrypted_members(tmp_path):
    archive = make_encrypted_zip(
        tmp_path / "clean.zip", {"a.txt": b"hello"}, PASSWORD
    )
    result = scan_file(str(archive), Limits(password=PASSWORD, verify=True))
    assert result.verified is True
    assert result.verified_uncompressed == 5


def test_production_rejects_wrong_password(tmp_path):
    archive = make_encrypted_zip(
        tmp_path / "clean.zip", {"a.txt": b"hello"}, PASSWORD
    )
    result = scan_file(
        str(archive),
        Limits(password=b"wrong", verify=True, require_verified=True),
    )
    assert result.verified is False
    assert result.verdict == "unknown"
    assert any(finding.code == "UNVERIFIED" for finding in result.findings)


def test_missing_aes_backend_fails_closed(tmp_path, monkeypatch):
    archive = make_encrypted_zip(
        tmp_path / "aes.zip", {"a.txt": b"hello"}, PASSWORD
    )
    monkeypatch.setattr("zipcheck.decrypt.pyzipper", None)
    result = scan_file(str(archive), Limits(password=PASSWORD))
    assert result.verdict == "unknown"
    assert any("zipcheck[aes]" in note for note in result.notes)


def test_stdlib_fallback_handles_unreadable_zipcrypto(tmp_path, monkeypatch):
    archive = build_encrypted_archive_member_zip(tmp_path / "legacy.zip")
    monkeypatch.setattr("zipcheck.decrypt.pyzipper", None)
    result = scan_file(str(archive), Limits(password=b"anything"))
    assert result.verdict == "unknown"
    assert any("decryption failed" in note for note in result.notes)


def test_unsupported_encrypted_method_fails_closed(tmp_path, monkeypatch):
    archive = make_encrypted_zip(
        tmp_path / "clean.zip", {"a.txt": b"hello"}, PASSWORD
    )
    monkeypatch.setattr("zipcheck.engine.DECRYPTABLE_METHODS", frozenset())
    result = scan_file(str(archive), Limits(password=PASSWORD))
    assert result.verdict == "unknown"


def test_password_is_hidden_from_limits_repr_and_results(tmp_path):
    limits = Limits(password=b"hunter2")
    assert "hunter2" not in repr(limits)
    assert limits == Limits()

    outer = _encrypted_bomb(tmp_path)
    result = scan_file(str(outer), Limits(password=b"wrong-hunter2"))
    payload = json.dumps(result.to_dict())
    assert "wrong-hunter2" not in payload


def test_cli_password_flag_detects_bomb(tmp_path, capsys):
    outer = _encrypted_bomb(tmp_path)
    code = main(["--json", "--password", PASSWORD.decode(), str(outer)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["results"][0]["verdict"] == "dangerous"
    assert PASSWORD.decode() not in json.dumps(payload)


def test_cli_password_file(tmp_path, capsys):
    outer = _encrypted_bomb(tmp_path)
    password_file = tmp_path / "password.txt"
    password_file.write_bytes(PASSWORD + b"\n")
    code = main(
        ["--json", "--password-file", str(password_file), str(outer)]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["results"][0]["verdict"] == "dangerous"


def test_cli_ask_password(tmp_path, capsys, monkeypatch):
    outer = _encrypted_bomb(tmp_path)
    monkeypatch.setattr("zipcheck.cli.getpass.getpass", lambda prompt: PASSWORD.decode())
    code = main(["--json", "--ask-password", str(outer)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["results"][0]["verdict"] == "dangerous"


def test_cli_empty_password_file_is_an_error(tmp_path, capsys):
    outer = _encrypted_bomb(tmp_path)
    password_file = tmp_path / "empty.txt"
    password_file.write_bytes(b"\n")
    code = main(["--password-file", str(password_file), str(outer)])
    assert code == 4
    assert "password file is empty" in capsys.readouterr().err


def test_encrypted_member_without_archive_name_is_inspected(tmp_path):
    inner = build_single_entry_zip(tmp_path / "inner.zip", usize=3 * 1024**3)
    outer = make_encrypted_zip(
        tmp_path / "outer.zip", {"payload.dat": inner.read_bytes()}, PASSWORD
    )
    result = scan_file(str(outer), Limits(password=PASSWORD))
    assert result.verdict == "dangerous"


def test_password_cap_hit_fails_closed(tmp_path):
    inner = make_zip(tmp_path / "inner.zip", {"a.txt": b"a"}).read_bytes()
    outer = make_encrypted_zip(
        tmp_path / "outer.zip", {"one.dat": inner, "two.dat": inner}, PASSWORD
    )
    result = scan_file(
        str(outer), Limits(password=PASSWORD, max_nested_candidates=1)
    )
    assert result.verdict == "unknown"
    assert any(
        finding.code == "INSPECTION_INCOMPLETE"
        for finding in result.findings
    )


def test_clean_encrypted_archive_with_password(tmp_path, capsys):
    encrypted = make_encrypted_zip(
        tmp_path / "clean.zip", {"a.txt": b"hello"}, PASSWORD
    )
    code = main(["--json", "--password", PASSWORD.decode(), str(encrypted)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["results"][0]["verdict"] == "clean"


def test_open_decryptor_rejects_unencrypted_archive(tmp_path):
    archive = make_zip(tmp_path / "plain.zip", {"a.txt": b"a"})
    with open(str(archive), "rb") as fp:
        with pytest.raises(DecryptionFailed):
            open_zip_decryptor(fp, [], b"password")
