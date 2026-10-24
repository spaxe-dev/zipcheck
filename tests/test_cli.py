from __future__ import annotations

import argparse
import json

import pytest

from zipcheck.cli import _parse_size, main

from .helpers import (
    build_encrypted_archive_member_zip,
    build_forged_bomb_zip,
    build_single_entry_zip,
    make_zip,
    make_zip_bomb,
)


def test_json_output_and_exit_code(tmp_path, capsys):
    path = build_single_entry_zip(tmp_path / "bomb.zip", usize=3 * 1024**3)
    code = main(["--json", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["results"][0]["verdict"] == "dangerous"
    assert payload["results"][0]["findings"]
    assert payload["summary"]["dangerous"] == 1


def test_clean_exit_code(tmp_path, capsys):
    path = make_zip(tmp_path / "clean.zip", {"a.txt": b"a"})
    code = main(["--json", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["results"][0]["verdict"] == "clean"


def test_fail_on_none(tmp_path, capsys):
    path = build_single_entry_zip(tmp_path / "bomb.zip", usize=3 * 1024**3)
    code = main(["--json", "--fail-on", "none", str(path)])
    capsys.readouterr()
    assert code == 0


def test_unknown_exit_code(tmp_path, capsys):
    path = tmp_path / "file.bin"
    path.write_bytes(b"not an archive at all")
    code = main(["--json", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 3
    assert payload["results"][0]["verdict"] == "unknown"


def test_quiet_output(tmp_path, capsys):
    path = make_zip(tmp_path / "clean.zip", {"a.txt": b"a"})
    code = main(["--quiet", str(path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "CLEAN" in out


def test_verify_cli_flags(tmp_path, capsys):
    path = make_zip(tmp_path / "clean.zip", {"a.txt": b"hello"})
    code = main(["--json", "--verify", "--require-verified", str(path)])
    payload = json.loads(capsys.readouterr().out)
    result = payload["results"][0]
    assert code == 0
    assert result["verified"] is True
    assert result["verified_uncompressed"] == 5


def test_production_preset_accepts_clean_archive(tmp_path, capsys):
    path = make_zip(tmp_path / "clean.zip", {"a.txt": b"hello"})
    code = main(["--json", "--production", str(path)])
    payload = json.loads(capsys.readouterr().out)
    result = payload["results"][0]
    assert code == 0
    assert result["verdict"] == "clean"
    assert result["verified"] is True


def test_production_preset_rejects_forged_bomb(tmp_path, capsys):
    path = build_forged_bomb_zip(tmp_path / "forged.zip")
    code = main(["--json", "--production", str(path)])
    payload = json.loads(capsys.readouterr().out)
    result = payload["results"][0]
    assert code == 2
    assert result["verdict"] == "dangerous"
    assert result["verified"] is False


def test_production_preset_rejects_unverifiable_archive(tmp_path, capsys):
    path = build_encrypted_archive_member_zip(tmp_path / "encrypted.zip")
    code = main(["--json", "--production", str(path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 3
    assert payload["results"][0]["verdict"] == "unknown"


def test_parse_size_accepts_units_and_rejects_garbage():
    assert _parse_size("1KiB") == 1024
    assert _parse_size("1.5MiB") == int(1.5 * 1024**2)
    assert _parse_size("2_048") == 2048
    assert _parse_size("7") == 7
    for value in ("", "many", "12potato"):
        with pytest.raises(argparse.ArgumentTypeError):
            _parse_size(value)


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "zipcheck" in capsys.readouterr().out


def test_directory_requires_recursive(tmp_path, capsys):
    code = main([str(tmp_path)])
    assert code == 4
    assert "use --recursive" in capsys.readouterr().err


def test_empty_directory_is_an_error(tmp_path, capsys):
    code = main(["--recursive", str(tmp_path)])
    assert code == 4
    assert "no archive files found" in capsys.readouterr().err


def test_recursive_scan_skips_non_archives(tmp_path, capsys):
    make_zip(tmp_path / "a.zip", {"a.txt": b"a"})
    (tmp_path / "notes.txt").write_text("not an archive")
    code = main(["--json", "-r", str(tmp_path)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert len(payload["results"]) == 1
    assert payload["results"][0]["path"].endswith("a.zip")


def test_missing_file_is_unknown(tmp_path, capsys):
    code = main(["--json", str(tmp_path / "missing.zip")])
    payload = json.loads(capsys.readouterr().out)
    assert code == 3
    assert payload["results"][0]["verdict"] == "unknown"
    assert payload["results"][0]["error"]


def test_human_summary_and_verbose_members(tmp_path, capsys):
    clean = make_zip(tmp_path / "clean.zip", {"a.txt": b"a"})
    assert main([str(clean)]) == 0
    out = capsys.readouterr().out
    assert "CLEAN" in out
    assert "file(s)" in out
    assert "use -v" in out

    bomb = build_single_entry_zip(tmp_path / "bomb.zip", usize=3 * 1024**3)
    assert main(["-v", str(bomb)]) == 2
    out = capsys.readouterr().out
    assert "EXTREME_EXPANSION" in out
    assert "members (sample)" in out


def test_verification_state_is_printed(tmp_path, capsys):
    clean = make_zip(tmp_path / "clean.zip", {"a.txt": b"hello"})
    assert main(["--verify", str(clean)]) == 0
    assert "verify:    verified" in capsys.readouterr().out

    bomb = make_zip_bomb(tmp_path / "bomb.zip", size=32 * 1024 * 1024)
    main(["--verify", "--verify-limit", "1MiB", str(bomb)])
    assert "cap reached" in capsys.readouterr().out


def test_fail_on_dangerous_ignores_suspicious(tmp_path, capsys):
    path = make_zip_bomb(tmp_path / "bomb.zip", size=64 * 1024 * 1024)
    assert main(["--json", str(path)]) == 1
    assert main(["--json", "--fail-on", "dangerous", str(path)]) == 0
    capsys.readouterr()


def test_nested_children_are_rendered(tmp_path, capsys):
    inner = make_zip(tmp_path / "inner.zip", {"a.txt": b"a"})
    outer = make_zip(
        tmp_path / "outer.zip",
        {"one.zip": inner.read_bytes(), "two.zip": inner.read_bytes()},
        method=0,
    )
    code = main([str(outer)])
    out = capsys.readouterr().out
    assert code == 0
    assert "nested:" in out


def test_internal_error_returns_four(tmp_path, capsys, monkeypatch):
    def boom(path, limits):
        raise RuntimeError("boom")

    monkeypatch.setattr("zipcheck.cli.scan_file", boom)
    code = main(["--json", str(tmp_path / "anything.zip")])
    payload = json.loads(capsys.readouterr().out)
    assert code == 4
    assert "internal error" in payload["results"][0]["error"]
