from __future__ import annotations

import json

from zipcheck.cli import main

from .helpers import build_single_entry_zip, make_zip


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
