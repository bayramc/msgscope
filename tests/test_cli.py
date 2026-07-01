"""End-to-end CLI behaviour: formats, exit codes, check selection."""

from __future__ import annotations

import json

from fixtures.builders import good_message, good_message_bytes
from msgscope.cli import main


def _orphan_bytes():
    m = good_message()
    m.add_stream("__substg1.0_80050102", b"orphan bytes")
    return m.build_bytes()


def test_clean_file_exits_zero(tmp_path, capsys):
    path = tmp_path / "good.msg"
    path.write_bytes(good_message_bytes())
    rc = main(["inspect", str(path), "--reproducible"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "No indicators found" in out


def test_json_output_is_valid(tmp_path, capsys):
    path = tmp_path / "orphan.msg"
    path.write_bytes(_orphan_bytes())
    rc = main(["inspect", str(path), "--format", "json", "--reproducible"])
    doc = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert doc["findings"][0]["id"] == "ORPHAN_SUBSTG"
    assert "verdict" not in doc


def test_fail_on_high_returns_10(tmp_path, capsys):
    path = tmp_path / "orphan.msg"
    path.write_bytes(_orphan_bytes())
    rc = main(["inspect", str(path), "--fail-on", "high", "--reproducible"])
    capsys.readouterr()
    assert rc == 10


def test_fail_on_high_ignores_low_only(tmp_path, capsys):
    from msgscope import properties as P

    m = good_message()
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | 0x40000000)  # only a low finding
    path = tmp_path / "low.msg"
    path.write_bytes(m.build_bytes())
    rc = main(["inspect", str(path), "--fail-on", "high", "--reproducible"])
    capsys.readouterr()
    assert rc == 0


def test_missing_file_returns_3(tmp_path, capsys):
    rc = main(["inspect", str(tmp_path / "nope.msg"), "--reproducible"])
    capsys.readouterr()
    assert rc == 3


def test_not_a_cfb_returns_3(tmp_path, capsys):
    path = tmp_path / "plain.msg"
    path.write_bytes(b"this is not a compound file at all")
    rc = main(["inspect", str(path), "--reproducible"])
    capsys.readouterr()
    assert rc == 3


def test_list_checks(capsys):
    rc = main(["inspect", "--list-checks"])
    out = capsys.readouterr().out
    assert rc == 0
    for cid in ("ORPHAN_SUBSTG", "HEADER_COUNTS", "CODEPAGE_MISMATCH"):
        assert cid in out


def test_output_to_file(tmp_path):
    path = tmp_path / "orphan.msg"
    path.write_bytes(_orphan_bytes())
    out_path = tmp_path / "report.json"
    rc = main(
        ["inspect", str(path), "--format", "json", "--output", str(out_path), "--reproducible"]
    )
    assert rc == 0
    doc = json.loads(out_path.read_text())
    assert doc["findings"][0]["id"] == "ORPHAN_SUBSTG"
