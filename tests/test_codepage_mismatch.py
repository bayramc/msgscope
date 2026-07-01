"""CODEPAGE_MISMATCH: declared codepage vs actual body bytes."""

from __future__ import annotations

import struct

from conftest import ids
from fixtures.builders import good_message
from msgscope import properties as P


def test_unicode_body_odd_length(analyze):
    m = good_message()
    m.set_raw(P.PidTagBodyW, struct.pack("<I", 5) + b"\x00" * 4, substg_data=b"ABCDE")
    report = analyze(m.build_bytes())
    assert ids(report) == {"CODEPAGE_MISMATCH"}
    assert any("utf-16" in f.title.lower() for f in report.findings)


def test_ansi_body_invalid_for_utf8_codepage(analyze):
    m = good_message()
    m.set(P.PidTagInternetCodepage, 65001)  # UTF-8
    m.set_raw(P.PidTagBodyA, struct.pack("<I", 2) + b"\x00" * 4, substg_data=b"\xff\xfe")
    report = analyze(m.build_bytes())
    assert ids(report) == {"CODEPAGE_MISMATCH"}
    assert any("decode" in f.title.lower() for f in report.findings)


def test_unknown_codepage(analyze):
    m = good_message()
    m.set(P.PidTagInternetCodepage, 12345)  # not a real codepage
    report = analyze(m.build_bytes())
    assert ids(report) == {"CODEPAGE_MISMATCH"}
    assert any("known codepage" in f.title.lower() for f in report.findings)


def test_valid_body_not_flagged(analyze):
    m = good_message()  # cp1252 + valid unicode body
    report = analyze(m.build_bytes(), select={"CODEPAGE_MISMATCH"})
    assert report.findings == []
