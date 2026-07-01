"""ORPHAN_SUBSTG fires on orphan / dangling streams and nowhere else."""

from __future__ import annotations

import struct

from conftest import ids
from fixtures.builders import good_message
from msgscope import properties as P


def test_orphan_stream_detected(analyze):
    m = good_message()
    m.add_stream("__substg1.0_80050102", b"orphan bytes not in the property table")
    report = analyze(m.build_bytes())
    assert ids(report) == {"ORPHAN_SUBSTG"}
    f = report.findings[0]
    assert f.evidence.stream == "__substg1.0_80050102"
    assert f.evidence.byte_offset is not None
    assert f.severity.value == "high"


def test_dangling_reference_detected(analyze):
    m = good_message()
    # PidTagSubject (Unicode) entry declares 10 bytes but no stream is written.
    m.set_raw(0x0037001F, struct.pack("<I", 10) + b"\x00" * 4, substg_data=None)
    report = analyze(m.build_bytes())
    assert ids(report) == {"ORPHAN_SUBSTG"}
    assert "missing" in report.findings[0].title.lower()


def test_zero_length_external_not_flagged_dangling(analyze):
    m = good_message()
    # A zero-length external value legitimately may omit its stream.
    m.set_raw(0x0037001F, struct.pack("<I", 0) + b"\x00" * 4, substg_data=None)
    report = analyze(m.build_bytes(), select={"ORPHAN_SUBSTG"})
    assert report.findings == []


def test_multivalue_element_streams_not_orphans(analyze):
    m = good_message()
    tag = P.make_tag(0x8011, 0x101F)  # PtypMultipleString
    # Property entry present, plus a length stream and two element streams.
    m.set_raw(tag, struct.pack("<I", 2) + b"\x00" * 4, substg_data=b"\x00\x00\x00\x00")
    m.add_stream(P.substg_name(tag, 0), "a".encode("utf-16-le"))
    m.add_stream(P.substg_name(tag, 1), "b".encode("utf-16-le"))
    report = analyze(m.build_bytes(), select={"ORPHAN_SUBSTG"})
    assert report.findings == []
