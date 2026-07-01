"""NAMEID_INTEGRITY: named-property mapping validation."""

from __future__ import annotations

import struct

from conftest import ids
from fixtures.builders import good_message
from msgscope import properties as P


def test_missing_nameid_storage_when_named_prop_used(analyze):
    m = good_message()
    m.set(P.make_tag(0x8005, P.PTYP_INTEGER32), 1)  # named property, inline
    report = analyze(m.build_bytes())
    assert ids(report) == {"NAMEID_INTEGRITY"}
    assert any("without a mapping" in f.title.lower() for f in report.findings)


def test_unmapped_named_property(analyze):
    m = good_message()
    m.set(P.make_tag(0x8005, P.PTYP_INTEGER32), 1)  # index 5 used
    m.set_nameid(guid=b"", entry=b"", string=b"")  # zero entries defined
    report = analyze(m.build_bytes())
    assert ids(report) == {"NAMEID_INTEGRITY"}


def test_guid_stream_length_not_multiple_of_16(analyze):
    m = good_message()
    m.set_nameid(guid=b"\x00" * 17, entry=b"", string=b"")
    report = analyze(m.build_bytes())
    assert ids(report) == {"NAMEID_INTEGRITY"}
    assert any("multiple of 16" in f.title.lower() for f in report.findings)


def test_entry_stream_length_not_multiple_of_8(analyze):
    m = good_message()
    m.set_nameid(guid=b"", entry=b"\x00" * 9, string=b"")
    report = analyze(m.build_bytes())
    assert ids(report) == {"NAMEID_INTEGRITY"}
    assert any("multiple of 8" in f.title.lower() for f in report.findings)


def test_entry_references_missing_guid(analyze):
    m = good_message()
    # One entry: name_off=0, prop_index=0, kind_info => guid_index=3 (needs GUID slot 0).
    entry = struct.pack("<IHH", 0, 0, (3 << 1) | 0)
    m.set_nameid(guid=b"", entry=entry, string=b"")
    report = analyze(m.build_bytes())
    assert ids(report) == {"NAMEID_INTEGRITY"}
    assert any("missing guid" in f.title.lower() for f in report.findings)


def test_string_entry_out_of_bounds(analyze):
    m = good_message()
    # kind_info: guid_index=1 (PS_MAPI), string bit set; name offset 100 into empty stream.
    entry = struct.pack("<IHH", 100, 0, (1 << 1) | 1)
    m.set_nameid(guid=b"", entry=entry, string=b"")
    report = analyze(m.build_bytes())
    assert ids(report) == {"NAMEID_INTEGRITY"}
    assert any("string table" in f.title.lower() for f in report.findings)
