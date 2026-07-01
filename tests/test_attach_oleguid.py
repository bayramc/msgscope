"""ATTACH_OLEGUID: unexpected CLSID / OLE GUID on storages."""

from __future__ import annotations

from conftest import ids
from fixtures.builders import AttachmentBuilder, good_message
from msgscope import properties as P


def test_unexpected_root_clsid(analyze):
    m = good_message()
    m.root_clsid = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    report = analyze(m.build_bytes())
    assert ids(report) == {"ATTACH_OLEGUID"}
    assert report.findings[0].evidence.region == "directory"


def test_unexpected_attachment_storage_clsid(analyze):
    m = good_message()
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | P.MSGFLAG_HASATTACH)
    ab = AttachmentBuilder()
    ab.clsid = b"\x02" * 16
    m.add_attachment(ab)
    report = analyze(m.build_bytes())
    assert ids(report) == {"ATTACH_OLEGUID"}


def test_zero_clsid_not_flagged(analyze):
    m = good_message()  # all storages carry zero CLSID
    report = analyze(m.build_bytes(), select={"ATTACH_OLEGUID"})
    assert report.findings == []
