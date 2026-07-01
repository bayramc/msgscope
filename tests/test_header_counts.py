"""HEADER_COUNTS: declared counts / numbering / allocators vs reality."""

from __future__ import annotations

from conftest import ids
from fixtures.builders import AttachmentBuilder, good_message
from msgscope import properties as P


def test_recipient_count_mismatch(analyze):
    m = good_message()  # one real recipient
    m.recip_count_override = 5
    report = analyze(m.build_bytes())
    assert ids(report) == {"HEADER_COUNTS"}
    assert report.findings[0].confidence.value == "high"


def test_attachment_count_mismatch(analyze):
    m = good_message()
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | P.MSGFLAG_HASATTACH)
    m.add_attachment(AttachmentBuilder())
    m.attach_count_override = 3  # declare 3, only 1 present
    report = analyze(m.build_bytes())
    assert ids(report) == {"HEADER_COUNTS"}


def test_non_contiguous_attachment_indices(analyze):
    m = good_message()
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | P.MSGFLAG_HASATTACH)
    m.add_attachment(AttachmentBuilder())
    m.add_attachment(AttachmentBuilder())
    m.attach_indices = [0, 2]  # gap at index 1
    report = analyze(m.build_bytes())
    assert ids(report) == {"HEADER_COUNTS"}
    assert any("contiguous" in f.title.lower() for f in report.findings)


def test_next_id_below_count(analyze):
    m = good_message()  # one recipient
    m.next_recip_override = 0  # allocator below the number present
    report = analyze(m.build_bytes())
    assert ids(report) == {"HEADER_COUNTS"}
    assert any("next" in f.title.lower() for f in report.findings)
