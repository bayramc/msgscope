"""MSGFLAGS: impossible / contradictory PidTagMessageFlags combinations."""

from __future__ import annotations

from conftest import ids
from fixtures.builders import AttachmentBuilder, good_message
from msgscope import properties as P


def test_hasattach_without_attachments(analyze):
    m = good_message()
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | P.MSGFLAG_HASATTACH)
    report = analyze(m.build_bytes())
    assert ids(report) == {"MSGFLAGS"}
    assert report.findings[0].severity.value == "high"


def test_attachments_without_hasattach(analyze):
    m = good_message()
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ)  # HASATTACH clear
    m.add_attachment(AttachmentBuilder())
    report = analyze(m.build_bytes(), select={"MSGFLAGS"})
    assert ids(report) == {"MSGFLAGS"}


def test_reserved_bits_set(analyze):
    m = good_message()
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | 0x40000000)
    report = analyze(m.build_bytes())
    assert ids(report) == {"MSGFLAGS"}
    assert report.findings[0].severity.value == "low"


def test_unsent_with_submit_time(analyze):
    m = good_message()  # has a submit time
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | P.MSGFLAG_UNSENT)
    report = analyze(m.build_bytes())
    assert ids(report) == {"MSGFLAGS"}
    assert any("unsent" in f.title.lower() for f in report.findings)


def test_fromme_on_received_mail(analyze):
    m = good_message()
    del m.entries[P.PidTagClientSubmitTime]  # looks received (delivery, no submit)
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | P.MSGFLAG_FROMME)
    report = analyze(m.build_bytes())
    assert ids(report) == {"MSGFLAGS"}
    assert report.findings[0].confidence.value == "low"
