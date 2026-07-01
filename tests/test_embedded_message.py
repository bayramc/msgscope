"""Embedded messages (attachments that are themselves messages) are inspected."""

from __future__ import annotations

from conftest import ids
from fixtures.builders import AttachmentBuilder, MessageBuilder, good_message
from msgscope import properties as P
from msgscope.container import MsgContainer, ObjectKind


def _with_embedded(embedded: MessageBuilder) -> bytes:
    m = good_message()
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | P.MSGFLAG_HASATTACH)
    ab = AttachmentBuilder()
    ab.embedded = embedded
    m.add_attachment(ab)
    return m.build_bytes()


def _clean_embedded() -> MessageBuilder:
    emb = MessageBuilder()
    emb.set(P.PidTagMessageClassW, "IPM.Note")
    emb.set(P.PidTagBodyW, "embedded body")
    return emb


def test_embedded_object_is_parsed(write_msg):
    path = write_msg(_with_embedded(_clean_embedded()))
    with MsgContainer(path) as c:
        kinds = {o.kind for o in c.objects}
    assert ObjectKind.MESSAGE_EMBEDDED in kinds
    assert ObjectKind.ATTACHMENT in kinds


def test_clean_embedded_has_no_findings(analyze):
    report = analyze(_with_embedded(_clean_embedded()))
    assert report.findings == []


def test_anomaly_inside_embedded_is_detected(analyze):
    emb = _clean_embedded()
    emb.add_stream("__substg1.0_80050102", b"orphan inside the embedded message")
    report = analyze(_with_embedded(emb), select={"ORPHAN_SUBSTG"})
    assert ids(report) == {"ORPHAN_SUBSTG"}
    assert "__attach_version1.0" in report.findings[0].evidence.object_path
