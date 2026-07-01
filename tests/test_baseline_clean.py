"""The well-formed baseline must produce no findings from any detector."""

from __future__ import annotations

from fixtures.builders import good_message_bytes


def test_good_message_has_no_findings(analyze):
    report = analyze(good_message_bytes())
    assert report.is_cfb
    assert report.findings == [], [f.id for f in report.findings]
    assert report.total == 0


def test_good_message_counts_are_zero(analyze):
    report = analyze(good_message_bytes())
    assert report.counts == {"info": 0, "low": 0, "medium": 0, "high": 0}
