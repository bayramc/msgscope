"""JSON output is deterministic and never contains a verdict/score."""

from __future__ import annotations

import json

from fixtures.builders import good_message
from msgscope.report import report_to_dict, report_to_json


def _orphan_bytes():
    m = good_message()
    m.add_stream("__substg1.0_80050102", b"orphan bytes")
    return m.build_bytes()


def test_json_is_byte_for_byte_reproducible(analyze):
    data = _orphan_bytes()
    a = report_to_json(analyze(data))
    b = report_to_json(analyze(data))
    assert a == b


def test_no_verdict_or_score_fields(analyze):
    doc = report_to_dict(analyze(_orphan_bytes()))
    blob = json.dumps(doc).lower()
    assert "verdict" not in blob
    assert "score" not in blob
    assert "forged" not in blob


def test_reproducible_run_block_has_no_volatile_fields(analyze):
    doc = report_to_dict(analyze(_orphan_bytes()))
    assert doc["run"] == {"reproducible": True}


def test_findings_sorted_by_severity(analyze):
    # Combine a high (orphan) and a low (reserved flag bit) anomaly.
    from msgscope import properties as P

    m = good_message()
    m.add_stream("__substg1.0_80050102", b"orphan bytes")
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | 0x40000000)
    report = analyze(m.build_bytes())
    ranks = [f.severity.rank for f in report.findings]
    assert ranks == sorted(ranks, reverse=True)
