"""FILETIME_SANITY: implausible or contradictory timestamps."""

from __future__ import annotations

import datetime as _dt
import struct

from conftest import ids
from fixtures.builders import good_message
from msgscope import properties as P


def test_creation_after_modification(analyze):
    m = good_message()
    m.set(P.PidTagCreationTime, _dt.datetime(2021, 5, 1, tzinfo=_dt.UTC))
    m.set(P.PidTagLastModificationTime, _dt.datetime(2021, 2, 1, tzinfo=_dt.UTC))
    report = analyze(m.build_bytes())
    assert ids(report) == {"FILETIME_SANITY"}
    assert any("creation" in f.title.lower() for f in report.findings)


def test_submit_after_delivery(analyze):
    m = good_message()
    m.set(P.PidTagClientSubmitTime, _dt.datetime(2021, 1, 1, 11, 0, tzinfo=_dt.UTC))
    m.set(P.PidTagMessageDeliveryTime, _dt.datetime(2021, 1, 1, 10, 0, tzinfo=_dt.UTC))
    report = analyze(m.build_bytes())
    assert ids(report) == {"FILETIME_SANITY"}
    assert any("delivery" in f.title.lower() for f in report.findings)


def test_epoch_timestamp(analyze):
    m = good_message()
    m.set_raw(P.PidTagCreationTime, struct.pack("<Q", 100))  # ~year 1601, not null
    report = analyze(m.build_bytes())
    assert "FILETIME_SANITY" in ids(report)
    assert ids(report) == {"FILETIME_SANITY"}
    assert any(f.detail_key.startswith("epoch") for f in report.findings)


def test_out_of_range_timestamp(analyze):
    m = good_message()
    m.set_raw(P.PidTagLastModificationTime, struct.pack("<Q", 0xFFFFFFFFFFFFFFFE))
    report = analyze(m.build_bytes())
    assert ids(report) == {"FILETIME_SANITY"}
    assert any("out of range" in f.title.lower() for f in report.findings)


def test_future_timestamp(analyze):
    m = good_message()  # all times in 2021
    past_ref = _dt.datetime(2020, 6, 1, tzinfo=_dt.UTC)
    report = analyze(m.build_bytes(), reference_time=past_ref)
    assert ids(report) == {"FILETIME_SANITY"}
    assert any(f.detail_key.startswith("future") for f in report.findings)


def test_null_timestamps_ignored(analyze):
    m = good_message()
    m.set_raw(P.PidTagCreationTime, struct.pack("<Q", 0))  # null marker
    report = analyze(m.build_bytes(), select={"FILETIME_SANITY"})
    # Null creation removes the ordering pair; no finding from a null value.
    assert report.findings == []
