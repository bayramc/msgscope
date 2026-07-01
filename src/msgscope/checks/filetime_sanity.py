"""FILETIME_SANITY - timestamp plausibility and internal ordering.

Checks the MAPI time properties for values that cannot occur in an organically
created message: timestamps at/near the 1601 epoch, in the future, or internally
contradictory (creation after last-modification, delivery before submission).
"""

from __future__ import annotations

from collections.abc import Iterable

from .. import filetime as FT
from .. import properties as P
from ..container import MsgObject
from ..findings import Confidence, Evidence, Finding, Severity
from .base import Check, CheckContext

_SPEC = "MS-OXOMSG / MS-OXPROPS (PtypTime)"

_EARLY_HARD_YEAR = 1700  # at/near the 1601 epoch -> impossible
_EARLY_SOFT_YEAR = 1990  # implausibly early for a real .msg


class FiletimeSanityCheck(Check):
    id = "FILETIME_SANITY"
    title = "Implausible or contradictory FILETIME"
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        c = ctx.container
        findings: list[Finding] = []
        ref = ctx.reference_time

        for obj in c.objects:
            findings.extend(self._per_value(ctx, obj, ref))
            findings.extend(self._ordering(ctx, obj))
        return findings

    def _per_value(self, ctx: CheckContext, obj: MsgObject, ref: object) -> list[Finding]:
        c = ctx.container
        out: list[Finding] = []
        for tag in (
            P.PidTagClientSubmitTime,
            P.PidTagMessageDeliveryTime,
            P.PidTagCreationTime,
            P.PidTagLastModificationTime,
        ):
            entry = obj.properties.get(tag)
            if entry is None:
                continue
            ticks = entry.as_filetime()
            if FT.is_null(ticks):
                continue
            offset = c.prop_value_offset(obj, entry)
            raw = c.hex_at(offset, 8)

            def ev(observed: str, expected: str, _o=offset, _r=raw) -> Evidence:
                return Evidence(
                    object_path=obj.path_str,
                    stream=P.PROPERTIES_STREAM,
                    byte_offset=_o,
                    region=obj.properties_stream_region,
                    observed=observed,
                    expected=expected,
                    raw_hex=_r,
                )

            dt = FT.to_datetime(ticks)
            if dt is None:
                out.append(
                    Finding(
                        id=self.id,
                        title="Timestamp value is out of range",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        summary_plain=f"The {P.tag_label(tag)} timestamp is not a valid date.",
                        why_it_matters=(
                            "A real timestamp falls within ordinary calendar dates; an "
                            "out-of-range value is produced by faulty or synthetic "
                            "generation."
                        ),
                        evidence=ev(
                            observed=f"{P.tag_label(tag)} = {FT.format_ticks(ticks)}",
                            expected="a representable calendar date",
                        ),
                        spec_reference=_SPEC,
                        detail_key=f"range:{obj.path_str}:{tag:08X}",
                    )
                )
                continue
            if dt.year < _EARLY_HARD_YEAR:
                out.append(
                    Finding(
                        id=self.id,
                        title="Timestamp sits at the 1601 epoch",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        summary_plain=(
                            f"The {P.tag_label(tag)} timestamp is essentially the zero "
                            "date used when no real time was written."
                        ),
                        why_it_matters=(
                            "A genuine message has real dates; a value pinned to the "
                            "1601 origin indicates the field was fabricated or left blank."
                        ),
                        evidence=ev(
                            observed=f"{P.tag_label(tag)} = {FT.format_ticks(ticks)}",
                            expected="a realistic message date",
                        ),
                        spec_reference=_SPEC,
                        detail_key=f"epoch:{obj.path_str}:{tag:08X}",
                    )
                )
            elif dt.year < _EARLY_SOFT_YEAR:
                out.append(
                    Finding(
                        id=self.id,
                        title="Timestamp is implausibly early",
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        summary_plain=(
                            f"The {P.tag_label(tag)} timestamp predates common email use."
                        ),
                        why_it_matters=(
                            "Very early dates are unusual for Outlook messages and may "
                            "indicate a fabricated timestamp."
                        ),
                        evidence=ev(
                            observed=f"{P.tag_label(tag)} = {FT.format_ticks(ticks)}",
                            expected=f"a date on or after ~{_EARLY_SOFT_YEAR}",
                        ),
                        spec_reference=_SPEC,
                        detail_key=f"early:{obj.path_str}:{tag:08X}",
                    )
                )
            elif ref is not None and dt > ref:  # type: ignore[operator]
                out.append(
                    Finding(
                        id=self.id,
                        title="Timestamp is in the future",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        summary_plain=f"The {P.tag_label(tag)} timestamp is later than now.",
                        why_it_matters=(
                            "A message cannot record an event that has not happened yet; "
                            "a future date points to a tampered or back-/forward-dated file."
                        ),
                        evidence=ev(
                            observed=f"{P.tag_label(tag)} = {FT.format_ticks(ticks)}",
                            expected=f"on or before {ref}",  # type: ignore[str-bytes-safe]
                        ),
                        spec_reference=_SPEC,
                        detail_key=f"future:{obj.path_str}:{tag:08X}",
                    )
                )
        return out

    def _ordering(self, ctx: CheckContext, obj: MsgObject) -> list[Finding]:
        c = ctx.container
        out: list[Finding] = []

        def ticks(tag: int) -> int | None:
            entry = obj.properties.get(tag)
            if entry is None:
                return None
            t = entry.as_filetime()
            return None if FT.is_null(t) else t

        created = ticks(P.PidTagCreationTime)
        modified = ticks(P.PidTagLastModificationTime)
        if created is not None and modified is not None and created > modified:
            off = c.prop_value_offset(obj, obj.properties[P.PidTagCreationTime])
            out.append(
                Finding(
                    id=self.id,
                    title="Creation time is after last-modification time",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    summary_plain=(
                        "The file says it was created after it was last changed, which "
                        "is impossible."
                    ),
                    why_it_matters=(
                        "An item cannot be modified before it exists; reversed times "
                        "indicate the timestamps were set by hand."
                    ),
                    evidence=Evidence(
                        object_path=obj.path_str,
                        stream=P.PROPERTIES_STREAM,
                        byte_offset=off,
                        region=obj.properties_stream_region,
                        observed=(
                            f"creation {FT.format_ticks(created)} > "
                            f"modification {FT.format_ticks(modified)}"
                        ),
                        expected="creation <= last-modification",
                    ),
                    spec_reference=_SPEC,
                    detail_key=f"order_cm:{obj.path_str}",
                )
            )

        submit = ticks(P.PidTagClientSubmitTime)
        delivery = ticks(P.PidTagMessageDeliveryTime)
        if submit is not None and delivery is not None and submit > delivery:
            off = c.prop_value_offset(obj, obj.properties[P.PidTagClientSubmitTime])
            out.append(
                Finding(
                    id=self.id,
                    title="Submit time is after delivery time",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    summary_plain=("The message was supposedly delivered before it was sent."),
                    why_it_matters=(
                        "Delivery always follows submission; a reversed pair suggests "
                        "the timestamps were altered."
                    ),
                    evidence=Evidence(
                        object_path=obj.path_str,
                        stream=P.PROPERTIES_STREAM,
                        byte_offset=off,
                        region=obj.properties_stream_region,
                        observed=(
                            f"submit {FT.format_ticks(submit)} > "
                            f"delivery {FT.format_ticks(delivery)}"
                        ),
                        expected="submit <= delivery",
                    ),
                    spec_reference=_SPEC,
                    detail_key=f"order_sd:{obj.path_str}",
                )
            )
        return out
