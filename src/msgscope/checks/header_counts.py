"""HEADER_COUNTS - property-stream header counts vs storages actually present.

The 32-byte top-level property-stream header declares the recipient and
attachment counts and the "next id" allocators.  Real files keep these in lock
step with the ``__recip_version1.0_#NNNNNNNN`` / ``__attach_version1.0_#NNNNNNNN``
storages that are physically present and number them contiguously from zero.
"""

from __future__ import annotations

from collections.abc import Iterable

from .. import properties as P
from ..findings import Confidence, Evidence, Finding, Severity
from .base import Check, CheckContext

_SPEC = "MS-OXMSG 2.4.1.1"

# Field offsets within the property-stream header.
_OFF_NEXT_RECIP = 8
_OFF_NEXT_ATTACH = 12
_OFF_RECIP_COUNT = 16
_OFF_ATTACH_COUNT = 20


def _indices(names: list[str], prefix: str) -> list[int]:
    out: list[int] = []
    for name in names:
        try:
            out.append(int(name[len(prefix) :], 16))
        except ValueError:
            continue
    return sorted(out)


class HeaderCountsCheck(Check):
    id = "HEADER_COUNTS"
    title = "Header object count does not match storages present"
    default_severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        c = ctx.container
        top = c.top()
        findings: list[Finding] = []

        specs = [
            (
                "recipient",
                top.declared_recipient_count,
                top.next_recipient_id,
                c.recipient_storage_names(),
                P.RECIP_PREFIX,
                _OFF_RECIP_COUNT,
                _OFF_NEXT_RECIP,
            ),
            (
                "attachment",
                top.declared_attachment_count,
                top.next_attachment_id,
                c.attachment_storage_names(),
                P.ATTACH_PREFIX,
                _OFF_ATTACH_COUNT,
                _OFF_NEXT_ATTACH,
            ),
        ]

        for kind, declared, next_id, names, prefix, count_off, next_off in specs:
            if declared is None:
                continue
            actual = len(names)
            if declared != actual:
                findings.append(
                    Finding(
                        id=self.id,
                        title=f"Header {kind} count does not match storages present",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        summary_plain=(
                            f"The file says it has {declared} {kind}(s), but {actual} "
                            f"{kind} folder(s) are actually inside it."
                        ),
                        why_it_matters=(
                            "Outlook keeps the declared count and the stored "
                            f"{kind} folders in agreement; a mismatch indicates the "
                            "container was edited or generated inconsistently."
                        ),
                        evidence=Evidence(
                            object_path=top.path_str,
                            stream=P.PROPERTIES_STREAM,
                            byte_offset=top.header_field_offset(count_off),
                            region=top.properties_stream_region,
                            observed=f"declared {kind} count = {declared}",
                            expected=f"{actual} {kind} storage(s) present",
                            raw_hex=c.hex_at(top.header_field_offset(count_off), 4),
                        ),
                        spec_reference=_SPEC,
                        detail_key=f"count:{kind}",
                    )
                )

            indices = _indices(names, prefix)
            if indices and indices != list(range(len(indices))):
                findings.append(
                    Finding(
                        id=self.id,
                        title=f"{kind.capitalize()} storages are not numbered contiguously",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        summary_plain=(
                            f"The {kind} folders are numbered with gaps instead of "
                            "0, 1, 2 in order."
                        ),
                        why_it_matters=(
                            f"Outlook numbers {kind} folders consecutively from zero; "
                            "gaps suggest one was removed or inserted after the fact."
                        ),
                        evidence=Evidence(
                            object_path=top.path_str,
                            observed=f"{kind} indices = {indices}",
                            expected=f"contiguous 0..{len(indices) - 1}",
                        ),
                        spec_reference=_SPEC,
                        detail_key=f"contig:{kind}",
                    )
                )

            if next_id is not None and next_id < actual:
                findings.append(
                    Finding(
                        id=self.id,
                        title=f"Next {kind} id is lower than the number present",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        summary_plain=(
                            f"The counter for the next {kind} id ({next_id}) is smaller "
                            f"than the number of {kind} folders already present ({actual})."
                        ),
                        why_it_matters=(
                            f"The allocator only ever moves forward, so it cannot be "
                            f"below the number of {kind} folders in a genuine file."
                        ),
                        evidence=Evidence(
                            object_path=top.path_str,
                            stream=P.PROPERTIES_STREAM,
                            byte_offset=top.header_field_offset(next_off),
                            region=top.properties_stream_region,
                            observed=f"next {kind} id = {next_id}",
                            expected=f">= {actual}",
                            raw_hex=c.hex_at(top.header_field_offset(next_off), 4),
                        ),
                        spec_reference=_SPEC,
                        detail_key=f"nextid:{kind}",
                    )
                )

        return findings
