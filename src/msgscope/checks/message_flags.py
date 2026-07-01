"""MSGFLAGS - PidTagMessageFlags bitmask validity.

PidTagMessageFlags (0x0E070003) is a bitmask.  Some bit combinations are
logically impossible and some contradict the rest of the message, so they are
strong tells of synthetic generation or editing.
"""

from __future__ import annotations

from collections.abc import Iterable

from .. import filetime as FT
from .. import properties as P
from ..findings import Confidence, Evidence, Finding, Severity
from .base import Check, CheckContext

_SPEC = "MS-OXCMSG 2.2.1.6 / MS-OXPROPS"


class MessageFlagsCheck(Check):
    id = "MSGFLAGS"
    title = "PidTagMessageFlags inconsistency"
    default_severity = Severity.MEDIUM

    def applies(self, ctx: CheckContext) -> bool:
        return P.PidTagMessageFlags in ctx.container.top().properties

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        c = ctx.container
        top = c.top()
        entry = top.properties.get(P.PidTagMessageFlags)
        if entry is None:
            return []
        flags = entry.as_uint32()
        offset = c.prop_value_offset(top, entry)
        region = top.properties_stream_region
        n_attach = len(c.attachment_storage_names())
        findings: list[Finding] = []

        def base_evidence(observed: str, expected: str) -> Evidence:
            return Evidence(
                object_path=top.path_str,
                stream=P.PROPERTIES_STREAM,
                byte_offset=offset,
                region=region,
                observed=observed,
                expected=expected,
                raw_hex=c.hex_at(offset, 4),
            )

        # 1. Reserved / undefined bits set.
        reserved = flags & ~P.MSGFLAG_DEFINED_MASK
        if reserved:
            findings.append(
                Finding(
                    id=self.id,
                    title="Reserved message-flag bits are set",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    summary_plain=(
                        "The message-status flags include bits that have no defined meaning."
                    ),
                    why_it_matters=(
                        "Outlook only sets defined flag bits; unknown bits point to a "
                        "value written by other software."
                    ),
                    evidence=base_evidence(
                        observed=f"flags=0x{flags:08X}, undefined bits=0x{reserved:08X}",
                        expected=f"only bits within mask 0x{P.MSGFLAG_DEFINED_MASK:08X}",
                    ),
                    spec_reference=_SPEC,
                    detail_key="reserved",
                )
            )

        # 2. HASATTACH vs reality.
        has_attach = bool(flags & P.MSGFLAG_HASATTACH)
        if has_attach and n_attach == 0:
            findings.append(
                Finding(
                    id=self.id,
                    title="HASATTACH set but no attachments present",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    summary_plain=(
                        "The message is flagged as having attachments, but no "
                        "attachments are stored inside it."
                    ),
                    why_it_matters=(
                        "Outlook sets this flag only when attachments exist; the flag "
                        "and contents disagree."
                    ),
                    evidence=base_evidence(
                        observed="MSGFLAG_HASATTACH set; 0 attachment storages",
                        expected="at least one __attach_version1.0_# storage",
                    ),
                    spec_reference=_SPEC,
                    detail_key="hasattach_set",
                )
            )
        elif not has_attach and n_attach > 0:
            findings.append(
                Finding(
                    id=self.id,
                    title="Attachments present but HASATTACH not set",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    summary_plain=(
                        "Attachments are stored inside the message, but it is not "
                        "flagged as having any."
                    ),
                    why_it_matters=(
                        "Outlook always flags messages that carry attachments; the "
                        "missing flag indicates inconsistent generation."
                    ),
                    evidence=base_evidence(
                        observed=f"MSGFLAG_HASATTACH clear; {n_attach} attachment storage(s)",
                        expected="MSGFLAG_HASATTACH set",
                    ),
                    spec_reference=_SPEC,
                    detail_key="hasattach_clear",
                )
            )

        # 3. UNSENT set but a client submit time exists.
        submit = top.properties.get(P.PidTagClientSubmitTime)
        submit_present = submit is not None and not FT.is_null(submit.as_filetime())
        if (flags & P.MSGFLAG_UNSENT) and submit_present:
            findings.append(
                Finding(
                    id=self.id,
                    title="UNSENT flag set on a message with a submit time",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    summary_plain=(
                        "The message is marked as never sent, yet it records the time "
                        "it was submitted for sending."
                    ),
                    why_it_matters=(
                        "A message cannot be both unsent and have a submit timestamp; "
                        "the two contradict each other."
                    ),
                    evidence=base_evidence(
                        observed="MSGFLAG_UNSENT set and PidTagClientSubmitTime present",
                        expected="UNSENT clear once a submit time is recorded",
                    ),
                    spec_reference=_SPEC,
                    detail_key="unsent_submit",
                )
            )

        # 4. FROMME on apparently received (external) mail.
        delivery = top.properties.get(P.PidTagMessageDeliveryTime)
        delivery_present = delivery is not None and not FT.is_null(delivery.as_filetime())
        if (flags & P.MSGFLAG_FROMME) and delivery_present and not submit_present:
            findings.append(
                Finding(
                    id=self.id,
                    title="FROMME set on an apparently received message",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    summary_plain=(
                        "The message is flagged as sent by the mailbox owner, but it "
                        "looks like an incoming message (it has a delivery time and no "
                        "submit time)."
                    ),
                    why_it_matters=(
                        "Mail that arrives from outside is not normally flagged as "
                        "originating from the current user."
                    ),
                    evidence=base_evidence(
                        observed="MSGFLAG_FROMME set with delivery time and no submit time",
                        expected="FROMME clear on externally-originating mail",
                    ),
                    spec_reference=_SPEC,
                    detail_key="fromme_received",
                )
            )

        return findings
