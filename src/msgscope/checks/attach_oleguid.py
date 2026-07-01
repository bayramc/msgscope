"""ATTACH_OLEGUID - unexpected CLSID / OLE GUID on storages.

Every CFB storage has a 16-byte CLSID in its directory entry.  In a genuine
``.msg`` the root carries the Outlook message CLSID (or zero) and the inner
storages (recipients, attachments, name-id) carry an all-zero CLSID.  An
unexpected GUID can mark an embedded OLE object inserted by other software.

The allowlist is intentionally small and is refined as the known-good corpus
grows, so findings are reported at low/medium confidence and lead with the raw
GUID as evidence.
"""

from __future__ import annotations

from collections.abc import Iterable

from .. import properties as P
from ..findings import Confidence, Evidence, Finding, Severity
from .base import Check, CheckContext

_SPEC = "MS-CFB 2.6.1 (Directory Entry CLSID)"

# Outlook message storage CLSID (IPM.Note).  Zero ("") is always acceptable.
_KNOWN_CLSIDS = {
    "00020D0B-0000-0000-C000-000000000046",
}


def _expected_for(name: str, is_root: bool) -> set[str]:
    if is_root:
        return _KNOWN_CLSIDS
    # Embedded message object storages legitimately carry the message CLSID.
    if name == P.substg_name(P.make_tag(0x3701, P.PTYP_OBJECT)):
        return _KNOWN_CLSIDS
    return set()  # only zero CLSID expected


class AttachOleGuidCheck(Check):
    id = "ATTACH_OLEGUID"
    title = "Unexpected CLSID / OLE GUID on a storage"
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        c = ctx.container
        findings: list[Finding] = []
        for info in c.dir_entries:
            if not (info.is_storage or info.is_root):
                continue
            if not info.clsid:  # zero CLSID is always fine
                continue
            allowed = _expected_for(info.name, info.is_root)
            if info.clsid.upper() in {a.upper() for a in allowed}:
                continue
            where = "/" if info.is_root else "/.../" + info.name
            findings.append(
                Finding(
                    id=self.id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.LOW,
                    summary_plain=(
                        "A folder inside the file is tagged with an unexpected program "
                        "identifier (CLSID)."
                    ),
                    why_it_matters=(
                        "Genuine Outlook storages are either untagged or carry the "
                        "Outlook message identifier; another identifier can indicate an "
                        "embedded object added by different software. Verify the GUID "
                        "against known providers."
                    ),
                    evidence=Evidence(
                        object_path=where,
                        stream=info.name,
                        byte_offset=info.clsid_offset,
                        region="directory",
                        directory_index=info.sid,
                        observed=f"CLSID = {{{info.clsid}}}",
                        expected=(
                            "Outlook message CLSID or all-zero"
                            if (info.is_root or info.name.startswith(P.SUBSTG_PREFIX))
                            else "all-zero CLSID"
                        ),
                        raw_hex=c.hex_at(info.clsid_offset, 16),
                    ),
                    spec_reference=_SPEC,
                    detail_key=f"clsid:{info.sid}",
                )
            )
        return findings
