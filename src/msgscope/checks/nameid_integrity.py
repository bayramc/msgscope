"""NAMEID_INTEGRITY - the named-property mapping in ``__nameid_version1.0``.

The named-property map translates property ids >= 0x8000 into a (GUID, LID-or-name)
pair using three streams: the GUID stream (00020102), the entry stream
(00030102), and the string stream (00040102).  This check validates the stream
sizes, that each entry's GUID index resolves, that string-named entries point
inside the string stream, and that every named property used elsewhere in the
file actually has a mapping entry.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable

from .. import properties as P
from ..container import MsgContainer
from ..findings import Confidence, Evidence, Finding, Severity
from .base import Check, CheckContext

_SPEC = "MS-OXMSG 2.2.3 / 2.2.3.1.2"

_GUID_STREAM = P.substg_name(P.make_tag(0x0002, P.PTYP_BINARY))  # __substg1.0_00020102
_ENTRY_STREAM = P.substg_name(P.make_tag(0x0003, P.PTYP_BINARY))  # __substg1.0_00030102
_STRING_STREAM = P.substg_name(P.make_tag(0x0004, P.PTYP_BINARY))  # __substg1.0_00040102

_NAMEID_PATH = (P.NAMEID_STORAGE,)
# GUID indices 0..2 are reserved/predefined (0 invalid, 1 PS_MAPI, 2 PS_PUBLIC_STRINGS).
_FIRST_STREAM_GUID_INDEX = 3


class NameIdIntegrityCheck(Check):
    id = "NAMEID_INTEGRITY"
    title = "Named-property mapping integrity"
    default_severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        c = ctx.container
        findings: list[Finding] = []

        used_indices = _named_indices_used(ctx)
        nameid = c.nameid_storage()

        if nameid is None:
            if used_indices:
                findings.append(
                    Finding(
                        id=self.id,
                        title="Named properties used without a mapping storage",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        summary_plain=(
                            "The file uses custom-named properties but has no table that "
                            "defines what those names mean."
                        ),
                        why_it_matters=(
                            "Outlook always writes the name-definition table when custom "
                            "properties are present; its absence indicates incomplete "
                            "synthetic generation."
                        ),
                        evidence=Evidence(
                            object_path="/",
                            observed=f"{len(used_indices)} named-property id(s) used; no {P.NAMEID_STORAGE}",
                            expected=f"{P.NAMEID_STORAGE} storage present",
                        ),
                        spec_reference=_SPEC,
                        detail_key="missing_storage",
                    )
                )
            return findings

        guid_stream = c.read_named_stream(_NAMEID_PATH, _GUID_STREAM) or b""
        entry_stream = c.read_named_stream(_NAMEID_PATH, _ENTRY_STREAM) or b""
        string_stream = c.read_named_stream(_NAMEID_PATH, _STRING_STREAM) or b""

        findings.extend(self._check_sizes(c, guid_stream, entry_stream))
        findings.extend(self._check_entries(c, guid_stream, entry_stream, string_stream))
        findings.extend(self._check_unmapped(entry_stream, used_indices))
        return findings

    def _check_sizes(self, c: MsgContainer, guid: bytes, entry: bytes) -> list[Finding]:
        out: list[Finding] = []
        if len(guid) % 16 != 0:
            info = c.entry((*_NAMEID_PATH, _GUID_STREAM))
            out.append(
                Finding(
                    id=self.id,
                    title="GUID stream length is not a multiple of 16",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    summary_plain="The list of property GUIDs has a truncated entry.",
                    why_it_matters=(
                        "Each GUID is exactly 16 bytes; a non-multiple length means the "
                        "table is malformed, as Outlook never writes it."
                    ),
                    evidence=Evidence(
                        object_path="/" + P.NAMEID_STORAGE,
                        stream=_GUID_STREAM,
                        byte_offset=info.file_offset if info else None,
                        region=info.region if info else None,
                        observed=f"length {len(guid)} bytes",
                        expected="a multiple of 16",
                    ),
                    spec_reference=_SPEC,
                    detail_key="guid_size",
                )
            )
        if len(entry) % 8 != 0:
            info = c.entry((*_NAMEID_PATH, _ENTRY_STREAM))
            out.append(
                Finding(
                    id=self.id,
                    title="Entry stream length is not a multiple of 8",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    summary_plain="The list of named-property definitions has a truncated entry.",
                    why_it_matters=(
                        "Each definition is exactly 8 bytes; a non-multiple length means "
                        "the table is malformed."
                    ),
                    evidence=Evidence(
                        object_path="/" + P.NAMEID_STORAGE,
                        stream=_ENTRY_STREAM,
                        byte_offset=info.file_offset if info else None,
                        region=info.region if info else None,
                        observed=f"length {len(entry)} bytes",
                        expected="a multiple of 8",
                    ),
                    spec_reference=_SPEC,
                    detail_key="entry_size",
                )
            )
        return out

    def _check_entries(
        self, c: MsgContainer, guid: bytes, entry: bytes, string: bytes
    ) -> list[Finding]:
        out: list[Finding] = []
        n_guids = len(guid) // 16
        for i in range(len(entry) // 8):
            name_off, _prop_index, kind_info = struct.unpack_from("<IHH", entry, i * 8)
            is_string = bool(kind_info & 0x0001)
            guid_index = kind_info >> 1
            abs_off, region = c.stream_offset_at((*_NAMEID_PATH, _ENTRY_STREAM), i * 8)

            if guid_index >= _FIRST_STREAM_GUID_INDEX:
                slot = guid_index - _FIRST_STREAM_GUID_INDEX
                if slot >= n_guids:
                    out.append(
                        Finding(
                            id=self.id,
                            title="Named-property entry references a missing GUID",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            summary_plain=(
                                "A custom-property definition points to a namespace GUID "
                                "that is not in the file's GUID list."
                            ),
                            why_it_matters=(
                                "The definition cannot be resolved, so it was not written "
                                "by a consistent MAPI provider."
                            ),
                            evidence=Evidence(
                                object_path="/" + P.NAMEID_STORAGE,
                                stream=_ENTRY_STREAM,
                                byte_offset=abs_off,
                                region=region,
                                observed=f"entry #{i} GUID index {guid_index} (slot {slot} of {n_guids})",
                                expected=f"GUID slot < {n_guids}",
                            ),
                            spec_reference=_SPEC,
                            detail_key=f"guid_index:{i}",
                        )
                    )

            if is_string:
                # name_off is a byte offset into the string stream: 4-byte length + name.
                ok = name_off + 4 <= len(string)
                if ok:
                    (slen,) = struct.unpack_from("<I", string, name_off)
                    ok = name_off + 4 + slen <= len(string)
                if not ok:
                    out.append(
                        Finding(
                            id=self.id,
                            title="Named-property entry points outside the string table",
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            summary_plain=(
                                "A custom-property name refers to a location beyond the "
                                "end of the stored name table."
                            ),
                            why_it_matters=(
                                "An out-of-bounds name offset means the mapping is "
                                "corrupt or fabricated."
                            ),
                            evidence=Evidence(
                                object_path="/" + P.NAMEID_STORAGE,
                                stream=_ENTRY_STREAM,
                                byte_offset=abs_off,
                                region=region,
                                observed=f"entry #{i} string offset {name_off}; string stream {len(string)} bytes",
                                expected="offset + 4 + name length <= string stream size",
                            ),
                            spec_reference=_SPEC,
                            detail_key=f"string_oob:{i}",
                        )
                    )
        return out

    def _check_unmapped(self, entry: bytes, used_indices: set[int]) -> list[Finding]:
        out: list[Finding] = []
        n_entries = len(entry) // 8
        missing = sorted(idx for idx in used_indices if idx >= n_entries)
        for idx in missing:
            prop_id = 0x8000 + idx
            out.append(
                Finding(
                    id=self.id,
                    title="Named property used without a mapping entry",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    summary_plain=(
                        "A custom-named property is used in the message but has no "
                        "definition in the name table."
                    ),
                    why_it_matters=(
                        "Every custom property Outlook stores has a matching definition; "
                        "an undefined one indicates inconsistent generation."
                    ),
                    evidence=Evidence(
                        object_path="/" + P.NAMEID_STORAGE,
                        stream=_ENTRY_STREAM,
                        observed=f"property id 0x{prop_id:04X} (index {idx}) used; only {n_entries} entries defined",
                        expected=f"a definition entry at index {idx}",
                    ),
                    spec_reference=_SPEC,
                    detail_key=f"unmapped:{idx}",
                )
            )
        return out


def _named_indices_used(ctx: CheckContext) -> set[int]:
    indices: set[int] = set()
    for obj in ctx.container.objects:
        for tag in obj.properties:
            pid = P.tag_id(tag)
            if 0x8000 <= pid <= 0xFFFE:
                indices.add(pid - 0x8000)
    return indices
