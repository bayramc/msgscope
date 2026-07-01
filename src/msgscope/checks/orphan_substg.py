"""ORPHAN_SUBSTG - substorage streams not indexed in the property table.

Every ``__substg1.0_`` stream a real MAPI provider writes is described by a
matching 16-byte entry in that object's ``__properties_version1.0`` table.  Two
inconsistencies are reported:

* **orphan**   - a substg stream exists with no property-table entry for its tag.
* **dangling** - a property-table entry of an externally-stored type points at a
  substg stream that is not present.

Known benign causes are limited (some writers emit empty streams or omit empty
values), so dangling findings on zero-length values are suppressed.
"""

from __future__ import annotations

from collections.abc import Iterable

from .. import properties as P
from ..findings import Confidence, Evidence, Finding, Severity
from .base import Check, CheckContext

_SPEC = "MS-OXMSG 2.1.3 / 2.4"


class OrphanSubstgCheck(Check):
    id = "ORPHAN_SUBSTG"
    title = "Substorage stream not indexed in property table"
    default_severity = Severity.HIGH

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        c = ctx.container
        findings: list[Finding] = []
        for obj in c.objects:
            present_tags: dict[int, str] = {}
            for name in obj.child_substg:
                parsed = P.parse_substg_name(name)
                if parsed is None:
                    continue
                tag, _mv = parsed
                # Keep the lexicographically smallest stream name per tag.
                if tag not in present_tags or name < present_tags[tag]:
                    present_tags[tag] = name

            # --- orphan: stream present, no property entry ---
            for tag in sorted(present_tags):
                if tag in obj.properties:
                    continue
                name = present_tags[tag]
                info = c.entry((*obj.path, name))
                findings.append(
                    Finding(
                        id=self.id,
                        title=self.title,
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        summary_plain=(
                            "A data stream exists inside the file that the file's own "
                            "property index does not list."
                        ),
                        why_it_matters=(
                            "Outlook records every stream it writes in the property "
                            "index. An unlisted stream suggests the file was assembled "
                            "or edited by other software."
                        ),
                        evidence=Evidence(
                            object_path=obj.path_str,
                            stream=name,
                            byte_offset=info.file_offset if info else None,
                            region=info.region if info else None,
                            directory_index=info.sid if info else None,
                            observed=f"stream present; no property entry for tag {P.tag_label(tag)}",
                            expected=f"a 16-byte entry with tag {P.tag_label(tag)} in {P.PROPERTIES_STREAM}",
                            raw_hex=c.hex_at(info.file_offset) if info else None,
                        ),
                        spec_reference=_SPEC,
                        detail_key=f"orphan:{tag:08X}",
                    )
                )

            # --- dangling: entry present, no stream ---
            for tag, entry in sorted(obj.properties.items()):
                if not P.is_stored_external(entry.prop_type):
                    continue
                if tag in present_tags:
                    continue
                if entry.external_size == 0:
                    # Empty values may legitimately omit the stream.
                    continue
                findings.append(
                    Finding(
                        id=self.id,
                        title="Property entry references a missing stream",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        summary_plain=(
                            "The file's index lists a value that should live in its own "
                            "stream, but that stream is missing."
                        ),
                        why_it_matters=(
                            "A genuine file stores the referenced data; a missing target "
                            "means the index and the contents disagree, which Outlook "
                            "does not produce."
                        ),
                        evidence=Evidence(
                            object_path=obj.path_str,
                            stream=P.substg_name(tag),
                            byte_offset=obj.header_field_offset(0),
                            region=obj.properties_stream_region,
                            observed=(
                                f"property entry {P.tag_label(tag)} declares "
                                f"{entry.external_size} bytes but no stream {P.substg_name(tag)}"
                            ),
                            expected=f"stream {P.substg_name(tag)} present under {obj.path_str}",
                        ),
                        spec_reference=_SPEC,
                        detail_key=f"dangling:{tag:08X}",
                    )
                )
        return findings
