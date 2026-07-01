"""CODEPAGE_MISMATCH - declared codepage vs the actual body bytes.

Compares PidTagInternetCodepage / PidTagMessageCodepage against the bytes of the
stored body streams: the Unicode body must be valid UTF-16LE, the ANSI body must
decode under the declared codepage, and the HTML body's declared charset should
agree with the codepage property.

Most byte sequences decode under single-byte codepages, so this check mostly
fires on UTF-8 / multibyte mismatches; findings are reported at low/medium
confidence with the offending bytes as evidence.
"""

from __future__ import annotations

import codecs
import re
from collections.abc import Iterable

from .. import properties as P
from ..container import MsgObject
from ..findings import Confidence, Evidence, Finding, Severity
from .base import Check, CheckContext

_SPEC = "MS-OXCMSG 2.2.1.x (body / codepage properties)"

# Windows codepage number -> python codec name (common subset).
_CODEPAGE_CODEC = {
    20127: "ascii",
    28591: "iso-8859-1",
    28592: "iso-8859-2",
    65000: "utf-7",
    65001: "utf-8",
}

_HTML_CHARSET_RE = re.compile(rb"charset\s*=\s*[\"']?\s*([A-Za-z0-9_\-]+)", re.IGNORECASE)


def _codec_for(cp: int) -> str | None:
    if cp in _CODEPAGE_CODEC:
        return _CODEPAGE_CODEC[cp]
    try:
        codecs.lookup(f"cp{cp}")
    except LookupError:
        return None
    return f"cp{cp}"


class CodepageMismatchCheck(Check):
    id = "CODEPAGE_MISMATCH"
    title = "Declared codepage does not match body bytes"
    default_severity = Severity.MEDIUM

    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        c = ctx.container
        top = c.top()
        findings: list[Finding] = []

        cp = _declared_codepage(top)
        codec = _codec_for(cp) if cp is not None else None

        # 1. Unicode body must be valid UTF-16LE.
        body_w = c.read_substg(top, P.PidTagBodyW)
        if body_w is not None:
            info = c.entry((*top.path, P.substg_name(P.PidTagBodyW)))
            problem = None
            if len(body_w) % 2 != 0:
                problem = f"odd length {len(body_w)} bytes"
            else:
                try:
                    body_w.decode("utf-16-le")
                except UnicodeDecodeError as exc:
                    problem = f"invalid UTF-16LE ({exc.reason})"
            if problem:
                findings.append(
                    Finding(
                        id=self.id,
                        title="Unicode body is not valid UTF-16",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        summary_plain="The message's Unicode body text is not stored as valid Unicode.",
                        why_it_matters=(
                            "Outlook stores the Unicode body as well-formed UTF-16; "
                            "malformed bytes indicate the stream was written by other "
                            "software."
                        ),
                        evidence=Evidence(
                            object_path=top.path_str,
                            stream=P.substg_name(P.PidTagBodyW),
                            byte_offset=info.file_offset if info else None,
                            region=info.region if info else None,
                            observed=problem,
                            expected="even-length, valid UTF-16LE",
                            raw_hex=c.hex_at(info.file_offset if info else None, 16),
                        ),
                        spec_reference=_SPEC,
                        detail_key="body_w",
                    )
                )

        # 2. ANSI body must decode under the declared codepage.
        body_a = c.read_substg(top, P.PidTagBodyA)
        if body_a is not None and cp is not None and codec is not None:
            try:
                body_a.decode(codec)
            except UnicodeDecodeError as exc:
                info = c.entry((*top.path, P.substg_name(P.PidTagBodyA)))
                bad_off = (
                    (info.file_offset + exc.start)
                    if info and info.file_offset is not None
                    else None
                )
                findings.append(
                    Finding(
                        id=self.id,
                        title="ANSI body does not decode under the declared codepage",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        summary_plain=(
                            f"The body text does not match the character set the file "
                            f"says it uses (codepage {cp})."
                        ),
                        why_it_matters=(
                            "When the declared encoding cannot decode the stored text, "
                            "the body and its metadata were not produced together, as a "
                            "real client would."
                        ),
                        evidence=Evidence(
                            object_path=top.path_str,
                            stream=P.substg_name(P.PidTagBodyA),
                            byte_offset=bad_off,
                            region=info.region if info else None,
                            observed=f"byte 0x{body_a[exc.start]:02X} at +{exc.start} invalid for cp{cp}",
                            expected=f"bytes decodable as {codec}",
                            raw_hex=c.hex_at(bad_off, 16),
                        ),
                        spec_reference=_SPEC,
                        detail_key="body_a",
                    )
                )

        # 3. Unknown declared codepage.
        if cp is not None and codec is None:
            entry = top.properties.get(P.PidTagInternetCodepage) or top.properties.get(
                P.PidTagMessageCodepage
            )
            off = c.prop_value_offset(top, entry) if entry else None
            findings.append(
                Finding(
                    id=self.id,
                    title="Declared codepage is not a known codepage",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    summary_plain=f"The file declares a character set ({cp}) that is not recognised.",
                    why_it_matters=(
                        "An unrecognised codepage number is unusual for Outlook and may "
                        "indicate a fabricated value."
                    ),
                    evidence=Evidence(
                        object_path=top.path_str,
                        stream=P.PROPERTIES_STREAM,
                        byte_offset=off,
                        region=top.properties_stream_region,
                        observed=f"codepage = {cp}",
                        expected="a recognised Windows codepage",
                        raw_hex=c.hex_at(off, 4),
                    ),
                    spec_reference=_SPEC,
                    detail_key="unknown_cp",
                )
            )

        # 4. HTML body charset vs declared codepage.
        html = c.read_substg(top, P.PidTagHtml)
        if html is not None and cp is not None:
            m = _HTML_CHARSET_RE.search(html)
            if m:
                declared_html = m.group(1).decode("ascii", "replace").lower()
                cp_codec = (codec or "").lower()
                try:
                    html_codec = codecs.lookup(declared_html).name
                except LookupError:
                    html_codec = declared_html
                if cp_codec and html_codec and codecs_differ(cp_codec, html_codec):
                    info = c.entry((*top.path, P.substg_name(P.PidTagHtml)))
                    findings.append(
                        Finding(
                            id=self.id,
                            title="HTML charset disagrees with the codepage property",
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            summary_plain=(
                                "The HTML body says it uses one character set while the "
                                "message property declares another."
                            ),
                            why_it_matters=(
                                "The HTML and the message metadata should describe the "
                                "same encoding; a mismatch can indicate stitched-together "
                                "content."
                            ),
                            evidence=Evidence(
                                object_path=top.path_str,
                                stream=P.substg_name(P.PidTagHtml),
                                byte_offset=info.file_offset if info else None,
                                region=info.region if info else None,
                                observed=f"HTML charset={declared_html}; codepage={cp}",
                                expected="matching encodings",
                            ),
                            spec_reference=_SPEC,
                            detail_key="html_charset",
                        )
                    )

        return findings


def codecs_differ(a: str, b: str) -> bool:
    try:
        return codecs.lookup(a).name != codecs.lookup(b).name
    except LookupError:
        return a != b


def _declared_codepage(top: MsgObject) -> int | None:
    for tag in (P.PidTagInternetCodepage, P.PidTagMessageCodepage):
        entry = top.properties.get(tag)
        if entry is not None:
            return entry.as_uint32()
    return None
