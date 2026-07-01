"""Human-readable terminal report.

Findings are grouped by severity (high first).  Colour is emitted only when
enabled (a TTY and not ``--no-color``); the plain form is fully deterministic.
"""

from __future__ import annotations

from collections.abc import Callable

from ..engine import Report
from ..findings import Finding, Severity

_RESET = "\033[0m"
_SEVERITY_COLOR = {
    Severity.HIGH: "\033[1;31m",  # bold red
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.LOW: "\033[36m",  # cyan
    Severity.INFO: "\033[2m",  # dim
}
_BOLD = "\033[1m"
_DIM = "\033[2m"


def _paint(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{_RESET}" if color else text


def render(report: Report, *, color: bool = False) -> str:
    lines: list[str] = []
    add = lines.append

    add(_paint(f"msgscope report - {report.target_name}", _BOLD, color))
    add(f"  SHA-256 : {report.sha256}")
    add(f"  Size    : {report.size_bytes} bytes")
    if not report.reproducible:
        add(f"  Analyzed: {report.analyzed_at.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    add("")

    if report.error:
        add(_paint(f"Cannot analyze: {report.error}", _SEVERITY_COLOR[Severity.HIGH], color))
        add("")
        add("No indicators evaluated. This tool reports indicators, not verdicts.")
        return "\n".join(lines) + "\n"

    if not report.findings:
        add("No indicators found. This is not proof of authenticity; it means none")
        add("of the current structural checks matched.")
        add("")
        add(_counts_line(report, color))
        return "\n".join(lines) + "\n"

    for sev in (Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        group = [f for f in report.findings if f.severity is sev]
        if not group:
            continue
        for f in group:
            _render_finding(add, f, color)
            add("")

    add(_counts_line(report, color))
    add(_paint("Indicators only - a human examiner draws the conclusion.", _DIM, color))
    return "\n".join(lines) + "\n"


def _render_finding(emit: Callable[[str], None], f: Finding, color: bool) -> None:
    tag = f"[{f.severity.value.upper()}/{f.confidence.value}]"
    emit(
        f"{_paint(tag, _SEVERITY_COLOR[f.severity], color)} {_paint(f.title, _BOLD, color)}  ({f.id})"
    )
    emit(f"  What : {f.summary_plain}")
    emit(f"  Why  : {f.why_it_matters}")
    e = f.evidence
    loc = e.object_path
    if e.stream:
        loc += f"  stream={e.stream}"
    if e.byte_offset is not None:
        loc += f"  offset=0x{e.byte_offset:X}"
    if e.region:
        loc += f"  region={e.region}"
    emit(f"  Where: {loc}")
    emit(f"  Seen : {e.observed}")
    emit(f"  Norm : {e.expected}")
    if e.raw_hex:
        emit(f"  Bytes: {e.raw_hex}")
    if f.spec_reference:
        emit(f"  Spec : {f.spec_reference}")


def _counts_line(report: Report, color: bool) -> str:
    c = report.counts
    parts = [
        _paint(f"high: {c['high']}", _SEVERITY_COLOR[Severity.HIGH], color),
        _paint(f"medium: {c['medium']}", _SEVERITY_COLOR[Severity.MEDIUM], color),
        _paint(f"low: {c['low']}", _SEVERITY_COLOR[Severity.LOW], color),
        _paint(f"info: {c['info']}", _SEVERITY_COLOR[Severity.INFO], color),
    ]
    return "Indicators  " + "  ".join(parts) + f"  ·  total: {report.total}"
