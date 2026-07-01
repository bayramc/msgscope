"""Check registry, plugin discovery, and the analysis pipeline.

Built-in checks register themselves on import of :mod:`msgscope.checks`.
Third-party detectors can ship as separate packages that advertise an entry
point in the ``msgscope.checks`` group; :func:`discover_plugins` loads them.

The engine runs each applicable check, collects findings, sorts them
deterministically, and computes the neutral counts summary.  It never derives a
verdict or aggregate score.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from importlib import metadata
from typing import TYPE_CHECKING

from .container import MsgContainer
from .findings import Confidence, Finding, Severity

if TYPE_CHECKING:
    from .checks.base import Check

ENTRY_POINT_GROUP = "msgscope.checks"

_REGISTRY: dict[str, Check] = {}


def register(check: Check) -> Check:
    """Register a check instance (idempotent by id)."""
    _REGISTRY[check.id] = check
    return check


def registered_checks() -> list[Check]:
    """All registered checks, ordered by id for determinism."""
    return [_REGISTRY[k] for k in sorted(_REGISTRY)]


def discover_plugins() -> None:
    """Load third-party checks advertised via the ``msgscope.checks`` group."""
    from .checks.base import Check

    for ep in metadata.entry_points(group=ENTRY_POINT_GROUP):
        obj = ep.load()
        check = obj() if isinstance(obj, type) else obj
        if isinstance(check, Check):
            register(check)


@dataclass
class Report:
    """Result of analysing one file."""

    target_name: str
    sha256: str
    size_bytes: int
    is_cfb: bool
    findings: list[Finding]
    analyzed_at: _dt.datetime
    argv: list[str] = field(default_factory=list)
    reproducible: bool = False
    error: str | None = None

    @property
    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def total(self) -> int:
        return len(self.findings)

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)


def analyze(
    container: MsgContainer,
    *,
    checks: list[Check] | None = None,
    select: set[str] | None = None,
    exclude: set[str] | None = None,
    reference_time: _dt.datetime | None = None,
    reproducible: bool = False,
    argv: list[str] | None = None,
) -> Report:
    """Run checks against an open container and build a deterministic report."""
    from .checks.base import CheckContext

    now = _dt.datetime.now(tz=_dt.UTC).replace(microsecond=0)
    analyzed_at = reference_time if (reproducible and reference_time) else now

    if not container.is_cfb:
        return Report(
            target_name=container.path.name,
            sha256=container.sha256,
            size_bytes=container.size,
            is_cfb=False,
            findings=[],
            analyzed_at=analyzed_at,
            argv=argv or [],
            reproducible=reproducible,
            error="not a Compound File Binary (CFB) container",
        )

    active = checks if checks is not None else registered_checks()
    if select:
        active = [c for c in active if c.id in select]
    if exclude:
        active = [c for c in active if c.id not in exclude]

    ctx = CheckContext(
        container=container,
        reference_time=reference_time or now,
    )

    findings: list[Finding] = []
    for check in active:
        if not check.applies(ctx):
            continue
        findings.extend(check.run(ctx))

    findings.sort(key=lambda f: (-f.severity.rank, f.sort_key()))

    return Report(
        target_name=container.path.name,
        sha256=container.sha256,
        size_bytes=container.size,
        is_cfb=True,
        findings=findings,
        analyzed_at=analyzed_at,
        argv=argv or [],
        reproducible=reproducible,
    )


# Confidence is re-exported for callers that only import the engine.
__all__ = [
    "Report",
    "analyze",
    "register",
    "registered_checks",
    "discover_plugins",
    "Confidence",
    "Severity",
]
