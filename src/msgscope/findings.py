"""Finding data model.

A *finding* is an indicator, never a verdict.  It carries a categorical severity
and confidence, plain-language explanation, and the concrete evidence (which
object/stream, byte offset, observed vs expected) so a human examiner can verify
it.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(enum.Enum):
    """How structurally significant the anomaly is (not how likely tampering)."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class Confidence(enum.Enum):
    """How sure the detector is that the observation is a true anomaly."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANK[self]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
}
_CONFIDENCE_RANK = {
    Confidence.LOW: 0,
    Confidence.MEDIUM: 1,
    Confidence.HIGH: 2,
}

# Accept case-insensitive names from the CLI (e.g. ``--fail-on high``).
SEVERITY_BY_NAME = {s.value: s for s in Severity}


@dataclass(frozen=True)
class Evidence:
    """Where and what: the verifiable basis for a finding."""

    object_path: str
    observed: str
    expected: str
    stream: str | None = None
    byte_offset: int | None = None
    region: str | None = None  # "FAT" | "miniFAT" | "directory" | None
    directory_index: int | None = None
    raw_hex: str | None = None

    def sort_key(self) -> tuple[str, int, str]:
        return (
            self.object_path,
            self.byte_offset if self.byte_offset is not None else -1,
            self.stream or "",
        )


@dataclass(frozen=True)
class Finding:
    """A single reported indicator."""

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    summary_plain: str
    why_it_matters: str
    evidence: Evidence
    spec_reference: str = ""
    # Optional tie-breaker so multiple findings from one check sort stably.
    detail_key: str = field(default="")

    def sort_key(self) -> tuple:
        return (self.id, *self.evidence.sort_key(), self.detail_key)
