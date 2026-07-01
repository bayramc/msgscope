"""The ``Check`` interface every detector implements.

A check is a small, self-contained detector.  It receives a :class:`CheckContext`
(the parsed container plus run parameters) and yields :class:`Finding` objects.
Checks must be pure readers and must not mutate the container or the file.
"""

from __future__ import annotations

import datetime as _dt
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass

from ..container import MsgContainer
from ..findings import Finding, Severity


@dataclass
class CheckContext:
    """Everything a check needs to run, injected for testability."""

    container: MsgContainer
    reference_time: _dt.datetime


class Check(ABC):
    """Base class for all detectors."""

    #: Stable identifier used in JSON output and ``--checks`` selection.
    id: str = ""
    #: Short human title.
    title: str = ""
    #: Default severity; individual findings may override.
    default_severity: Severity = Severity.MEDIUM

    def applies(self, ctx: CheckContext) -> bool:  # noqa: ARG002
        """Whether this check is relevant to the given container."""
        return True

    @abstractmethod
    def run(self, ctx: CheckContext) -> Iterable[Finding]:
        """Inspect the container and yield findings (possibly none)."""
        raise NotImplementedError
