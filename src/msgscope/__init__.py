"""msgscope - MSG structural-integrity / tamper inspector.

A read-only forensic inspector for Outlook ``.msg`` (MS-OXMSG / Compound File
Binary) files.  It reports *indicators* with severity, confidence, and evidence
- never a verdict.  A human examiner draws the conclusion.
"""

from __future__ import annotations

from importlib import metadata

try:
    __version__ = metadata.version("msgscope")
except metadata.PackageNotFoundError:  # pragma: no cover - source checkout
    __version__ = "0.1.0"

__all__ = ["__version__"]
