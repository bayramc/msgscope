"""Built-in detectors.

Importing this package registers every built-in check with the engine.  Each
detector is a small, independent module implementing :class:`base.Check`.
"""

from __future__ import annotations

from .. import engine
from .attach_oleguid import AttachOleGuidCheck
from .base import Check, CheckContext
from .codepage_mismatch import CodepageMismatchCheck
from .filetime_sanity import FiletimeSanityCheck
from .header_counts import HeaderCountsCheck
from .message_flags import MessageFlagsCheck
from .nameid_integrity import NameIdIntegrityCheck
from .orphan_substg import OrphanSubstgCheck

BUILTIN_CHECKS: list[type[Check]] = [
    OrphanSubstgCheck,
    HeaderCountsCheck,
    MessageFlagsCheck,
    FiletimeSanityCheck,
    NameIdIntegrityCheck,
    AttachOleGuidCheck,
    CodepageMismatchCheck,
]


def register_builtins() -> None:
    for cls in BUILTIN_CHECKS:
        engine.register(cls())


register_builtins()

__all__ = ["Check", "CheckContext", "BUILTIN_CHECKS", "register_builtins"]
