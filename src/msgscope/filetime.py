"""Windows FILETIME helpers.

A FILETIME is a 64-bit unsigned count of 100-nanosecond intervals since
1601-01-01 00:00:00 UTC.  ``.msg`` files store ``PtypTime`` values as a FILETIME
in the 8-byte property-entry value slot.
"""

from __future__ import annotations

import datetime as _dt

# 100-ns ticks per second.
_TICKS_PER_SECOND = 10_000_000
_EPOCH = _dt.datetime(1601, 1, 1, tzinfo=_dt.UTC)

# Sentinels used by MAPI to mean "no value".
FILETIME_NULL = 0
FILETIME_MAX = 0xFFFFFFFFFFFFFFFF

# datetime can only represent up to year 9999; ticks past this overflow.
_MAX_REPRESENTABLE_TICKS = int(
    (_dt.datetime(9999, 12, 31, 23, 59, 59, tzinfo=_dt.UTC) - _EPOCH).total_seconds()
    * _TICKS_PER_SECOND
)


def is_null(ticks: int) -> bool:
    """True for the conventional unset markers (0 and all-ones)."""
    return ticks in (FILETIME_NULL, FILETIME_MAX)


def is_representable(ticks: int) -> bool:
    """True if *ticks* maps to a real ``datetime`` (within year 1..9999)."""
    return 0 <= ticks <= _MAX_REPRESENTABLE_TICKS


def to_datetime(ticks: int) -> _dt.datetime | None:
    """Convert FILETIME ticks to a timezone-aware UTC ``datetime``.

    Returns ``None`` for null markers or values outside the representable range.
    """
    if is_null(ticks) or not is_representable(ticks):
        return None
    return _EPOCH + _dt.timedelta(microseconds=ticks / 10)


def from_datetime(dt: _dt.datetime) -> int:
    """Convert a ``datetime`` to FILETIME ticks (assumes UTC if naive)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.UTC)
    delta = dt - _EPOCH
    return int(delta.total_seconds() * _TICKS_PER_SECOND)


def format_ticks(ticks: int) -> str:
    """Human-readable rendering for evidence strings."""
    if ticks == FILETIME_NULL:
        return "0 (null)"
    if ticks == FILETIME_MAX:
        return "0xFFFFFFFFFFFFFFFF (null)"
    dt = to_datetime(ticks)
    if dt is None:
        return f"{ticks} ticks (out of range)"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
