#!/usr/bin/env python3
"""Generate a labeled set of *synthetic, tampered* ``.msg`` files.

Each file starts from a well-formed baseline and has exactly one anomaly
injected, so you can watch a specific detector fire:

    python scripts/make_synthetic.py --out corpus/synthetic
    msgscope inspect corpus/synthetic/*.msg

The files contain no personal data. They are built with the same in-repo CFB
writer the test suite uses.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import struct
import sys
from pathlib import Path

# Make tests/fixtures importable when run from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from fixtures.builders import good_message  # type: ignore[import-not-found]  # noqa: E402
from msgscope import properties as P  # noqa: E402


def orphan_stream() -> bytes:
    """A data stream the property table does not list -> ORPHAN_SUBSTG."""
    m = good_message()
    m.add_stream("__substg1.0_80050102", b"data not indexed by the property table")
    return m.build_bytes()


def bad_recipient_count() -> bytes:
    """Header claims more recipients than are stored -> HEADER_COUNTS."""
    m = good_message()  # one real recipient
    m.recip_count_override = 4
    return m.build_bytes()


def impossible_flags() -> bytes:
    """HASATTACH set with no attachments present -> MSGFLAGS."""
    m = good_message()
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | P.MSGFLAG_HASATTACH)
    return m.build_bytes()


def future_timestamp() -> bytes:
    """A delivery time centuries in the future -> FILETIME_SANITY."""
    m = good_message()
    m.set(P.PidTagMessageDeliveryTime, _dt.datetime(2999, 1, 1, tzinfo=_dt.UTC))
    return m.build_bytes()


def broken_nameid() -> bytes:
    """A malformed named-property GUID table -> NAMEID_INTEGRITY."""
    m = good_message()
    m.set_nameid(guid=b"\x00" * 17, entry=b"", string=b"")  # 17 is not a multiple of 16
    return m.build_bytes()


def unexpected_clsid() -> bytes:
    """An unexpected program identifier on the root storage -> ATTACH_OLEGUID."""
    m = good_message()
    m.root_clsid = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    return m.build_bytes()


def codepage_mismatch() -> bytes:
    """ANSI body that cannot decode under the declared UTF-8 codepage."""
    m = good_message()
    m.set(P.PidTagInternetCodepage, 65001)  # UTF-8
    m.set_raw(P.PidTagBodyA, struct.pack("<I", 2) + b"\x00" * 4, substg_data=b"\xff\xfe")
    return m.build_bytes()


CASES: list[tuple[str, str, str]] = [
    ("orphan_stream.msg", "ORPHAN_SUBSTG", "orphan substorage stream"),
    ("bad_recipient_count.msg", "HEADER_COUNTS", "header recipient count mismatch"),
    ("impossible_flags.msg", "MSGFLAGS", "HASATTACH set, no attachments"),
    ("future_timestamp.msg", "FILETIME_SANITY", "delivery time in year 2999"),
    ("broken_nameid.msg", "NAMEID_INTEGRITY", "malformed GUID table"),
    ("unexpected_clsid.msg", "ATTACH_OLEGUID", "unexpected root CLSID"),
    ("codepage_mismatch.msg", "CODEPAGE_MISMATCH", "ANSI body vs UTF-8 codepage"),
]

_BUILDERS = {
    "orphan_stream.msg": orphan_stream,
    "bad_recipient_count.msg": bad_recipient_count,
    "impossible_flags.msg": impossible_flags,
    "future_timestamp.msg": future_timestamp,
    "broken_nameid.msg": broken_nameid,
    "unexpected_clsid.msg": unexpected_clsid,
    "codepage_mismatch.msg": codepage_mismatch,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="corpus/synthetic", help="output directory")
    args = parser.parse_args(argv)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    print(f"{'file':28} {'expects':18} anomaly")
    print("-" * 72)
    for filename, expected, description in CASES:
        (out / filename).write_bytes(_BUILDERS[filename]())
        print(f"{filename:28} {expected:18} {description}")

    print(f"\nWrote {len(CASES)} files to {out}/")
    print(f"Try:  msgscope inspect {out}/orphan_stream.msg")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
