#!/usr/bin/env python3
"""Tamper with an existing ``.msg`` file to see msgscope catch the edit.

This simulates a realistic scenario: someone alters a genuine message in place.
It copies the input to a new file and edits a single fixed-size property value in
the copy (same-size overwrite via olefile), leaving the ORIGINAL untouched.

    python scripts/tamper_msg.py --in real.msg --out tampered.msg --mutation set-hasattach
    msgscope inspect tampered.msg

Mutations:
  set-hasattach     force the HASATTACH flag on (fires MSGFLAGS if no attachments)
  future-delivery   set the delivery time to the year 2999 (fires FILETIME_SANITY)
  reverse-times     set creation after last-modification (fires FILETIME_SANITY)
"""

from __future__ import annotations

import argparse
import datetime as _dt
import shutil
import struct
import sys
from pathlib import Path

import olefile

from msgscope import filetime as FT
from msgscope import properties as P

_TOP_HEADER = 32  # top-level message property-stream header size
_PROPS = [P.PROPERTIES_STREAM]


def _load_props(ole: olefile.OleFileIO) -> bytearray:
    with ole.openstream(_PROPS) as fh:
        return bytearray(fh.read())


def _find_entry(data: bytearray, tag: int) -> int | None:
    """Return the byte offset of the 16-byte entry for *tag*, or None."""
    for off in range(_TOP_HEADER, len(data) - 15, 16):
        if struct.unpack_from("<I", data, off)[0] == tag:
            return off
    return None


def _set_value(data: bytearray, tag: int, value8: bytes) -> bool:
    off = _find_entry(data, tag)
    if off is None:
        return False
    data[off + 8 : off + 16] = value8.ljust(8, b"\x00")[:8]
    return True


def _mutate(data: bytearray, mutation: str) -> str:
    if mutation == "set-hasattach":
        off = _find_entry(data, P.PidTagMessageFlags)
        if off is None:
            return "message has no PidTagMessageFlags to modify"
        flags = struct.unpack_from("<I", data, off + 8)[0]
        _set_value(data, P.PidTagMessageFlags, struct.pack("<I", flags | P.MSGFLAG_HASATTACH))
        return f"flags 0x{flags:08X} -> 0x{flags | P.MSGFLAG_HASATTACH:08X} (HASATTACH set)"
    if mutation == "future-delivery":
        ticks = FT.from_datetime(_dt.datetime(2999, 1, 1, tzinfo=_dt.UTC))
        if not _set_value(data, P.PidTagMessageDeliveryTime, struct.pack("<Q", ticks)):
            return "message has no PidTagMessageDeliveryTime to modify"
        return "delivery time set to 2999-01-01"
    if mutation == "reverse-times":
        late = FT.from_datetime(_dt.datetime(2999, 1, 1, tzinfo=_dt.UTC))
        early = FT.from_datetime(_dt.datetime(2000, 1, 1, tzinfo=_dt.UTC))
        ok_c = _set_value(data, P.PidTagCreationTime, struct.pack("<Q", late))
        ok_m = _set_value(data, P.PidTagLastModificationTime, struct.pack("<Q", early))
        if not (ok_c and ok_m):
            return "message lacks creation/last-modification times to modify"
        return "creation set after last-modification"
    return f"unknown mutation: {mutation}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--in", dest="inp", required=True, help="input .msg (never modified)")
    parser.add_argument("--out", required=True, help="output .msg (the tampered copy)")
    parser.add_argument(
        "--mutation",
        default="set-hasattach",
        choices=("set-hasattach", "future-delivery", "reverse-times"),
    )
    args = parser.parse_args(argv)

    src = Path(args.inp)
    if not olefile.isOleFile(str(src)):
        print(f"error: {src} is not a .msg (CFB) file", file=sys.stderr)
        return 3

    dst = Path(args.out)
    shutil.copyfile(src, dst)  # work on a copy; never touch the input

    ole = olefile.OleFileIO(str(dst), write_mode=True)
    try:
        data = _load_props(ole)
        note = _mutate(data, args.mutation)
        # write_stream requires the same size — every mutation above is in-place.
        ole.write_stream(_PROPS, bytes(data))
    finally:
        ole.close()

    print(f"Wrote {dst}  ({note})")
    print(f"Original {src} is unchanged.")
    print(f"Try:  msgscope inspect {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
