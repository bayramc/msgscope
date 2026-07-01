"""A minimal Compound File Binary (CFB v3) writer for test fixtures.

No maintained pure-Python CFB *writer* exists (olefile is read-only), yet the
tamper checks need byte-precise containers with deliberately injected anomalies.
This writer produces valid CFB files that ``olefile`` reads back, using 512-byte
sectors, 64-byte mini-sectors and a 4096-byte mini-stream cutoff (matching real
``.msg`` files).

It is intentionally small and only covers what fixtures need; it is not a
general-purpose CFB library.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field

SECTOR = 512
MINI = 64
MINI_CUTOFF = 4096
ENTRIES_PER_FAT_SECTOR = SECTOR // 4  # 128
DIR_ENTRIES_PER_SECTOR = SECTOR // 128  # 4

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
NOSTREAM = 0xFFFFFFFF

STGTY_EMPTY = 0
STGTY_STORAGE = 1
STGTY_STREAM = 2
STGTY_ROOT = 5

ZERO_CLSID = b"\x00" * 16


@dataclass
class Stream:
    name: str
    data: bytes
    clsid: bytes = ZERO_CLSID


@dataclass
class Storage:
    name: str
    children: list = field(default_factory=list)  # list[Stream | Storage]
    clsid: bytes = ZERO_CLSID


@dataclass
class _Rec:
    sid: int
    name: str
    etype: int
    clsid: bytes
    data: bytes = b""
    left: int = NOSTREAM
    right: int = NOSTREAM
    child: int = NOSTREAM
    isect_start: int = ENDOFCHAIN
    size: int = 0


def _cfb_key(name: str) -> tuple[int, str]:
    # CFB sibling order: by UTF-16 code-unit length, then case-insensitive name.
    return (len(name), name.upper())


class _Writer:
    def __init__(self, root_children: list, root_clsid: bytes) -> None:
        self.records: list[_Rec] = []
        root = self._alloc("Root Entry", STGTY_ROOT, root_clsid)
        root.child = self._build_children(root_children)

    def _alloc(self, name: str, etype: int, clsid: bytes, data: bytes = b"") -> _Rec:
        rec = _Rec(sid=len(self.records), name=name, etype=etype, clsid=clsid, data=data)
        self.records.append(rec)
        return rec

    def _build_children(self, children: list) -> int:
        recs: list[_Rec] = []
        pending: list[tuple[_Rec, list]] = []
        for child in children:
            if isinstance(child, Storage):
                rec = self._alloc(child.name, STGTY_STORAGE, child.clsid)
                pending.append((rec, child.children))
            else:
                rec = self._alloc(child.name, STGTY_STREAM, child.clsid, child.data)
            recs.append(rec)
        root_sid = self._build_bst(sorted(recs, key=lambda r: _cfb_key(r.name)))
        for rec, kids in pending:
            rec.child = self._build_children(kids)
        return root_sid

    def _build_bst(self, recs: list[_Rec]) -> int:
        if not recs:
            return NOSTREAM
        mid = len(recs) // 2
        node = recs[mid]
        node.left = self._build_bst(recs[:mid])
        node.right = self._build_bst(recs[mid + 1 :])
        return node.sid

    def to_bytes(self) -> bytes:
        sectors: list[bytes] = []
        fat: list[int] = []

        def add_chain(data: bytes) -> int:
            if not data:
                return ENDOFCHAIN
            n = math.ceil(len(data) / SECTOR)
            padded = data.ljust(n * SECTOR, b"\x00")
            start = len(sectors)
            for j in range(n):
                sectors.append(padded[j * SECTOR : (j + 1) * SECTOR])
                fat.append(start + j + 1 if j < n - 1 else ENDOFCHAIN)
            return start

        streams = [r for r in self.records if r.etype == STGTY_STREAM]

        # 1. Big streams (>= mini cutoff) go straight into the FAT.
        for rec in streams:
            if len(rec.data) >= MINI_CUTOFF:
                rec.isect_start = add_chain(rec.data)
                rec.size = len(rec.data)

        # 2. Mini stream + mini FAT for the small streams.
        mini_data = bytearray()
        minifat: list[int] = []
        for rec in streams:
            size = len(rec.data)
            if 0 < size < MINI_CUTOFF:
                n = math.ceil(size / MINI)
                start_mini = len(minifat)
                for j in range(n):
                    minifat.append(start_mini + j + 1 if j < n - 1 else ENDOFCHAIN)
                rec.isect_start = start_mini
                rec.size = size
                mini_data += rec.data.ljust(n * MINI, b"\x00")
            elif size == 0:
                rec.isect_start = ENDOFCHAIN
                rec.size = 0

        root = self.records[0]
        root.isect_start = add_chain(bytes(mini_data)) if mini_data else ENDOFCHAIN
        root.size = len(mini_data)

        if minifat:
            minifat_bytes = b"".join(struct.pack("<I", x) for x in minifat)
            first_minifat = add_chain(minifat_bytes)
            n_minifat = math.ceil(len(minifat_bytes) / SECTOR)
        else:
            first_minifat = ENDOFCHAIN
            n_minifat = 0

        # 3. Directory.
        dir_bytes = b"".join(self._dir_entry(r) for r in self.records)
        n_dir_entries = len(self.records)
        pad_entries = (-n_dir_entries) % DIR_ENTRIES_PER_SECTOR
        dir_bytes += self._empty_dir_entry() * pad_entries
        first_dir = add_chain(dir_bytes)

        # 4. FAT sectors (fixpoint: FAT must also describe itself).
        content = len(sectors)
        f = 1
        while True:
            need = math.ceil((content + f) / ENTRIES_PER_FAT_SECTOR)
            if need == f:
                break
            f = need
        if f > 109:  # pragma: no cover - fixtures stay tiny
            raise ValueError("fixture too large for header DIFAT")

        full_fat = [FREESECT] * (f * ENTRIES_PER_FAT_SECTOR)
        full_fat[:content] = fat
        for i in range(f):
            full_fat[content + i] = FATSECT
        fat_bytes = b"".join(struct.pack("<I", x) for x in full_fat)
        for j in range(f):
            sectors.append(fat_bytes[j * SECTOR : (j + 1) * SECTOR])
        difat = [content + i for i in range(f)]

        header = self._header(first_dir, f, first_minifat, n_minifat, difat)
        return header + b"".join(sectors)

    def _dir_entry(self, rec: _Rec) -> bytes:
        name = rec.name.encode("utf-16-le") + b"\x00\x00"
        name_len = len(name)
        name_field = name.ljust(64, b"\x00")
        return (
            name_field
            + struct.pack("<H", name_len)
            + struct.pack("<BB", rec.etype, 1)  # color = black
            + struct.pack("<III", rec.left, rec.right, rec.child)
            + rec.clsid
            + struct.pack("<I", 0)  # state
            + struct.pack("<Q", 0)  # create time
            + struct.pack("<Q", 0)  # modify time
            + struct.pack("<I", rec.isect_start)
            + struct.pack("<Q", rec.size)
        )

    def _empty_dir_entry(self) -> bytes:
        return (
            b"\x00" * 64
            + struct.pack("<H", 0)
            + struct.pack("<BB", STGTY_EMPTY, 0)
            + struct.pack("<III", NOSTREAM, NOSTREAM, NOSTREAM)
            + ZERO_CLSID
            + struct.pack("<I", 0)
            + struct.pack("<Q", 0)
            + struct.pack("<Q", 0)
            + struct.pack("<I", ENDOFCHAIN)
            + struct.pack("<Q", 0)
        )

    def _header(
        self,
        first_dir: int,
        n_fat: int,
        first_minifat: int,
        n_minifat: int,
        difat: list[int],
    ) -> bytes:
        difat_field = list(difat) + [FREESECT] * (109 - len(difat))
        return (
            b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
            + ZERO_CLSID
            + struct.pack("<H", 0x003E)  # minor version
            + struct.pack("<H", 0x0003)  # major version (v3)
            + struct.pack("<H", 0xFFFE)  # byte order
            + struct.pack("<H", 9)  # sector shift -> 512
            + struct.pack("<H", 6)  # mini sector shift -> 64
            + b"\x00" * 6  # reserved
            + struct.pack("<I", 0)  # number of directory sectors (v3 = 0)
            + struct.pack("<I", n_fat)
            + struct.pack("<I", first_dir)
            + struct.pack("<I", 0)  # transaction signature
            + struct.pack("<I", MINI_CUTOFF)
            + struct.pack("<I", first_minifat)
            + struct.pack("<I", n_minifat)
            + struct.pack("<I", ENDOFCHAIN)  # first DIFAT sector
            + struct.pack("<I", 0)  # number of DIFAT sectors
            + b"".join(struct.pack("<I", x) for x in difat_field)
        )


def write_cfb(root_children: list, root_clsid: bytes = ZERO_CLSID) -> bytes:
    """Serialize a directory tree (``Storage`` / ``Stream``) into CFB bytes."""
    return _Writer(root_children, root_clsid).to_bytes()
