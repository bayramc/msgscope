"""``MsgContainer`` - the single low-level access layer over a ``.msg`` file.

Wraps :mod:`olefile` to expose exactly what the detectors need: per-object MAPI
property tables, the storage/stream tree, directory-entry CLSIDs, computed
absolute byte offsets (FAT vs miniFAT), and raw ``read_at`` access for evidence
snippets.  Detectors consume *only* this class; they never touch ``olefile``
directly.

The container is strictly read-only: the file is opened ``rb`` / memory-mapped
with read access and never written.
"""

from __future__ import annotations

import enum
import hashlib
import mmap
import struct
from dataclasses import dataclass, field
from pathlib import Path

import olefile

from . import properties as P

# CFB special FAT values.
_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF
_MAXREGSECT = 0xFFFFFFFA  # values >= this are reserved/special

_CLSID_OFFSET_IN_DIRENTRY = 0x50
_DIRENTRY_SIZE = 128


class ObjectKind(enum.Enum):
    MESSAGE_TOP = "message"
    MESSAGE_EMBEDDED = "embedded-message"
    RECIPIENT = "recipient"
    ATTACHMENT = "attachment"


_HEADER_SIZE = {
    ObjectKind.MESSAGE_TOP: 32,
    ObjectKind.MESSAGE_EMBEDDED: 24,
    ObjectKind.RECIPIENT: 8,
    ObjectKind.ATTACHMENT: 8,
}


@dataclass(frozen=True)
class PropertyEntry:
    """One 16-byte entry from a ``__properties_version1.0`` stream."""

    tag: int
    flags: int
    value: bytes  # the 8-byte value slot
    entry_index: int  # ordinal within the property table

    @property
    def prop_id(self) -> int:
        return P.tag_id(self.tag)

    @property
    def prop_type(self) -> int:
        return P.tag_type(self.tag)

    def as_uint32(self) -> int:
        return struct.unpack_from("<I", self.value, 0)[0]

    def as_filetime(self) -> int:
        return struct.unpack_from("<Q", self.value, 0)[0]

    @property
    def external_size(self) -> int:
        """For externally-stored properties, the declared data size."""
        return struct.unpack_from("<I", self.value, 0)[0]


@dataclass
class DirEntryInfo:
    """A CFB directory entry, with computed byte offsets for evidence."""

    sid: int
    name: str
    entry_type: int  # olefile.STGTY_*
    clsid: str  # "" when all-zero
    size: int
    isect_start: int  # first sector (FAT) or first mini-sector (miniFAT)
    file_offset: int | None  # absolute offset of the stream's first data byte
    region: str | None  # "FAT" | "miniFAT" | None
    direntry_offset: int | None  # absolute offset of the 128-byte directory entry
    clsid_offset: int | None  # absolute offset of the 16-byte CLSID field

    @property
    def is_storage(self) -> bool:
        return self.entry_type == olefile.STGTY_STORAGE

    @property
    def is_root(self) -> bool:
        return self.entry_type == olefile.STGTY_ROOT

    @property
    def is_stream(self) -> bool:
        return self.entry_type == olefile.STGTY_STREAM


@dataclass
class MsgObject:
    """A MAPI object (message / recipient / attachment) with its property table."""

    kind: ObjectKind
    path: tuple[str, ...]  # storage path; () for the top-level message
    properties: dict[int, PropertyEntry] = field(default_factory=dict)
    properties_stream_offset: int | None = None
    properties_stream_region: str | None = None
    header_bytes: bytes = b""
    # Counts declared in the property-stream header (message objects only).
    declared_recipient_count: int | None = None
    declared_attachment_count: int | None = None
    next_recipient_id: int | None = None
    next_attachment_id: int | None = None
    # Child stream/storage names directly under this object's storage.
    child_substg: list[str] = field(default_factory=list)

    @property
    def path_str(self) -> str:
        return "/" if not self.path else "/" + "/".join(self.path)

    def header_field_offset(self, in_header: int) -> int | None:
        if self.properties_stream_offset is None:
            return None
        return self.properties_stream_offset + in_header


class MsgContainer:
    """Read-only structural view of a ``.msg`` compound file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.size = self.path.stat().st_size
        self.sha256 = _sha256_of(self.path)
        # Handle is held open for the mmap's lifetime and closed in close().
        self._fh = open(self.path, "rb")  # noqa: SIM115
        self._mm: mmap.mmap | None = None
        if self.size > 0:
            self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)

        self.is_cfb = olefile.isOleFile(str(self.path))
        self.objects: list[MsgObject] = []
        self.dir_entries: list[DirEntryInfo] = []
        self._entry_by_path: dict[tuple[str, ...], DirEntryInfo] = {}
        self._children: dict[tuple[str, ...], list[DirEntryInfo]] = {}

        self._ole: olefile.OleFileIO | None = None
        if self.is_cfb:
            self._ole = olefile.OleFileIO(str(self.path))
            self._read_cfb_header()
            self._index_directory()
            self._build_objects()

    # -- lifecycle ----------------------------------------------------------
    def close(self) -> None:
        if self._ole is not None:
            self._ole.close()
            self._ole = None
        if self._mm is not None:
            self._mm.close()
            self._mm = None
        self._fh.close()

    def __enter__(self) -> MsgContainer:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- raw access ---------------------------------------------------------
    def read_at(self, offset: int, n: int) -> bytes:
        """Read *n* raw bytes at absolute *offset* (read-only)."""
        if self._mm is None or offset < 0 or offset >= self.size:
            return b""
        return bytes(self._mm[offset : offset + n])

    def hex_at(self, offset: int | None, n: int = 16) -> str | None:
        if offset is None:
            return None
        data = self.read_at(offset, n)
        return data.hex() if data else None

    # -- CFB geometry -------------------------------------------------------
    def _read_cfb_header(self) -> None:
        hdr = self.read_at(0, 76)
        self._sector_size = 1 << struct.unpack_from("<H", hdr, 0x1E)[0]
        self._mini_sector_size = 1 << struct.unpack_from("<H", hdr, 0x20)[0]
        self._first_dir_sector = struct.unpack_from("<I", hdr, 0x30)[0]
        self._mini_cutoff = struct.unpack_from("<I", hdr, 0x38)[0]
        assert self._ole is not None
        self._fat = self._ole.fat
        self._root_start = self._ole.root.isectStart

    def _sector_offset(self, sect: int) -> int:
        return (sect + 1) * self._sector_size

    def _follow_chain(self, start: int, limit: int = 1_000_000) -> list[int]:
        chain: list[int] = []
        seen: set[int] = set()
        cur = start
        while cur < _MAXREGSECT and cur not in seen and len(chain) < limit:
            if cur >= len(self._fat):
                break
            seen.add(cur)
            chain.append(cur)
            cur = self._fat[cur]
        return chain

    def _stream_offset(self, isect_start: int, size: int) -> tuple[int | None, str | None]:
        """Absolute file offset of a stream's first byte, plus its region."""
        if size == 0 or isect_start >= _MAXREGSECT:
            return None, None
        if size >= self._mini_cutoff:
            return self._sector_offset(isect_start), "FAT"
        # Mini stream: data lives inside the root entry's regular-FAT chain.
        byte_in_mini = isect_start * self._mini_sector_size
        root_chain = self._follow_chain(self._root_start)
        big_index = byte_in_mini // self._sector_size
        within = byte_in_mini % self._sector_size
        if big_index >= len(root_chain):
            return None, "miniFAT"
        return self._sector_offset(root_chain[big_index]) + within, "miniFAT"

    def _minifat(self) -> list[int]:
        assert self._ole is not None
        mf = getattr(self._ole, "minifat", None)
        if not mf:
            self._ole.loadminifat()
            mf = self._ole.minifat
        return mf or []

    def _follow_mini_chain(self, start: int, limit: int = 1_000_000) -> list[int]:
        minifat = self._minifat()
        chain: list[int] = []
        seen: set[int] = set()
        cur = start
        while cur < _MAXREGSECT and cur not in seen and len(chain) < limit:
            if cur >= len(minifat):
                break
            seen.add(cur)
            chain.append(cur)
            cur = minifat[cur]
        return chain

    def stream_offset_at(
        self, path: tuple[str, ...], logical: int
    ) -> tuple[int | None, str | None]:
        """Absolute file offset of *logical* byte position inside a stream.

        Correctly follows the FAT or mini-FAT sector chain, so it is accurate
        even for fragmented streams.
        """
        info = self._entry_by_path.get(path)
        if info is None or info.size == 0 or logical < 0 or logical >= info.size:
            return None, info.region if info else None
        if info.size >= self._mini_cutoff:
            chain = self._follow_chain(info.isect_start)
            idx, within = divmod(logical, self._sector_size)
            if idx >= len(chain):
                return None, "FAT"
            return self._sector_offset(chain[idx]) + within, "FAT"
        mini_chain = self._follow_mini_chain(info.isect_start)
        midx, mwithin = divmod(logical, self._mini_sector_size)
        if midx >= len(mini_chain):
            return None, "miniFAT"
        byte_in_mini = mini_chain[midx] * self._mini_sector_size + mwithin
        root_chain = self._follow_chain(self._root_start)
        bidx, bwithin = divmod(byte_in_mini, self._sector_size)
        if bidx >= len(root_chain):
            return None, "miniFAT"
        return self._sector_offset(root_chain[bidx]) + bwithin, "miniFAT"

    def header_field_offset(self, obj: MsgObject, in_header: int) -> int | None:
        return self.stream_offset_at((*obj.path, P.PROPERTIES_STREAM), in_header)[0]

    def prop_entry_offset(self, obj: MsgObject, entry: PropertyEntry) -> int | None:
        header = _HEADER_SIZE[obj.kind]
        logical = header + entry.entry_index * 16
        return self.stream_offset_at((*obj.path, P.PROPERTIES_STREAM), logical)[0]

    def prop_value_offset(self, obj: MsgObject, entry: PropertyEntry) -> int | None:
        header = _HEADER_SIZE[obj.kind]
        logical = header + entry.entry_index * 16 + 8
        return self.stream_offset_at((*obj.path, P.PROPERTIES_STREAM), logical)[0]

    def _direntry_offset(self, sid: int) -> int | None:
        chain = self._follow_chain(self._first_dir_sector)
        per_sector = self._sector_size // _DIRENTRY_SIZE
        sect_index = sid // per_sector
        within = (sid % per_sector) * _DIRENTRY_SIZE
        if sect_index >= len(chain):
            return None
        return self._sector_offset(chain[sect_index]) + within

    # -- directory indexing -------------------------------------------------
    def _index_directory(self) -> None:
        assert self._ole is not None
        self._walk_entry(self._ole.root, ())

    def _walk_entry(self, entry: object, prefix: tuple[str, ...]) -> None:
        # entry is an olefile.OleDirectoryEntry
        sid = getattr(entry, "sid", -1)
        name = getattr(entry, "name", "")
        is_root = prefix == () and getattr(entry, "entry_type", None) == olefile.STGTY_ROOT
        path = () if is_root else (*prefix, name)

        clsid = getattr(entry, "clsid", "") or ""
        if clsid in ("00000000-0000-0000-0000-000000000000",):
            clsid = ""
        size = int(getattr(entry, "size", 0) or 0)
        isect = getattr(entry, "isectStart", _ENDOFCHAIN)
        direntry_offset = self._direntry_offset(sid) if sid >= 0 else None
        clsid_offset = (
            direntry_offset + _CLSID_OFFSET_IN_DIRENTRY if direntry_offset is not None else None
        )
        file_offset, region = self._stream_offset(isect, size)

        info = DirEntryInfo(
            sid=sid,
            name=name,
            entry_type=int(getattr(entry, "entry_type", 0) or 0),
            clsid=clsid,
            size=size,
            isect_start=isect,
            file_offset=file_offset,
            region=region,
            direntry_offset=direntry_offset,
            clsid_offset=clsid_offset,
        )
        self.dir_entries.append(info)
        self._entry_by_path[path] = info
        self._children.setdefault(prefix, [])
        if not is_root:
            self._children[prefix].append(info)

        for kid in getattr(entry, "kids", []) or []:
            self._walk_entry(kid, path)

    def children_of(self, path: tuple[str, ...]) -> list[DirEntryInfo]:
        return self._children.get(path, [])

    def entry(self, path: tuple[str, ...]) -> DirEntryInfo | None:
        return self._entry_by_path.get(path)

    # -- object / property parsing -----------------------------------------
    def _build_objects(self) -> None:
        # Top-level message object.
        self.objects.append(self._make_object(ObjectKind.MESSAGE_TOP, ()))
        # Recipients, attachments, and embedded messages anywhere in the tree.
        for path, info in sorted(self._entry_by_path.items()):
            if info.entry_type != olefile.STGTY_STORAGE:
                continue
            name = path[-1]
            if name.startswith(P.RECIP_PREFIX):
                self.objects.append(self._make_object(ObjectKind.RECIPIENT, path))
            elif name.startswith(P.ATTACH_PREFIX):
                self.objects.append(self._make_object(ObjectKind.ATTACHMENT, path))
            elif name == P.substg_name(P.make_tag(0x3701, P.PTYP_OBJECT)):
                # __substg1.0_3701000D : an embedded message inside an attachment.
                self.objects.append(self._make_object(ObjectKind.MESSAGE_EMBEDDED, path))

    def _make_object(self, kind: ObjectKind, path: tuple[str, ...]) -> MsgObject:
        obj = MsgObject(kind=kind, path=path)
        obj.child_substg = [c.name for c in self.children_of(path)]

        prop_path = (*path, P.PROPERTIES_STREAM)
        info = self._entry_by_path.get(prop_path)
        if info is None:
            return obj
        obj.properties_stream_offset = info.file_offset
        obj.properties_stream_region = info.region

        data = self._read_stream(prop_path)
        if data is None:
            return obj
        header_size = _HEADER_SIZE[kind]
        obj.header_bytes = data[:header_size]
        if (
            kind in (ObjectKind.MESSAGE_TOP, ObjectKind.MESSAGE_EMBEDDED)
            and len(data) >= header_size
        ):
            # Reserved(8) NextRecipId(4) NextAttachId(4) RecipCount(4) AttachCount(4)
            (
                obj.next_recipient_id,
                obj.next_attachment_id,
                obj.declared_recipient_count,
                obj.declared_attachment_count,
            ) = struct.unpack_from("<IIII", data, 8)

        body = data[header_size:]
        for i in range(0, len(body) - 15, 16):
            tag, flags = struct.unpack_from("<II", body, i)
            value = body[i + 8 : i + 16]
            entry = PropertyEntry(tag=tag, flags=flags, value=value, entry_index=i // 16)
            obj.properties[tag] = entry
        return obj

    def _read_stream(self, path: tuple[str, ...]) -> bytes | None:
        if self._ole is None:
            return None
        try:
            with self._ole.openstream(list(path)) as fh:
                return fh.read()
        except (OSError, ValueError, KeyError):
            return None

    # -- convenience accessors ---------------------------------------------
    def top(self) -> MsgObject:
        return self.objects[0]

    def recipients(self) -> list[MsgObject]:
        return [o for o in self.objects if o.kind == ObjectKind.RECIPIENT]

    def attachments(self) -> list[MsgObject]:
        return [o for o in self.objects if o.kind == ObjectKind.ATTACHMENT]

    def recipient_storage_names(self) -> list[str]:
        return sorted(
            c.name
            for c in self.children_of(())
            if c.name.startswith(P.RECIP_PREFIX) and c.entry_type == olefile.STGTY_STORAGE
        )

    def attachment_storage_names(self) -> list[str]:
        return sorted(
            c.name
            for c in self.children_of(())
            if c.name.startswith(P.ATTACH_PREFIX) and c.entry_type == olefile.STGTY_STORAGE
        )

    def nameid_storage(self) -> DirEntryInfo | None:
        return self._entry_by_path.get((P.NAMEID_STORAGE,))

    def read_substg(self, obj: MsgObject, tag: int) -> bytes | None:
        """Read the ``__substg1.0_`` stream backing *tag* under *obj*, if present."""
        name = P.substg_name(tag)
        if name not in obj.child_substg:
            return None
        return self._read_stream((*obj.path, name))

    def read_named_stream(self, storage: tuple[str, ...], name: str) -> bytes | None:
        return self._read_stream((*storage, name))


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
