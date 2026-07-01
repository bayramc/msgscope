"""Assemble ``.msg`` fixtures (well-formed and deliberately anomalous).

Built on :mod:`cfb_writer`, these builders encode MAPI property tables, recipient
and attachment storages, and the named-property map, with escape hatches so each
test can inject exactly one anomaly (an orphan stream, a bad count, a reversed
timestamp, ...) while keeping everything else valid.
"""

from __future__ import annotations

import datetime as _dt
import struct

from msgscope import filetime as FT
from msgscope import properties as P

from .cfb_writer import ZERO_CLSID, Storage, Stream, write_cfb

# (value_slot_bytes, substg_data or None)
_Encoded = tuple[bytes, bytes | None]

_ATTACH_DATA_OBJECT = P.make_tag(0x3701, P.PTYP_OBJECT)  # 0x3701000D


def encode_value(tag: int, value: object) -> _Encoded:
    """Encode a python value into the 8-byte slot and optional substg data."""
    ptype = P.tag_type(tag)
    if ptype in (P.PTYP_INTEGER32, P.PTYP_ERRORCODE):
        return struct.pack("<I", int(value) & 0xFFFFFFFF) + b"\x00" * 4, None
    if ptype == P.PTYP_INTEGER16:
        return struct.pack("<H", int(value) & 0xFFFF) + b"\x00" * 6, None
    if ptype == P.PTYP_BOOLEAN:
        return struct.pack("<H", 1 if value else 0) + b"\x00" * 6, None
    if ptype == P.PTYP_INTEGER64:
        return struct.pack("<Q", int(value)), None
    if ptype == P.PTYP_TIME:
        ticks = value if isinstance(value, int) else FT.from_datetime(value)  # type: ignore[arg-type]
        return struct.pack("<Q", ticks & 0xFFFFFFFFFFFFFFFF), None
    if ptype == P.PTYP_FLOATING64:
        return struct.pack("<d", float(value)), None

    # External (stored in a __substg1.0_ stream).
    data = _encode_external(ptype, value)
    return struct.pack("<I", len(data)) + b"\x00" * 4, data


def _encode_external(ptype: int, value: object) -> bytes:
    if ptype == P.PTYP_STRING:  # Unicode
        return str(value).encode("utf-16-le")
    if ptype == P.PTYP_STRING8:  # ANSI-ish
        if isinstance(value, bytes):
            return value
        return str(value).encode("latin-1", "replace")
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


class ObjectBuilder:
    """Common base for the message, recipients, and attachments."""

    def __init__(self) -> None:
        # tag -> (value_slot, substg_data | None); insertion order preserved.
        self.entries: dict[int, _Encoded] = {}
        self.extra_streams: list[tuple[str, bytes]] = []
        self.extra_storages: list[Storage] = []

    def set(self, tag: int, value: object) -> ObjectBuilder:
        self.entries[tag] = encode_value(tag, value)
        return self

    def set_raw(
        self, tag: int, value_slot: bytes, substg_data: bytes | None = None
    ) -> ObjectBuilder:
        """Set an entry directly. For an external type, pass ``substg_data=None``
        to create a dangling reference (entry present, stream absent)."""
        self.entries[tag] = (value_slot.ljust(8, b"\x00")[:8], substg_data)
        return self

    def add_stream(self, name: str, data: bytes = b"x") -> ObjectBuilder:
        """Add a raw child stream (e.g. an orphan ``__substg1.0_`` stream)."""
        self.extra_streams.append((name, data))
        return self

    def _property_children(self, header: bytes) -> list:
        body = b""
        substreams: list[Stream] = []
        for tag in sorted(self.entries):
            value_slot, substg = self.entries[tag]
            body += struct.pack("<II", tag, 0x06) + value_slot  # flags: readable|writable
            if substg is not None:
                substreams.append(Stream(P.substg_name(tag), substg))
        children: list = [Stream(P.PROPERTIES_STREAM, header + body)]
        children.extend(substreams)
        children.extend(Stream(name, data) for name, data in self.extra_streams)
        children.extend(self.extra_storages)
        return children


class RecipientBuilder(ObjectBuilder):
    def children(self) -> list:
        return self._property_children(b"\x00" * 8)


class AttachmentBuilder(ObjectBuilder):
    def __init__(self) -> None:
        super().__init__()
        self.clsid = ZERO_CLSID
        self.embedded: MessageBuilder | None = None

    def children(self) -> list:
        extra: list = []
        if self.embedded is not None:
            # Reference the embedded message object and store it as a sub-storage.
            self.set_raw(_ATTACH_DATA_OBJECT, struct.pack("<I", 1) + b"\x00" * 4, None)
            extra.append(
                Storage(P.substg_name(_ATTACH_DATA_OBJECT), self.embedded._embedded_children())
            )
        return self._property_children(b"\x00" * 8) + extra


class MessageBuilder(ObjectBuilder):
    def __init__(self) -> None:
        super().__init__()
        self.recipients: list[RecipientBuilder] = []
        self.attachments: list[AttachmentBuilder] = []
        self.root_clsid = ZERO_CLSID
        self.nameid_streams: dict[str, bytes] | None = None
        self.recip_count_override: int | None = None
        self.attach_count_override: int | None = None
        self.next_recip_override: int | None = None
        self.next_attach_override: int | None = None
        # Explicit indices for recipient/attachment storages (for gap injection).
        self.recip_indices: list[int] | None = None
        self.attach_indices: list[int] | None = None

    def add_recipient(self, rb: RecipientBuilder) -> RecipientBuilder:
        self.recipients.append(rb)
        return rb

    def add_attachment(self, ab: AttachmentBuilder) -> AttachmentBuilder:
        self.attachments.append(ab)
        return ab

    def set_nameid(self, guid: bytes, entry: bytes, string: bytes = b"") -> None:
        self.nameid_streams = {
            P.substg_name(P.make_tag(0x0002, P.PTYP_BINARY)): guid,
            P.substg_name(P.make_tag(0x0003, P.PTYP_BINARY)): entry,
            P.substg_name(P.make_tag(0x0004, P.PTYP_BINARY)): string,
        }

    # -- header + shared assembly ------------------------------------------
    def _header(self, embedded: bool) -> bytes:
        n_recip = self.recip_count_override
        if n_recip is None:
            n_recip = len(self.recipients)
        n_attach = self.attach_count_override
        if n_attach is None:
            n_attach = len(self.attachments)
        next_recip = (
            self.next_recip_override
            if self.next_recip_override is not None
            else len(self.recipients)
        )
        next_attach = (
            self.next_attach_override
            if self.next_attach_override is not None
            else len(self.attachments)
        )
        counts = struct.pack("<IIII", next_recip, next_attach, n_recip, n_attach)
        if embedded:
            return b"\x00" * 8 + counts  # 24-byte embedded header
        return b"\x00" * 8 + counts + b"\x00" * 8  # 32-byte top header

    def _shared_children(self, header: bytes) -> list:
        children = self._property_children(header)

        recip_idx = self.recip_indices or list(range(len(self.recipients)))
        for idx, rb in zip(recip_idx, self.recipients):
            children.append(Storage(f"{P.RECIP_PREFIX}{idx:08X}", rb.children()))

        attach_idx = self.attach_indices or list(range(len(self.attachments)))
        for idx, ab in zip(attach_idx, self.attachments):
            children.append(Storage(f"{P.ATTACH_PREFIX}{idx:08X}", ab.children(), ab.clsid))

        if self.nameid_streams is not None:
            nameid_children = [Stream(name, data) for name, data in self.nameid_streams.items()]
            children.append(Storage(P.NAMEID_STORAGE, nameid_children))
        return children

    def _embedded_children(self) -> list:
        return self._shared_children(self._header(embedded=True))

    def build_bytes(self) -> bytes:
        children = self._shared_children(self._header(embedded=False))
        return write_cfb(children, root_clsid=self.root_clsid)


# --- convenience baselines --------------------------------------------------
def good_message() -> MessageBuilder:
    """A well-formed message that should yield zero findings."""
    m = MessageBuilder()
    m.set(P.PidTagMessageClassW, "IPM.Note")
    m.set(P.PidTagMessageFlags, P.MSGFLAG_READ | P.MSGFLAG_UNMODIFIED)
    m.set(P.PidTagInternetCodepage, 1252)
    m.set(P.PidTagBodyW, "Hello, this is a normal message body.")
    m.set(P.PidTagCreationTime, _dt.datetime(2021, 1, 1, 9, 0, tzinfo=_dt.UTC))
    m.set(P.PidTagLastModificationTime, _dt.datetime(2021, 1, 2, 9, 0, tzinfo=_dt.UTC))
    m.set(P.PidTagClientSubmitTime, _dt.datetime(2021, 1, 1, 10, 0, tzinfo=_dt.UTC))
    m.set(P.PidTagMessageDeliveryTime, _dt.datetime(2021, 1, 1, 10, 5, tzinfo=_dt.UTC))

    r = RecipientBuilder()
    r.set(P.PidTagReceivedByAddressTypeW, "SMTP")
    r.set(0x3003001F, "alice@example.com")  # PidTagEmailAddress (Unicode)
    r.set(0x3001001F, "Alice Example")  # PidTagDisplayName
    m.add_recipient(r)
    return m


def good_message_bytes() -> bytes:
    return good_message().build_bytes()
