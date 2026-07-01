"""MAPI property tag / type constants and ``__substg1.0_`` name <-> tag helpers.

A MAPI property *tag* is a 32-bit value: the high 16 bits are the property *id*
and the low 16 bits are the property *type* (``Ptyp*``).  In the MS-OXMSG
property stream the tag is stored little-endian, so the first two bytes are the
type and the next two are the id.

Variable-length properties (and fixed-length properties whose value exceeds the
8-byte value slot) are not stored inline in the property table; their data lives
in a stream named ``__substg1.0_<8 hex digits>`` where the eight hex digits are
the property tag (id then type).  Multivalue elements add a ``-XXXXXXXX`` index
suffix.
"""

from __future__ import annotations

# --- Property types (Ptyp*) -------------------------------------------------
PTYP_UNSPECIFIED = 0x0000
PTYP_NULL = 0x0001
PTYP_INTEGER16 = 0x0002
PTYP_INTEGER32 = 0x0003
PTYP_FLOATING32 = 0x0004
PTYP_FLOATING64 = 0x0005
PTYP_CURRENCY = 0x0006
PTYP_FLOATINGTIME = 0x0007
PTYP_ERRORCODE = 0x000A
PTYP_BOOLEAN = 0x000B
PTYP_OBJECT = 0x000D
PTYP_INTEGER64 = 0x0014
PTYP_STRING8 = 0x001E  # ANSI / codepage string
PTYP_STRING = 0x001F  # Unicode UTF-16LE
PTYP_TIME = 0x0040  # FILETIME, 8 bytes
PTYP_GUID = 0x0048  # 16 bytes
PTYP_SERVERID = 0x00FB
PTYP_RESTRICTION = 0x00FD
PTYP_RULEACTION = 0x00FE
PTYP_BINARY = 0x0102

PTYP_MULTIVALUE_FLAG = 0x1000

# Names for human-readable evidence.
PTYP_NAMES = {
    PTYP_UNSPECIFIED: "PtypUnspecified",
    PTYP_NULL: "PtypNull",
    PTYP_INTEGER16: "PtypInteger16",
    PTYP_INTEGER32: "PtypInteger32",
    PTYP_FLOATING32: "PtypFloating32",
    PTYP_FLOATING64: "PtypFloating64",
    PTYP_CURRENCY: "PtypCurrency",
    PTYP_FLOATINGTIME: "PtypFloatingTime",
    PTYP_ERRORCODE: "PtypErrorCode",
    PTYP_BOOLEAN: "PtypBoolean",
    PTYP_OBJECT: "PtypObject",
    PTYP_INTEGER64: "PtypInteger64",
    PTYP_STRING8: "PtypString8",
    PTYP_STRING: "PtypString",
    PTYP_TIME: "PtypTime",
    PTYP_GUID: "PtypGuid",
    PTYP_SERVERID: "PtypServerId",
    PTYP_RESTRICTION: "PtypRestriction",
    PTYP_RULEACTION: "PtypRuleAction",
    PTYP_BINARY: "PtypBinary",
}

# Fixed-length types whose value fits inline in the 8-byte property-entry slot.
# Everything else is stored in a ``__substg1.0_`` stream (or, for PtypObject, a
# sub-storage).
_INLINE_FIXED_TYPES = frozenset(
    {
        PTYP_INTEGER16,
        PTYP_INTEGER32,
        PTYP_FLOATING32,
        PTYP_FLOATING64,
        PTYP_CURRENCY,
        PTYP_FLOATINGTIME,
        PTYP_ERRORCODE,
        PTYP_BOOLEAN,
        PTYP_INTEGER64,
        PTYP_TIME,
    }
)


# --- Property tags (PidTag*) ------------------------------------------------
# Full 32-bit tags used directly by the detectors.
PidTagMessageClassW = 0x001A001F
PidTagMessageClassA = 0x001A001E
PidTagMessageFlags = 0x0E070003
PidTagClientSubmitTime = 0x00390040
PidTagMessageDeliveryTime = 0x0E060040
PidTagCreationTime = 0x30070040
PidTagLastModificationTime = 0x30080040
PidTagInternetCodepage = 0x3FDE0003
PidTagMessageCodepage = 0x3FFD0003
PidTagBodyW = 0x1000001F
PidTagBodyA = 0x1000001E
PidTagHtml = 0x10130102
PidTagSenderAddressTypeW = 0x0C1E001F
PidTagReceivedByAddressTypeW = 0x0075001F
PidTagSenderEmailAddressW = 0x0C1F001F
PidTagSentRepresentingEmailAddressW = 0x0065001F

# Property *ids* (type-independent) for friendly labelling.
PROP_ID_NAMES = {
    0x001A: "PidTagMessageClass",
    0x0E07: "PidTagMessageFlags",
    0x0039: "PidTagClientSubmitTime",
    0x0E06: "PidTagMessageDeliveryTime",
    0x3007: "PidTagCreationTime",
    0x3008: "PidTagLastModificationTime",
    0x3FDE: "PidTagInternetCodepage",
    0x3FFD: "PidTagMessageCodepage",
    0x1000: "PidTagBody",
    0x1013: "PidTagHtml",
    0x0C1E: "PidTagSenderAddressType",
    0x0075: "PidTagReceivedByAddressType",
    0x0C1F: "PidTagSenderEmailAddress",
    0x0065: "PidTagSentRepresentingEmailAddress",
    0x3701: "PidTagAttachDataObject",
}


# --- PidTagMessageFlags bits (MSGFLAG_*) ------------------------------------
MSGFLAG_READ = 0x00000001
MSGFLAG_UNMODIFIED = 0x00000002
MSGFLAG_SUBMIT = 0x00000004
MSGFLAG_UNSENT = 0x00000008
MSGFLAG_HASATTACH = 0x00000010
MSGFLAG_FROMME = 0x00000020
MSGFLAG_ASSOCIATED = 0x00000040
MSGFLAG_RESEND = 0x00000080
MSGFLAG_RN_PENDING = 0x00000100
MSGFLAG_NRN_PENDING = 0x00000200
MSGFLAG_EVERREAD = 0x00000400
MSGFLAG_ORIGIN_X400 = 0x00001000
MSGFLAG_ORIGIN_INTERNET = 0x00002000
MSGFLAG_ORIGIN_MISC_EXT = 0x00008000

# Every bit MS-OXCMSG / MS-OXPROPS defines as meaningful.  Bits outside this
# mask are reserved and should be zero.
MSGFLAG_DEFINED_MASK = (
    MSGFLAG_READ
    | MSGFLAG_UNMODIFIED
    | MSGFLAG_SUBMIT
    | MSGFLAG_UNSENT
    | MSGFLAG_HASATTACH
    | MSGFLAG_FROMME
    | MSGFLAG_ASSOCIATED
    | MSGFLAG_RESEND
    | MSGFLAG_RN_PENDING
    | MSGFLAG_NRN_PENDING
    | MSGFLAG_EVERREAD
    | MSGFLAG_ORIGIN_X400
    | MSGFLAG_ORIGIN_INTERNET
    | MSGFLAG_ORIGIN_MISC_EXT
)

MSGFLAG_BIT_NAMES = {
    MSGFLAG_READ: "MSGFLAG_READ",
    MSGFLAG_UNMODIFIED: "MSGFLAG_UNMODIFIED",
    MSGFLAG_SUBMIT: "MSGFLAG_SUBMIT",
    MSGFLAG_UNSENT: "MSGFLAG_UNSENT",
    MSGFLAG_HASATTACH: "MSGFLAG_HASATTACH",
    MSGFLAG_FROMME: "MSGFLAG_FROMME",
    MSGFLAG_ASSOCIATED: "MSGFLAG_ASSOCIATED",
    MSGFLAG_RESEND: "MSGFLAG_RESEND",
    MSGFLAG_RN_PENDING: "MSGFLAG_RN_PENDING",
    MSGFLAG_NRN_PENDING: "MSGFLAG_NRN_PENDING",
    MSGFLAG_EVERREAD: "MSGFLAG_EVERREAD",
    MSGFLAG_ORIGIN_X400: "MSGFLAG_ORIGIN_X400",
    MSGFLAG_ORIGIN_INTERNET: "MSGFLAG_ORIGIN_INTERNET",
    MSGFLAG_ORIGIN_MISC_EXT: "MSGFLAG_ORIGIN_MISC_EXT",
}


SUBSTG_PREFIX = "__substg1.0_"
PROPERTIES_STREAM = "__properties_version1.0"
NAMEID_STORAGE = "__nameid_version1.0"
RECIP_PREFIX = "__recip_version1.0_#"
ATTACH_PREFIX = "__attach_version1.0_#"


def tag_id(tag: int) -> int:
    """Return the 16-bit property id of a 32-bit tag."""
    return (tag >> 16) & 0xFFFF


def tag_type(tag: int) -> int:
    """Return the 16-bit property type of a 32-bit tag."""
    return tag & 0xFFFF


def make_tag(prop_id: int, prop_type: int) -> int:
    return ((prop_id & 0xFFFF) << 16) | (prop_type & 0xFFFF)


def is_multivalue(prop_type: int) -> bool:
    return bool(prop_type & PTYP_MULTIVALUE_FLAG)


def is_stored_inline(prop_type: int) -> bool:
    """True if the value lives in the property-table entry, not a substg stream."""
    return prop_type in _INLINE_FIXED_TYPES


def is_stored_external(prop_type: int) -> bool:
    """True if the property's value is stored in a ``__substg1.0_`` stream/storage."""
    if prop_type in (PTYP_UNSPECIFIED, PTYP_NULL):
        return False
    return not is_stored_inline(prop_type)


def type_name(prop_type: int) -> str:
    base = prop_type & ~PTYP_MULTIVALUE_FLAG
    name = PTYP_NAMES.get(base, f"0x{base:04X}")
    return f"PtypMultiple{name[4:]}" if is_multivalue(prop_type) else name


def tag_label(tag: int) -> str:
    """Human label like ``PidTagMessageFlags (0x0E070003)``."""
    name = PROP_ID_NAMES.get(tag_id(tag))
    if name:
        return f"{name} (0x{tag:08X})"
    return f"0x{tag:08X}"


def substg_name(tag: int, mv_index: int | None = None) -> str:
    """Build the ``__substg1.0_`` stream name for a tag (optional multivalue index)."""
    base = f"{SUBSTG_PREFIX}{tag_id(tag):04X}{tag_type(tag):04X}"
    if mv_index is not None:
        return f"{base}-{mv_index:08X}"
    return base


def parse_substg_name(name: str) -> tuple[int, int | None] | None:
    """Parse a ``__substg1.0_`` stream name.

    Returns ``(tag, mv_index)`` where ``mv_index`` is ``None`` for a scalar
    property or an integer for a multivalue element stream.  Returns ``None`` if
    *name* is not a substg stream name we recognise.
    """
    if not name.startswith(SUBSTG_PREFIX):
        return None
    rest = name[len(SUBSTG_PREFIX) :]
    mv_index: int | None = None
    if "-" in rest:
        rest, _, idx = rest.partition("-")
        try:
            mv_index = int(idx, 16)
        except ValueError:
            return None
    if len(rest) != 8:
        return None
    try:
        tag = int(rest, 16)
    except ValueError:
        return None
    return tag, mv_index
