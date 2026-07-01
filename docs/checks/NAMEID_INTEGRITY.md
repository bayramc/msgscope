# NAMEID_INTEGRITY — Named-property mapping integrity

**Default severity:** high · **Confidence:** medium

## In plain language
Outlook lets messages carry custom properties identified by name rather than by a
fixed number. The definitions of those names live in a small table. This check
makes sure that table is well-formed and that every custom property the message
uses is actually defined in it.

## How it works
The `__nameid_version1.0` storage holds three streams: the GUID stream
(`00020102`), the entry stream (`00030102`), and the string stream (`00040102`).
`msgscope`:

1. Checks the GUID stream length is a multiple of 16 and the entry stream a
   multiple of 8.
2. For each 8-byte entry, checks its GUID index resolves (accounting for the
   predefined `PS_MAPI` and `PS_PUBLIC_STRINGS` namespaces) and that
   string-named entries point inside the string stream.
3. Checks every named property id (≥ `0x8000`) used anywhere in the file has a
   corresponding definition entry — and flags the whole storage as missing if it
   is absent while named properties are used.

## Why it matters
A malformed or incomplete name map means custom properties cannot be resolved —
something a consistent MAPI provider never produces. It commonly appears when a
generator writes named-property values without writing the matching definitions.

## Known benign causes
- Rare, non-standard extensions could use namespaces `msgscope` does not model;
  the evidence names the exact entry so a reviewer can verify.

## Spec reference
MS-OXMSG §2.2.3 (named property mapping), §2.2.3.1.2 (entry stream format).
