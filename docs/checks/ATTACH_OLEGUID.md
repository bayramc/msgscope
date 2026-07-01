# ATTACH_OLEGUID — Unexpected CLSID / OLE GUID on a storage

**Default severity:** medium · **Confidence:** low–medium

## In plain language
Each folder inside the file can carry a program identifier (a CLSID / GUID). In a
genuine `.msg`, the outer folder carries the Outlook message identifier (or none)
and the inner folders carry none. This check flags folders tagged with an
unexpected identifier.

## How it works
`msgscope` reads the 16-byte CLSID from every storage's CFB directory entry and
compares it against a small allowlist:

- **Root:** the Outlook message CLSID (`00020D0B-…`) or all-zero.
- **Embedded message object storages** (`__substg1.0_3701000D`): the same.
- **All other storages:** all-zero only.

Anything else is reported, leading with the raw GUID as evidence.

## Why it matters
An unexpected CLSID can mark an embedded OLE object or a container produced by
software other than Outlook.

## Known benign causes
- The allowlist is intentionally small and grows as the known-good corpus grows,
  so this check is **evidence-forward and low/medium confidence**. Always verify
  the reported GUID against known providers before drawing conclusions.

## Spec reference
MS-CFB §2.6.1 (directory entry CLSID field).
