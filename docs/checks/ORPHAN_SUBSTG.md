# ORPHAN_SUBSTG — Substorage stream not indexed in the property table

**Default severity:** high · **Confidence:** medium

## In plain language
Every piece of data inside a `.msg` file is supposed to be listed in the file's
own index. This check finds data streams that are present but *not* listed, and
index entries that point at data streams that are *not* present.

## How it works
For each MAPI object (the message, each recipient, each attachment), `msgscope`:

1. Reads the object's `__properties_version1.0` table into the set of property
   tags it declares.
2. Decodes every child `__substg1.0_XXXXYYYY` stream/storage name back into a
   property tag.
3. Reports an **orphan** when a stream's tag has no matching table entry, and a
   **dangling reference** when a table entry of an externally-stored type has no
   matching stream. Multivalue element streams (`…-XXXXXXXX`) are matched to
   their base tag so they are not mistaken for orphans.

## Why it matters
Real MAPI providers (Outlook/Exchange) always keep the index and the stored
streams in agreement. A mismatch is a strong sign the container was assembled or
edited by other software.

## Known benign causes
- Some writers emit an empty stream for a zero-length value; dangling findings on
  zero-length values are therefore suppressed.
- Exotic or newly-defined multivalue layouts could in principle be misread; the
  evidence always names the exact stream so a reviewer can confirm.

## Spec reference
MS-OXMSG §2.1.3 (storage/stream naming), §2.4 (property stream).
