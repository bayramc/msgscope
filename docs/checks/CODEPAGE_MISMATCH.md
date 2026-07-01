# CODEPAGE_MISMATCH — Declared codepage vs actual body bytes

**Default severity:** medium · **Confidence:** low–medium

## In plain language
The message declares which character set its text uses. This check confirms the
stored body text actually matches that declaration.

## How it works
`msgscope` reads `PidTagInternetCodepage` (`0x3FDE`) / `PidTagMessageCodepage`
(`0x3FFD`) and compares them with the body streams:

1. The Unicode body (`__substg1.0_1000001F`) must be even-length, valid UTF-16LE.
2. The ANSI body (`__substg1.0_1000001E`) must decode under the declared codepage.
3. The HTML body's `charset` (if any) should agree with the declared codepage.
4. An unrecognised declared codepage number is itself reported (low).

## Why it matters
When the declared encoding cannot decode the stored text, the body and its
metadata were not produced together, as a real client would.

## Known benign causes
- Most byte sequences decode under single-byte codepages, so this check mostly
  fires on UTF-8/multibyte mismatches — genuine but occasionally explainable
  (e.g. mixed-encoding forwarded content). It is low/medium confidence and always
  includes the offending bytes.

## Spec reference
MS-OXCMSG §2.2.1 (body and codepage properties).
