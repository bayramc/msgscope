# FILETIME_SANITY — Implausible or contradictory timestamps

**Default severity:** varies (low–high) · **Confidence:** medium–high

## In plain language
Checks the message's dates for values that cannot occur naturally: dates stuck
at the computer "zero date" (1601), dates in the future, or dates that
contradict each other (created after last modified, delivered before sent).

## How it works
`msgscope` reads the `PtypTime` properties — submit (`0x0039`), delivery
(`0x0E06`), creation (`0x3007`), last-modification (`0x3008`) — on every object,
skipping the null markers (`0` and all-ones), and reports:

| Condition | Severity | Confidence |
|-----------|----------|------------|
| Value not a representable date | high | high |
| Value at/near the 1601 epoch | high | medium |
| Value implausibly early (before ~1990) | low | low |
| Value in the future (vs the reference clock) | medium | medium |
| Creation after last-modification | high | high |
| Submit after delivery | medium | medium |

The "future" comparison uses the current clock by default; under `--reproducible`
(or with `--reference-time`) it uses a fixed clock so results are deterministic.

## Why it matters
Timestamps are one of the easiest fields to fabricate and one of the most
scrutinised in disputes. Contradictions are physically impossible and therefore
strong indicators of hand-editing.

## Known benign causes
- Legitimately archived old mail can trip the "implausibly early" rule, hence its
  low severity and confidence.
- Small clock skew between systems can make delivery marginally precede submit;
  the evidence shows both exact values for the reviewer to judge.

## Spec reference
MS-OXOMSG / MS-OXPROPS (PtypTime message properties).
