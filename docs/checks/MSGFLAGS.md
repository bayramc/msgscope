# MSGFLAGS — PidTagMessageFlags bitmask validity

**Default severity:** varies (low–high) · **Confidence:** low–high

## In plain language
`PidTagMessageFlags` is a set of yes/no status bits (read, has-attachments,
unsent, from-me, …). Some combinations are impossible, and some contradict the
rest of the message.

## How it works
`msgscope` reads the flags value (property `0x0E070003`) and reports:

| Sub-finding | Severity | Confidence |
|-------------|----------|------------|
| Reserved/undefined bits set | low | medium |
| `HASATTACH` set but no attachment storages | high | high |
| Attachments present but `HASATTACH` clear | medium | high |
| `UNSENT` set but a client submit time exists | medium | medium |
| `FROMME` set on an apparently received message | medium | low |

The `FROMME` heuristic treats a message with a delivery time and no submit time
as "received", so it is deliberately low confidence.

## Why it matters
The flags are set by the sending/receiving client; contradictions between the
flags and the actual stored content or timestamps indicate the file did not come
together the way a real client produces one.

## Known benign causes
- Unusual but legitimate workflows (drafts, associated/FAI messages, resend
  states) can produce uncommon flag combinations; the `FROMME` and `UNSENT`
  sub-findings are rated accordingly.

## Spec reference
MS-OXCMSG §2.2.1.6 (PidTagMessageFlags); MS-OXPROPS.
