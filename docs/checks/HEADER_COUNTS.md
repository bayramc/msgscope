# HEADER_COUNTS — Header object counts vs storages present

**Default severity:** high · **Confidence:** high

## In plain language
The message's header states how many recipients and attachments it has. This
check compares those declared numbers with the recipient and attachment folders
actually stored inside the file, and checks how those folders are numbered.

## How it works
The 32-byte top-level property-stream header carries the recipient count,
attachment count, and the "next id" allocators. `msgscope`:

1. Compares each declared count with the number of `__recip_version1.0_#NNNNNNNN`
   / `__attach_version1.0_#NNNNNNNN` storages present.
2. Checks the `#NNNNNNNN` indices number contiguously from zero.
3. Checks each "next id" allocator is not smaller than the number present.

## Why it matters
Outlook keeps the header counts, the stored folders, and the allocators in lock
step. A disagreement points to inconsistent generation or post-hoc editing (for
example a recipient removed without updating the header).

## Known benign causes
- Very few. This is one of the most deterministic checks, hence high confidence.

## Spec reference
MS-OXMSG §2.4.1.1 (property stream header for the top-level message object).
