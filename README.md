# msgscope

**A read-only structural-integrity / tamper inspector for Outlook `.msg` files.**

`msgscope` opens an Outlook `.msg` (MS-OXMSG / Compound File Binary) file at the
raw container level and reports **indicators** that a file may have been
synthetically generated or edited rather than produced organically by a real
MAPI provider (Outlook/Exchange). Each indicator carries a **severity**, a
**confidence**, and the **evidence** behind it — which stream/storage, which byte
offset, observed vs expected.

> `msgscope` never outputs a verdict like "FORGED". It surfaces indicators; a
> human examiner draws the conclusion. **Showing the work is the product.**

It is intended for digital-forensics and eDiscovery practitioners. Every finding
is written to be explainable in plain language to a non-technical stakeholder
(e.g. opposing counsel), with a one-line "why this matters".

- **Read-only.** The input file is never modified. A SHA-256 of the input is
  recorded for chain-of-custody hygiene.
- **Two outputs.** A readable terminal report and a machine-readable JSON report
  (deterministic, for pipelines and case-management systems).
- **Pluggable.** New detectors register through a standard entry-point group.

---

## Install

### Standalone binary (no Python required)

Download the binary for your platform from the
[Releases](https://github.com/bayramc/msgscope/releases) page, then verify it
against the published `SHA256SUMS` (see [Verifying downloads](#verifying-downloads)).

### With pipx (developers / pipelines)

```console
pipx install msgscope
```

---

## Usage

```console
msgscope inspect evidence.msg
msgscope inspect evidence.msg --format json --output evidence.report.json
msgscope inspect *.msg --fail-on high        # exit 10 if any high-severity indicator
msgscope inspect evidence.msg --reproducible # omit volatile run metadata
msgscope inspect --list-checks
```

`msgscope` only ever reads the file. It computes a SHA-256 of the input and
prints it in both report formats.

### Example terminal output

```text
msgscope report - evidence.msg
  SHA-256 : 6f1e...9ab2
  Size    : 41984 bytes

[HIGH/medium] Substorage stream not indexed in property table  (ORPHAN_SUBSTG)
  What : A data stream exists inside the file that the file's own property index does not list.
  Why  : Outlook records every stream it writes in the property index. An unlisted stream
         suggests the file was assembled or edited by other software.
  Where: /  stream=__substg1.0_80050102  offset=0x6E00  region=miniFAT
  Seen : stream present; no property entry for tag 0x80050102
  Norm : a 16-byte entry with tag 0x80050102 in __properties_version1.0
  Spec : MS-OXMSG 2.1.3 / 2.4

Indicators  high: 1  medium: 0  low: 0  info: 0  ·  total: 1
Indicators only - a human examiner draws the conclusion.
```

### Example JSON output

```json
{
  "schema_version": "1.0",
  "tool": { "name": "msgscope", "version": "0.1.0" },
  "target": { "name": "evidence.msg", "sha256": "6f1e...9ab2", "size_bytes": 41984, "is_cfb": true },
  "findings": [
    {
      "id": "ORPHAN_SUBSTG",
      "severity": "high",
      "confidence": "medium",
      "summary_plain": "A data stream exists inside the file that the file's own property index does not list.",
      "evidence": { "object_path": "/", "stream": "__substg1.0_80050102", "byte_offset": 28160, "region": "miniFAT" }
    }
  ],
  "summary": { "counts": { "high": 1, "medium": 0, "low": 0, "info": 0 }, "total": 1 }
}
```

(Some fields are abbreviated above; see `docs/json-schema.md` for the full schema.)

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Ran successfully. (Indicators alone never change the exit status — the file is not judged.) |
| `10` | `--fail-on <severity>` was set and at least one finding met the threshold. |
| `3`  | An input could not be read or was not a CFB container. |
| `2`  | Command-line usage error. |

---

## Try it against fake / tampered files

Two helper scripts let you see the detectors fire without needing real evidence.

**Generate synthetic files** (one anomaly each, no personal data):

```console
python scripts/make_synthetic.py --out corpus/synthetic
msgscope inspect corpus/synthetic/orphan_stream.msg
```

**Tamper with an existing message** (edits a *copy*; the original is never
touched) — simulates someone altering a genuine file:

```console
python scripts/tamper_msg.py --in real.msg --out tampered.msg --mutation set-hasattach
msgscope inspect tampered.msg
```

Mutations: `set-hasattach`, `future-delivery`, `reverse-times`. See
[CONTRIBUTING.md](CONTRIBUTING.md) for validating against a real known-good
corpus.

### Tamper with a file by hand

The **golden rule: always work on a copy** (`cp original.msg mine.msg`) —
`msgscope` never writes, but you are about to.

The core primitive is: find a 16-byte property entry, change its 8-byte value,
and write the stream back at the *same size* (all `olefile` allows in place):

```python
import olefile, struct

ole = olefile.OleFileIO("mine.msg", write_mode=True)
data = bytearray(ole.openstream("__properties_version1.0").read())
for off in range(32, len(data) - 15, 16):            # entries follow the 32-byte header
    if struct.unpack_from("<I", data, off)[0] == 0x0E070003:   # PidTagMessageFlags
        flags = struct.unpack_from("<I", data, off + 8)[0]
        struct.pack_into("<I", data, off + 8, flags | 0x10)    # force HASATTACH on
ole.write_stream("__properties_version1.0", bytes(data))
ole.close()
```

Then `msgscope inspect mine.msg` catches it, and the input's SHA-256 changes.

Prefer a **hex editor** (e.g. Hex Fiend on macOS)? Random byte-flips usually just
corrupt the container (`msgscope` then reports `is_cfb: false` — itself a signal).
To edit a *specific* field, first run `msgscope` on a script-tampered copy: it
prints the exact `offset=0x…` of the value it flagged, so you know where to edit.

---

## Check catalog

| id | default severity | what it checks |
|----|------------------|----------------|
| `ORPHAN_SUBSTG` | high | substorage streams not indexed in the property table (and the inverse) |
| `HEADER_COUNTS` | high | header recipient/attachment counts vs storages present |
| `MSGFLAGS` | medium | impossible/contradictory PidTagMessageFlags combinations |
| `FILETIME_SANITY` | medium | pre-epoch/future/contradictory timestamps |
| `NAMEID_INTEGRITY` | high | named-property mapping (`__nameid_version1.0`) integrity |
| `ATTACH_OLEGUID` | medium | unexpected CLSID / OLE GUID on storages |
| `CODEPAGE_MISMATCH` | medium | declared codepage vs actual body bytes |

Each check is documented in plain language in [`docs/checks/`](docs/checks/),
including its spec reference and its known benign causes.

### Writing your own detector

Detectors are discovered through the `msgscope.checks` entry-point group. Ship a
package that exposes a `Check` subclass and advertises it:

```toml
[project.entry-points."msgscope.checks"]
my_detector = "my_pkg.checks:MyCheck"
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full walkthrough.

---

## Verifying downloads

Every release ships a `SHA256SUMS` file generated by CI (never by hand), so you
can confirm a download's integrity — appropriate for a file-integrity tool.

```console
# macOS / Linux
shasum -a 256 -c SHA256SUMS

# Windows (PowerShell)
Get-FileHash .\msgscope-windows-x86_64.exe -Algorithm SHA256
```

Compare the printed hash to the matching line in `SHA256SUMS`.

> **Windows SmartScreen note.** The Windows binaries are **not** code-signed, so
> SmartScreen may warn "Windows protected your PC" on first run. This is expected
> for unsigned executables. Verify the SHA-256 hash against `SHA256SUMS` before
> running, then choose **More info → Run anyway** if your policy permits.

---

## Background

`msgscope` accompanies an article on detecting synthetic `.msg` files:
<!-- ARTICLE_URL -->

## Disclaimer

`msgscope` reports structural indicators only. It does not determine authenticity
and does not provide legal advice. Findings are inputs to expert human review.

## License

[MIT](LICENSE).
