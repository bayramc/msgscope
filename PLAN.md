# msgscope — Design Plan

## Context

Forensic examiners and eDiscovery practitioners regularly receive Outlook `.msg`
files whose provenance is in question — was this an organically-created message
saved by Outlook/Exchange, or was it synthesized/edited by a library or by hand
to fabricate evidence? Today there is no focused, open, *explainable* tool that
inspects the raw MS-OXMSG / Compound File Binary (CFB) container and surfaces the
structural tells of synthetic generation, with evidence a non-technical
stakeholder can follow.

`msgscope` fills that gap. It is a read-only CLI that opens a `.msg` at the
container level and reports **indicators** — each with a severity, a confidence,
and the concrete evidence (which storage/stream, which byte offset, observed vs
expected) — and **never** a verdict. Showing the work *is* the product: a human
examiner draws the conclusion.

Decisions locked for v1: name `msgscope`; categorical severity
`{info,low,medium,high}` + categorical confidence `{low,medium,high}`; top-level
summary is **neutral counts only** (no aggregate/anomaly score); test corpus =
synthetic fixtures built in-repo + a few tiny, content-free committed samples.

---

## 1. Design principles (non-negotiable)

1. **No verdict, ever.** Output is a list of indicators + evidence + a neutral
   counts summary. No "FORGED", no overall score, no pass/fail of the *file*.
2. **Explainable to a layperson.** Every finding carries `summary_plain` and
   `why_it_matters` in plain language (opposing-counsel-readable).
3. **Two outputs, deterministic.** Human terminal report + machine JSON report.
   Byte-for-byte reproducible given the same input (volatile run metadata is
   isolated and suppressible).
4. **Read-only + chain of custody.** Opens input `rb`, never writes to it.
   Computes and records SHA-256 of the input. A test asserts the input bytes are
   unchanged after a full run.
5. **Container-level, not parser-level.** Built on a low-level CFB library so the
   tamper checks can inspect raw storages/streams/offsets the format internals
   depend on.

---

## 2. Dependency choice (justification)

| Need | Choice | Why |
|---|---|---|
| Read raw CFB (storages, streams, directory entries, CLSIDs, sector offsets) | **`olefile`** (BSD-3, pure-Python, mature; underpins oletools) | Exposes `direntries`, `listdir`, `openstream`, per-entry `clsid`/`size`/`isectStart`, `sectorsize`/`minisectorsize`. Gives the raw container access the checks require. |
| NOT used | extract-msg / independentsoft / aspose | High-level `.msg` parsers abstract away the container; they normalize/repair exactly the structure we must inspect. Rejected for the product path. |
| Build synthetic fixtures with byte-precise injected anomalies | **Small in-repo CFB *writer* helper** (`tests/fixtures/cfb_writer.py`) + `olefile.write_stream` for same-size byte mutations of a base file | No maintained pure-Python CFB *writer* exists (olefile is read-only aside from same-size stream overwrite). A tiny writer gives reproducible, license-clean, anomaly-precise fixtures for CI. |

Core runtime dependency is **only `olefile`**. Terminal coloring is hand-rolled
ANSI gated on TTY (no `rich` dependency) to keep the PyInstaller binary small and
deterministic. Dev-only deps: `pytest`, `pytest-cov`, `ruff`, `mypy`, `build`.

---

## 3. Architecture

```
input.msg ──▶ MsgContainer (olefile wrapper)
                  │  parsed property tables (per object), storage/stream tree,
                  │  directory entries + computed byte offsets, raw read_at()
                  ▼
              Engine ── iterates registered Checks (built-in + entry-point plugins)
                  │      each Check.run(ctx) -> list[Finding]
                  ▼
        deterministic sort + neutral counts
                  │
          ┌───────┴────────┐
   TextReport         JsonReport (schema_version, target, run, findings, summary)
```

- **`container.py` — `MsgContainer`**: the single low-level access layer. Wraps
  `olefile`, parses each object's `__properties_version1.0` into a tag→entry map,
  enumerates `__recip_*` / `__attach_*` / `__nameid_*` storages, decodes
  `__substg1.0_XXXXYYYY` stream names to tags, exposes directory-entry CLSIDs and
  **computed byte offsets** (FAT vs miniFAT region noted), and `read_at(off, n)`
  for raw evidence snippets. Checks consume *only* this — they never touch
  `olefile` directly (keeps checks clean and testable).
- **`properties.py`**: PidTag/PtypXxx constants, property-type sizes, name maps,
  tag↔streamname encode/decode.
- **`filetime.py`**: FILETIME (100-ns since 1601-01-01 UTC) ↔ datetime, with
  null markers (`0`, `0xFFFFFFFFFFFFFFFF`) handled.
- **`findings.py`**: `Severity`, `Confidence` enums; `Evidence`, `Finding`
  dataclasses (frozen, ordered).
- **`engine.py`**: registry + plugin discovery via `importlib.metadata`
  entry-point group `msgscope.checks`; runs checks, collects findings, applies
  deterministic ordering and neutral counts.
- **`checks/base.py` — `Check` ABC**: `id`, `title`, `default_severity`,
  `applies(ctx) -> bool`, `run(ctx) -> Iterable[Finding]`. New detectors = new
  module + registration; third parties can ship checks in a separate package via
  the entry-point group. **Pluggable by construction.**
- **`report/`**: `json_report.py` (deterministic serializer) and
  `text_report.py` (grouped-by-severity terminal renderer, color optional).

### Determinism strategy
JSON is split into `target` (sha256, size, basename — derived purely from input),
`findings` (stable-sorted), `summary` (counts), and a separate `run` block (tool
version, schema version, `analyzed_at`, argv). Findings sort by
`(check_id, object_path, byte_offset, tag)`. `--reproducible` omits volatile
`run` fields so golden-file tests compare byte-for-byte. "Future timestamp"
checks take an injectable reference clock (real `now` by default; fixed epoch
under `--reproducible`/`SOURCE_DATE_EPOCH`).

---

## 4. Check catalog

Format internals each check relies on (so the detection logic is reviewable):
- `__properties_version1.0` header: top-level message = **32 bytes** (8 reserved,
  NextRecipientId u32, NextAttachmentId u32, RecipientCount u32, AttachmentCount
  u32, 8 reserved); embedded message = 24 bytes; recipient/attachment object = 8
  bytes. Then 16-byte entries (tag u32 = id<<16|type, flags u32, value 8 bytes).
- Variable-length / >8-byte fixed props live in `__substg1.0_<8hex tag>` streams.
- Storages: `__recip_version1.0_#XXXXXXXX`, `__attach_version1.0_#XXXXXXXX`,
  `__nameid_version1.0`.

| id | severity (default) | conf | What it checks | Core detection logic |
|---|---|---|---|---|
| `ORPHAN_SUBSTG` | high | medium | Substorage streams not indexed in the property array (and the inverse: entries pointing at a missing stream) | Decode every `__substg1.0_*` name to a tag; assert a matching 16-byte entry exists in that object's property table. Stream-without-entry = orphan; entry-of-varlen-type without stream = dangling. Handles multivalue `…-XXXXXXXX` sub-stream naming to avoid FPs. |
| `HEADER_COUNTS` | high | high | 32-byte root header counts vs storages present | Parse RecipientCount/AttachmentCount/Next* from header; count actual `__recip_*`/`__attach_*` storages; flag mismatch, non-contiguous `#NNNNNNNN` indices, Next* < count. Cross-refs `MSGFLAG_HASATTACH`. |
| `MSGFLAGS` | varies | low–high | PidTagMessageFlags (0x0E07) bitmask validity | Sub-findings: reserved/undefined bits set; `HASATTACH` set with 0 attachments (high) or clear with attachments (medium); `UNSENT` set but ClientSubmitTime present (contradiction); `FROMME` set on externally-originating mail (delivery time present + received-by ≠ sender; heuristic → low confidence). |
| `FILETIME_SANITY` | varies | medium–high | FILETIME plausibility & internal ordering | Read PtypTime props inline from entries: submit 0x0039, delivery 0x0E06, creation 0x3007, lastmod 0x3008. Flag pre-epoch/absurdly-small (high), future vs reference clock (medium), creation>lastmod (high), submit>delivery (medium). Null markers excluded. |
| `NAMEID_INTEGRITY` | high | medium | `__nameid_version1.0` mapping integrity | GUID stream len %16, entry stream len %8; each entry's GUID index valid (incl. PS_MAPI=1/PS_PUBLIC_STRINGS=2), string-named props point to valid offsets in the 00040102 string stream (len-prefixed UTF-16LE, 4-byte padded). Named-prop IDs (≥0x8000) used in property tables must have a mapping; unmapped usage flagged. |
| `ATTACH_OLEGUID` | medium | low–medium | Unexpected OLEGUID/CLSID on storages / custom attach substreams | Read 16-byte CLSID from each storage directory entry; compare to a seeded allowlist (root `.msg` CLSID, embedded-message CLSIDs, zero). Flag unexpected non-zero or unknown GUIDs, and PtypGuid (0x0048) values with unknown provider GUIDs in attachment substreams. Allowlist refined as corpus grows → low confidence by design, evidence-forward. |
| `CODEPAGE_MISMATCH` | medium | low–medium | PidTagInternetCodepage (0x3FDE) vs actual body bytes | Compare declared codepage / PidTagMessageCodepage (0x3FFD) against: ANSI body `1000001E` decodability under the declared codepage; Unicode body `1000001F` valid UTF-16LE (even length, decodes); HTML `10130102` `<meta charset>` vs declared; odd-length Unicode substg streams. Offending bytes included as hex evidence. |

Each check ships a `docs/checks/<id>.md` documenting: the spec reference
(MS-OXMSG / MS-OXCMSG / MS-CFB section), the plain-language rationale, and
**known benign causes** (so confidence is honestly calibrated and FPs are
explainable). The 7 above are the v1 catalog.

**Candidate extensions** (registered later via the same plugin path, listed so
the design proves pluggability): CFB header/FAT-chain sanity & unreferenced
sectors; required-core-property presence (e.g. PidTagMessageClass 0x001A);
exact stream/storage name casing; PidTagMessageClass plausibility.

---

## 5. Output contract

### Terminal (default, stdout)
Header line: tool+version, target basename, SHA-256, size. Findings grouped by
severity (high→info), each showing title, severity/confidence, `summary_plain`,
`why_it_matters`, and an `Evidence:` block (object path, byte offset, region,
observed vs expected, optional hex). Footer: neutral counts
(`high: N  medium: N  low: N  info: N  · total: N`). Color via ANSI only on a
TTY; `--no-color` and non-TTY = plain.

### JSON (`--format json` / `--output file.json`)
```json
{
  "schema_version": "1.0",
  "tool": {"name": "msgscope", "version": "0.1.0"},
  "target": {"name": "evidence.msg", "sha256": "…", "size_bytes": 12345,
             "is_cfb": true},
  "run": {"analyzed_at": "2026-06-30T12:00:00Z", "argv": ["…"],
          "reproducible": false},
  "findings": [
    {
      "id": "ORPHAN_SUBSTG",
      "title": "Substorage stream not indexed in property table",
      "severity": "high",
      "confidence": "medium",
      "summary_plain": "A data stream exists inside the file that the file's own index does not list.",
      "why_it_matters": "Outlook always lists every stream it writes; an unlisted stream suggests the file was assembled by other software.",
      "evidence": {
        "object_path": "/",
        "stream": "__substg1.0_80050102",
        "byte_offset": 28160,
        "region": "FAT",
        "directory_index": 7,
        "observed": "stream present; no property entry with tag 0x80050102",
        "expected": "matching 16-byte entry in __properties_version1.0",
        "raw_hex": "504b0304…"
      },
      "spec_reference": "MS-OXMSG 2.4 / 2.1.3"
    }
  ],
  "summary": {"counts": {"high": 1, "medium": 0, "low": 0, "info": 0},
              "total": 1}
}
```
No `verdict`/`score` field anywhere — enforced by a schema test.

### Exit codes (verdict-free, pipeline-friendly)
`0` ran OK (default, regardless of findings) · `0/10` with `--fail-on <sev>`
(10 if any finding ≥ sev) · `2` usage error · `3` input error (unreadable / not
a CFB). The default never lets indicators flip exit status — the *file* is not
judged. CLI flags: `inspect FILE...`, `--format text|json`, `--output PATH`,
`--checks`/`--exclude`/`--list-checks`, `--reproducible`, `--no-color`,
`--fail-on`, `--reference-time`, `--version`.

---

## 6. Test strategy & corpus

- **Per-check unit tests** (`tests/test_<id>.py`): build a synthetic `.msg`
  in-repo via `tests/fixtures/cfb_writer.py` with the specific anomaly injected,
  assert that detector fires *and that other detectors stay silent on it*
  (precision matters as much as recall). A clean baseline fixture asserts **zero**
  findings.
- **Determinism test**: run twice → identical JSON under `--reproducible`;
  golden file committed.
- **Read-only guarantee test**: hash input before/after a full run, assert equal.
- **CLI tests**: format selection, exit codes, `--fail-on`, `--list-checks`.
- **Corpus sourcing:**
  - *Known-good*: provide a documented `pywin32`/Outlook script (developer-run on
    Windows, **not** CI) to save real `.msg`; keep under `corpus/good/`
    (gitignored). Commit only 1–2 tiny, scrubbed, content-free good samples to
    `sample/` after manual PII review.
  - *Known-synthetic*: primary source is the in-repo CFB writer (license-clean,
    byte-precise, runs in CI). Diversify locally with third-party generators
    (e.g. Aspose.Email trial, Independentsoft, .NET MsgKit, libpff tooling) under
    `corpus/synthetic/` (gitignored). **CI depends only on the in-repo builder.**
  - `sample/README.md` records provenance + a safety/no-PII statement.

---

## 7. Repo layout & deliverables

```
PLAN.md  README.md  LICENSE(MIT)  CONTRIBUTING.md  CHANGELOG.md  .gitignore
pyproject.toml            # hatchling, src layout, requires-python>=3.11
                          # deps=[olefile]; [project.scripts] msgscope=...
                          # MIT classifier; entry-points "msgscope.checks"
src/msgscope/
  __init__.py __main__.py cli.py engine.py container.py properties.py
  filetime.py findings.py
  report/{__init__,json_report,text_report}.py
  checks/{base,orphan_substg,header_counts,message_flags,filetime_sanity,
          nameid_integrity,attach_oleguid,codepage_mismatch}.py
tests/
  conftest.py  fixtures/{cfb_writer.py, builders.py}
  test_<each_check>.py  test_report_determinism.py  test_cli.py
  test_readonly_guarantee.py
sample/{README.md, good_minimal.msg, synthetic_orphan.msg}
docs/{json-schema.md, checks/<id>.md ...}
.github/
  workflows/{ci.yml, release.yml}
  release-notes-template.md
```

- **README**: leads with what the tool does + the "indicators, not verdicts"
  philosophy; install (`pipx install msgscope` *or* download a Releases binary);
  **SmartScreen note** for unsigned Windows binaries + **how to verify SHA256**
  (per-OS commands against `SHA256SUMS`); usage; example terminal + JSON output;
  check-catalog table; exit codes; plugin-authoring pointer; read-only /
  chain-of-custody statement; "not legal advice" disclaimer;
  `<!-- ARTICLE_URL -->` placeholder (**fill in**).
- **CONTRIBUTING**: dev setup, lint/test commands, how to add a check (Check
  subclass → register entry point → fixture + test → `docs/checks/<id>.md`),
  corpus rules (no PII, scrub, provenance), commit/PR + security-disclosure.

---

## 8. Distribution & release pipeline (designed in from the start)

Two **separate** workflows:

### `ci.yml` — every push & PR
Matrix Python 3.11/3.12/3.13. Steps: `ruff check`, `ruff format --check`,
`mypy`, `pytest --cov`. (Read-path smoke also on windows/macos runners.)

### `release.yml` — only on tag `v*.*.*`
1. **build** (matrix `ubuntu/macos/windows`, one runner per OS): install
   PyInstaller + project; `pyinstaller --onefile` → `msgscope-<os>-<arch>[.exe]`
   that runs with **no Python installed**. Upload per-OS artifact. Set
   `SOURCE_DATE_EPOCH` for best-effort reproducibility.
2. **checksums** (needs build): download all artifacts; generate one
   **`SHA256SUMS`** covering every artifact (`sha256sum`/`shasum -a 256`). A
   file-integrity tool must let users verify its own integrity — CI produces the
   hashes, never by hand.
3. **pypi** (needs build): `python -m build` (sdist+wheel) → publish via **PyPI
   Trusted Publishing (OIDC)** with `id-token: write` (no stored token).
   Target install path `pipx install msgscope`. MIT classifier present.
4. **release** (needs checksums + pypi): `gh release create` / `action-gh-release`
   attaching all binaries + `SHA256SUMS` + sdist/wheel; body from
   `release-notes-template.md`; prerelease if tag has `-rc`. Permissions:
   `contents: write`, `id-token: write`.

**Release notes template** leads with what the tool does, links the backing
article (`<!-- ARTICLE_URL -->`, **fill in**), and documents SHA256
verification. **No paid code-signing now** — README documents the SmartScreen
workaround instead.

---

## 9. Open items to confirm (flagged, not blocking)

1. **Article URL** — placeholder `<!-- ARTICLE_URL -->` in README + release notes.
2. **In-repo CFB writer** for fixtures — confirm OK to hand-roll a small writer
   (justification in §2); alternative is committing more binary fixtures.
3. **PyPI auth** — plan uses OIDC Trusted Publishing (recommended, tokenless);
   say if you'd rather use an API token secret.
4. **"Future timestamp" reference clock** — default real `now`; fixed epoch under
   `--reproducible`. Confirm acceptable.
5. **CLSID/codepage allowlists** start seeded and are refined as the good corpus
   grows; until then those two checks stay low-confidence + evidence-forward.

---

## 10. Verification (once code is built)

- `pipx run --spec . msgscope inspect sample/synthetic_orphan.msg` → shows the
  expected indicator(s) with evidence; `sample/good_minimal.msg` → zero findings.
- `msgscope inspect --format json --reproducible f.msg` run twice → identical
  bytes (determinism); JSON validates against `docs/json-schema.md` and contains
  no `verdict`/`score`.
- `pytest -q` → every detector fires only on its targeted fixture; read-only and
  determinism tests pass.
- Tag a `v0.0.1-rc1` on a fork → `release.yml` produces 3 binaries + `SHA256SUMS`;
  `shasum -a 256 -c SHA256SUMS` verifies; PyPI test-publish succeeds.
