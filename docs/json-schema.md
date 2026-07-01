# JSON report schema (`schema_version` 1.0)

`msgscope inspect --format json` emits one object per file (or a JSON array when
several files are inspected in one run). The output is deterministic; with
`--reproducible` the volatile `run` fields are omitted so golden files compare
byte-for-byte.

There is deliberately **no** `verdict` or aggregate `score` field.

## Top level

| Field | Type | Notes |
|-------|------|-------|
| `schema_version` | string | `"1.0"`. |
| `tool` | object | `{ "name": "msgscope", "version": "<x.y.z>" }`. |
| `target` | object | Derived purely from the input file (see below). |
| `run` | object | Volatile run metadata. Omitted fields under `--reproducible`. |
| `error` | string | Present only when the file could not be analysed (e.g. not a CFB). |
| `findings` | array | Zero or more findings, ordered deterministically. |
| `summary` | object | Neutral counts only. |

### `target`

| Field | Type |
|-------|------|
| `name` | string (basename) |
| `sha256` | string (hex) |
| `size_bytes` | integer |
| `is_cfb` | boolean |

### `run`

Full form: `{ "analyzed_at": "<ISO-8601 UTC>", "argv": [...], "reproducible": false }`.
Under `--reproducible`: `{ "reproducible": true }`.

### `findings[]`

| Field | Type | Notes |
|-------|------|-------|
| `id` | string | Stable check id, e.g. `ORPHAN_SUBSTG`. |
| `title` | string | Short human title. |
| `severity` | string | `info` \| `low` \| `medium` \| `high`. |
| `confidence` | string | `low` \| `medium` \| `high`. |
| `summary_plain` | string | Layperson explanation of what was seen. |
| `why_it_matters` | string | One line on why it is suspicious. |
| `evidence` | object | See below. |
| `spec_reference` | string | Relevant MS-OXMSG / MS-CFB section. |

### `findings[].evidence`

| Field | Type | Notes |
|-------|------|-------|
| `object_path` | string | MAPI object, `/` for the top message. |
| `stream` | string \| null | Stream/storage name, when applicable. |
| `byte_offset` | integer \| null | Absolute file offset of the evidence. |
| `region` | string \| null | `FAT`, `miniFAT`, or `directory`. |
| `directory_index` | integer \| null | CFB directory entry index (SID). |
| `observed` | string | What the tool actually found. |
| `expected` | string | What a genuine file would show. |
| `raw_hex` | string \| null | Hex dump at `byte_offset` (up to 16 bytes). |

### `summary`

```json
{ "counts": { "high": 0, "medium": 0, "low": 0, "info": 0 }, "total": 0 }
```

## Example

```json
{
  "schema_version": "1.0",
  "tool": { "name": "msgscope", "version": "0.1.0" },
  "target": { "name": "synthetic_orphan.msg", "sha256": "50b8...256f", "size_bytes": 4096, "is_cfb": true },
  "run": { "reproducible": true },
  "findings": [
    {
      "id": "ORPHAN_SUBSTG",
      "title": "Substorage stream not indexed in property table",
      "severity": "high",
      "confidence": "medium",
      "summary_plain": "A data stream exists inside the file that the file's own property index does not list.",
      "why_it_matters": "Outlook records every stream it writes in the property index. An unlisted stream suggests the file was assembled or edited by other software.",
      "evidence": {
        "object_path": "/",
        "stream": "__substg1.0_80050102",
        "byte_offset": 960,
        "region": "miniFAT",
        "directory_index": 7,
        "observed": "stream present; no property entry for tag 0x80050102",
        "expected": "a 16-byte entry with tag 0x80050102 in __properties_version1.0",
        "raw_hex": "6f727068616e65642064617461206e6f"
      },
      "spec_reference": "MS-OXMSG 2.1.3 / 2.4"
    }
  ],
  "summary": { "counts": { "high": 1, "medium": 0, "low": 0, "info": 0 }, "total": 1 }
}
```
