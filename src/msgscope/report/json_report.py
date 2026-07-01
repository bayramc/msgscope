"""Deterministic JSON serialization of a report.

The output is split into ``target`` (derived purely from the input),
``findings`` (already deterministically ordered by the engine), ``summary``
(neutral counts), and a ``run`` block for volatile metadata.  In ``reproducible``
mode the volatile fields are omitted so golden files compare byte-for-byte.

There is deliberately no ``verdict`` or aggregate ``score`` field anywhere.
"""

from __future__ import annotations

import json
from typing import Any

from .. import __version__
from ..engine import Report
from ..findings import Finding

SCHEMA_VERSION = "1.0"


def _evidence_dict(f: Finding) -> dict[str, Any]:
    e = f.evidence
    return {
        "object_path": e.object_path,
        "stream": e.stream,
        "byte_offset": e.byte_offset,
        "region": e.region,
        "directory_index": e.directory_index,
        "observed": e.observed,
        "expected": e.expected,
        "raw_hex": e.raw_hex,
    }


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "title": f.title,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "summary_plain": f.summary_plain,
        "why_it_matters": f.why_it_matters,
        "evidence": _evidence_dict(f),
        "spec_reference": f.spec_reference,
    }


def report_to_dict(report: Report) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "msgscope", "version": __version__},
        "target": {
            "name": report.target_name,
            "sha256": report.sha256,
            "size_bytes": report.size_bytes,
            "is_cfb": report.is_cfb,
        },
    }
    if not report.reproducible:
        doc["run"] = {
            "analyzed_at": report.analyzed_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "argv": report.argv,
            "reproducible": False,
        }
    else:
        doc["run"] = {"reproducible": True}

    if report.error:
        doc["error"] = report.error

    doc["findings"] = [_finding_dict(f) for f in report.findings]
    doc["summary"] = {"counts": report.counts, "total": report.total}
    return doc


def report_to_json(report: Report) -> str:
    """Serialize to a stable, pretty-printed JSON string (trailing newline)."""
    return json.dumps(report_to_dict(report), indent=2, ensure_ascii=False) + "\n"
