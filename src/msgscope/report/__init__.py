"""Report renderers: deterministic JSON and human-readable terminal text."""

from __future__ import annotations

from .json_report import SCHEMA_VERSION, report_to_dict, report_to_json
from .text_report import render as render_text

__all__ = ["SCHEMA_VERSION", "report_to_dict", "report_to_json", "render_text"]
