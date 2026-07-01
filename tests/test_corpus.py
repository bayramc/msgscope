"""Validation harness for a real-world corpus (git-ignored, optional).

Drop real Outlook exports under ``corpus/good/*.msg`` and third-party-generated
files under ``corpus/synthetic/*.msg`` (see ``scripts/capture_corpus.py`` and
CONTRIBUTING.md). These tests then run automatically:

* every known-good file must produce **zero** findings — any finding is a false
  positive to fix or a confidence to lower;
* every known-synthetic file must at least load as a CFB container.

When the corpus folders are empty (the default, e.g. in CI) the tests skip.
"""

from __future__ import annotations

import datetime as _dt
import glob
import os

import pytest

from msgscope import engine
from msgscope.container import MsgContainer

_ROOT = os.path.dirname(os.path.dirname(__file__))
_GOOD = sorted(glob.glob(os.path.join(_ROOT, "corpus", "good", "*.msg")))
_SYNTHETIC = sorted(glob.glob(os.path.join(_ROOT, "corpus", "synthetic", "*.msg")))

# Fixed clock so "future timestamp" checks are deterministic.
_REF = _dt.datetime(2100, 1, 1, tzinfo=_dt.UTC)


def _analyze(path: str):
    with MsgContainer(path) as container:
        return engine.analyze(container, reference_time=_REF, reproducible=True)


@pytest.mark.skipif(not _GOOD, reason="no corpus/good/*.msg (add real Outlook exports locally)")
@pytest.mark.parametrize("path", _GOOD, ids=[os.path.basename(p) for p in _GOOD])
def test_known_good_has_no_findings(path):
    report = _analyze(path)
    assert report.is_cfb, f"{path} is not a CFB container"
    detail = "\n".join(
        f"  {f.id} [{f.severity.value}/{f.confidence.value}]: {f.evidence.observed}"
        for f in report.findings
    )
    assert report.findings == [], f"false positives on known-good file:\n{detail}"


@pytest.mark.skipif(
    not _SYNTHETIC, reason="no corpus/synthetic/*.msg (add generated files locally)"
)
@pytest.mark.parametrize("path", _SYNTHETIC, ids=[os.path.basename(p) for p in _SYNTHETIC])
def test_known_synthetic_loads(path):
    report = _analyze(path)
    assert report.is_cfb, f"{path} is not a CFB container"
