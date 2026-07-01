"""Shared test fixtures.

Makes ``fixtures`` importable, registers the built-in checks, and provides an
``analyze`` helper that runs the engine against fixture bytes with a fixed
reference clock (so ``future timestamp`` checks are deterministic).
"""

from __future__ import annotations

import datetime as _dt
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

import msgscope.checks  # noqa: E402,F401  (registers built-ins on import)
from msgscope import engine  # noqa: E402
from msgscope.container import MsgContainer  # noqa: E402
from msgscope.engine import Report  # noqa: E402

# Far-future reference clock: nothing in the fixtures is "in the future" unless a
# test overrides it.
REF = _dt.datetime(2100, 1, 1, tzinfo=_dt.UTC)


@pytest.fixture
def write_msg(tmp_path):
    def _write(data: bytes, name: str = "sample.msg"):
        path = tmp_path / name
        path.write_bytes(data)
        return path

    return _write


@pytest.fixture
def analyze(write_msg):
    def _analyze(
        data: bytes,
        *,
        select: set[str] | None = None,
        exclude: set[str] | None = None,
        reference_time: _dt.datetime = REF,
    ) -> Report:
        path = write_msg(data)
        with MsgContainer(path) as container:
            return engine.analyze(
                container,
                select=select,
                exclude=exclude,
                reference_time=reference_time,
                reproducible=True,
            )

    return _analyze


def ids(report: Report) -> set[str]:
    return {f.id for f in report.findings}
