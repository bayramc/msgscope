"""The tool must never modify the input, and must record its SHA-256."""

from __future__ import annotations

import hashlib

from fixtures.builders import good_message
from msgscope import engine
from msgscope.container import MsgContainer


def test_input_bytes_unchanged_after_run(write_msg):
    m = good_message()
    m.add_stream("__substg1.0_80050102", b"orphan bytes")
    data = m.build_bytes()
    path = write_msg(data)

    before = hashlib.sha256(path.read_bytes()).hexdigest()
    with MsgContainer(path) as container:
        engine.analyze(container, reproducible=True)
    after = hashlib.sha256(path.read_bytes()).hexdigest()

    assert before == after


def test_recorded_sha256_matches_file(write_msg):
    data = good_message().build_bytes()
    path = write_msg(data)
    expected = hashlib.sha256(data).hexdigest()
    with MsgContainer(path) as container:
        report = engine.analyze(container, reproducible=True)
    assert report.sha256 == expected
    assert container.sha256 == expected
