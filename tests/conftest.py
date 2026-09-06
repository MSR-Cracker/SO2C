"""Regression tests: run against the repository's own sample library.

Add ``input/lib.so`` (a real dex2c-compiled arm64 shared object) to the repo
root to exercise the full analysis pipeline.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from so2c.engine import Analysis, load_elf  # noqa: E402

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
LIB = os.path.join(ROOT, "input", "lib.so")

REQUIRES_SAMPLE = pytest.mark.skipif(
    not os.path.exists(LIB),
    reason="input/lib.so sample not present in repository",
)


@pytest.fixture
def analysis():
    return Analysis(load_elf(LIB))