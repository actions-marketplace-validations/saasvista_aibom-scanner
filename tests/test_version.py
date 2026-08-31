"""The package version and the packaging metadata must not drift apart."""

import re
from pathlib import Path

from aibom_scanner import __version__

PYPROJECT = Path(__file__).parent.parent / "pyproject.toml"


def test_version_matches_pyproject():
    match = re.search(r'^version = "([^"]+)"', PYPROJECT.read_text(), re.MULTILINE)
    assert match, "no version field in pyproject.toml"
    assert match.group(1) == __version__
