"""Runs the dashboard page's own JavaScript tests as part of the Python suite.

The assertions live in tests/js/dashboard_page_tests.mjs, because the thing
under test is JavaScript and running it in a JavaScript engine is the only way
to test it honestly. This wrapper is here so `pytest` alone runs everything and
a failure in the page shows up in the same place as a failure in the service.

Node is not a dependency of ATLAS. Without it the page tests are skipped, and
the skip says so rather than passing silently.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "tests" / "js" / "dashboard_page_tests.mjs"


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    for candidate in (Path.home() / ".local" / "node" / "node.exe",
                      Path.home() / ".local" / "node" / "node"):
        if candidate.exists():
            return str(candidate)
    return None


@pytest.mark.js
def test_the_dashboard_pages_javascript_passes_its_own_tests():
    node = _node()
    if node is None:
        pytest.skip("node not found; the dashboard page's JavaScript tests need it")

    run = subprocess.run([node, str(RUNNER)], cwd=ROOT, capture_output=True,
                         encoding="utf-8", errors="replace", timeout=300)

    summary = run.stdout.strip().splitlines()[-1] if run.stdout.strip() else "(no output)"
    assert run.returncode == 0, f"{summary}\n{run.stdout}\n{run.stderr}"
    assert summary.endswith("0 failed"), summary
    passed = int(summary.split(" ")[0])
    assert passed >= 29, f"the page's test file shrank unexpectedly: {summary}"
