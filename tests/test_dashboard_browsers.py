"""The dashboard in real browser engines (2026-09-22).

Runs tests/browser/dashboard_matrix.mjs through Playwright for Chromium,
Firefox and WebKit. Each engine loads three pages -- the real docs/index.html
from the file, the same page served over a local HTTP server (how a static host
serves it), and a failure page (warnings, a failed test run, a dropped scenario,
missing databases) -- at three widths in light and dark, clicking every scenario.

Playwright and its browsers are NOT an ATLAS dependency. They live outside the
repository (default %LOCALAPPDATA%\\ATLAS\\tools\\playwright, or
ATLAS_PLAYWRIGHT_DIR); without them this test skips and says why. An engine that
cannot start on the machine is also skipped with its error, never counted as a
pass: on the 2026-09-22 development PC Playwright's Firefox build fails to start
("side-by-side configuration is incorrect", a missing Windows C++ runtime), so
only Chromium and WebKit ran there.

Since 2026-09-25 the matrix also drives the INSTALLED Google Chrome and
Microsoft Edge (Playwright channels "chrome" and "msedge") and two device
EMULATIONS: WebKit with the iPhone 13 profile and Chromium with the Pixel 7
profile (viewport, user agent, touch, taps). Emulation is labelled as emulation
in every result; it is not iOS Safari and not a phone.

Not covered by any of this: Safari on Apple hardware, real phones, screen
readers, or a hosted (GitHub Pages) copy.
"""

from __future__ import annotations

import functools
import http.server
import json
import os
import re
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "tests" / "browser" / "dashboard_matrix.mjs"


def _playwright_dir() -> Path | None:
    explicit = os.environ.get("ATLAS_PLAYWRIGHT_DIR")
    base = os.environ.get("LOCALAPPDATA")
    for candidate in ([Path(explicit)] if explicit else []) + (
            [Path(base) / "ATLAS" / "tools" / "playwright"] if base else []):
        if (candidate / "node_modules" / "playwright").exists():
            return candidate
    return None


def _node() -> str | None:
    found = shutil.which("node")
    if found:
        return found
    for candidate in (Path.home() / ".local" / "node" / "node.exe", Path.home() / ".local" / "node" / "node"):
        if candidate.exists():
            return str(candidate)
    return None


@pytest.fixture(scope="module")
def pages(tmp_path_factory):
    docs = ROOT / "docs"
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(docs))
    handler.log_message = lambda *a, **k: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    # A failure page: the real page code with a data island describing a failed
    # export -- missing databases, a failed test run, a dropped scenario.
    page = (docs / "index.html").read_text(encoding="utf-8")
    start = '<script id="atlas-data" type="application/json">'
    i = page.index(start) + len(start)
    j = page.index("</script>", i)
    data = json.loads(page[i:j].replace("<\\/", "</"))
    data["snapshot"] = {"available": False}
    data["sweep"]["rows"] = data["sweep"]["rows"][:-1]
    data["measurements"]["tests"] = {"total": 340, "failed_count": 11, "error_count": 0,
                                     "returncode": 1, "failed": True, "method": "executed by this export"}
    data["warnings"] = ["no transaction database on this machine; snapshot omitted",
                        "SIMULATED: a scenario returned HTTP 500",
                        "the test run did not pass: 340 passed, 11 failed, 0 errors (pytest exit status 1)"]
    failure = tmp_path_factory.mktemp("failure-page") / "index.html"
    failure.write_text(page[:i] + json.dumps(data).replace("</", "<\\/") + page[j:], encoding="utf-8")
    try:
        yield {
            "file": (docs / "index.html").as_uri(),
            "served": f"http://127.0.0.1:{server.server_address[1]}/index.html",
            "failure": failure.as_uri(),
        }
    finally:
        server.shutdown()


@pytest.mark.browser
@pytest.mark.parametrize("engine", ["chromium", "firefox", "webkit", "chrome", "msedge",
                                    "iphone-emulated", "android-emulated"])
def test_the_dashboard_in_a_real_browser_engine(engine, pages):
    node, playwright_dir = _node(), _playwright_dir()
    if node is None or playwright_dir is None:
        pytest.skip("Playwright is not installed (see this file's docstring); not an ATLAS dependency")
    run = subprocess.run([node, str(MATRIX), str(playwright_dir), engine,
                          *(f"{label}={url}" for label, url in pages.items())],
                         capture_output=True, encoding="utf-8", errors="replace", timeout=900)
    lines = [line for line in run.stdout.splitlines() if line.startswith("{")]
    assert lines, f"no result from the browser run:\n{run.stdout}\n{run.stderr}"
    result = json.loads(lines[-1])
    if not result["launched"]:
        pytest.skip(f"{engine} could not start on this machine: {result.get('error')}")
    failed = [load for load in result["loads"] if not load["ok"]]
    assert not failed, json.dumps(failed, indent=1)
    viewports = 1 if result["emulated"] else 3
    assert result["viewports"] == viewports
    assert len(result["loads"]) == 3 * viewports * 2, "the matrix did not run every page, width and scheme"
    assert result["emulated"] is engine.endswith("-emulated"), "emulation must be labelled as such"
    assert all(load["clicked"] == load["controls"] > 0 for load in result["loads"])
