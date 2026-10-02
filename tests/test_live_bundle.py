"""The "Run it live" page (docs/live/) and the ATLAS bundle it runs (2026-10-02).

The page runs ATLAS's real code in the visitor's browser. These tests pin what makes
that trustworthy: the bundle is exactly the repository's current source (never stale,
never a secret), the page loads nothing until the visitor clicks, and the one outside
script it then loads is pinned to a version and an integrity hash.
"""

from __future__ import annotations

import io
import json
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIVE = ROOT / "docs" / "live"
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(LIVE))
import atlas_browser  # noqa: E402
import build_live_bundle as blb  # noqa: E402

PAGE = (LIVE / "index.html").read_text(encoding="utf-8")


# --------------------------------------------------------------- the bundle

def test_the_published_bundle_is_exactly_the_current_source():
    assert blb.main(["--check"]) == 0, "docs/live is stale: run python scripts/build_live_bundle.py"


def test_the_bundle_is_deterministic():
    assert blb.build()[0] == blb.build()[0]


def test_the_bundle_holds_only_atlas_source_and_never_a_secret():
    names = zipfile.ZipFile(io.BytesIO((LIVE / "atlas-bundle.zip").read_bytes())).namelist()
    assert names == sorted(names) and len(names) == json.loads((LIVE / "atlas-bundle.json").read_text())["file_count"]
    for n in names:
        assert not n.endswith((".key", ".db", ".pem")) and Path(n).name not in ("secrets.h", "atlas_ca.h"), n
        assert not n.startswith(("tests/", "scripts/", "docs/", "dev-certs/", "ledger/")), n
        assert re.fullmatch(r"(contracts|keystore)\.py|atlas_service/.+|bank_service/.+|firmware/[a-z_]+\.py", n), n
    for needed in ("atlas_service/main.py", "bank_service/main.py", "contracts.py", "keystore.py",
                   "firmware/virtual_device.py", "atlas_service/policy/policies/user-demo-1.yaml",
                   "atlas_service/policy/policies/user-demo-1.yaml.sig", "atlas_service/policy/policies/user-demo-1.pub"):
        assert needed in names, needed


def test_a_secret_looking_file_is_refused_even_if_tracked(monkeypatch):
    monkeypatch.setattr(blb.subprocess, "run", lambda *a, **k: type("R", (), {"stdout": "contracts.py\natlas_service/keys/atlas.key\n"})())
    try:
        blb.tracked_files()
    except SystemExit as exc:
        assert "refusing" in str(exc)
    else:
        raise AssertionError("a .key file was accepted into the bundle")


# --------------------------------------------------------------- the page

def test_nothing_is_loaded_until_the_visitor_clicks():
    assert not re.search(r"<script[^>]+src=", PAGE, re.I), "a script tag loads before the click"
    assert not re.search(r"<link[^>]+(stylesheet|preload|prefetch|modulepreload)", PAGE, re.I)
    assert "createElement(\"script\")" in PAGE and '$("go").addEventListener("click", start)' in PAGE


def test_the_outside_script_is_pinned_and_integrity_checked():
    url = re.search(r'PYODIDE_URL = "([^"]+)"', PAGE).group(1)
    sri = re.search(r'PYODIDE_SRI = "([^"]+)"', PAGE).group(1)
    assert url == "https://cdn.jsdelivr.net/pyodide/v314.0.7/full/pyodide.js"
    assert re.fullmatch(r"sha384-[A-Za-z0-9+/]{64}", sri)
    assert "s.integrity = PYODIDE_SRI" in PAGE and 's.crossOrigin = "anonymous"' in PAGE


def test_the_page_talks_only_to_itself_and_the_pinned_cdn():
    urls = set(re.findall(r"https?://[^\s\"'<>)]+", PAGE))
    allowed = {"https://cdn.jsdelivr.net/pyodide/v314.0.7/full/pyodide.js", "https://github.com/Dhanu2626/atlas"}
    assert urls <= allowed, urls - allowed
    fetched = set(re.findall(r'fetch\("([^"]+)"', PAGE))
    assert fetched == {"atlas-bundle.zip", "atlas-bundle.json", "atlas_browser.py"}
    for banned in ("XMLHttpRequest", "WebSocket", "sendBeacon", "localStorage", "document.cookie"):
        assert banned not in PAGE, banned


def test_the_page_refuses_a_bundle_that_does_not_match_its_hash():
    assert "manifest.bundle_sha256" in PAGE and "refusing to run it" in PAGE


def test_the_page_says_what_it_downloads_and_offers_the_replay_instead():
    for words in ("39 MB", "cdn.jsdelivr.net", "Pyodide 314.0.7", "Just watch the recorded runs", "What is simulated, plainly"):
        assert words in PAGE, words


def test_the_page_and_the_runner_agree_on_the_setup_steps():
    drawn = re.findall(r'\["(step_\w+)", "([^"]+)"\]', PAGE)
    assert [(m, l) for m, l in drawn] == [(m, l) for l, m in atlas_browser.LiveAtlas.STEPS]


def test_the_dashboard_offers_the_live_page():
    dashboard = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
    assert 'href=\\"live/\\"' in dashboard          # inside the page's JavaScript string


# --------------------------------------------------------------- the runner's input checks

def test_the_runner_rejects_bad_payment_input_before_anything_is_signed():
    import asyncio

    live = atlas_browser.LiveAtlas("unused")
    live.vd = None                                   # anything past validation would fail loudly
    for payee, rupees, hhmm, message in (
        ("ben mother", "100", "10:00", "payee"), ("x" * 41, "100", "10:00", "payee"),
        ("ben-mother", "0", "10:00", "amount"), ("ben-mother", "-5", "10:00", "amount"),
        ("ben-mother", "200000001", "10:00", "amount"), ("ben-mother", "100", "24:00", "time"),
        ("ben-mother", "100", "9am", "time"),
    ):
        try:
            asyncio.run(live.pay(payee, rupees, hhmm))
        except ValueError as exc:
            assert message in str(exc).lower(), (payee, rupees, hhmm, exc)
        else:
            raise AssertionError(f"accepted {payee!r} {rupees!r} {hhmm!r}")


# --------------------------------------------------------------- the freshness check (2026-10-02)
# GitHub's Linux runner rebuilt the bundle byte-differently from Windows (zipfile records
# the building OS; compressors vary) although every file was identical. The check now
# compares contents, so these pin that it still catches what matters.

def _repack(tmp_path, *, stored=False, tamper=None):
    import hashlib

    src = zipfile.ZipFile(io.BytesIO((LIVE / "atlas-bundle.zip").read_bytes()))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED) as out:
        for name in src.namelist():
            data = src.read(name)
            if name == tamper:
                data += b"\n# tampered\n"
            out.writestr(name, data)
    blob = buf.getvalue()
    manifest = json.loads((LIVE / "atlas-bundle.json").read_text(encoding="utf-8"))
    manifest["bundle_sha256"] = hashlib.sha256(blob).hexdigest()       # a consistent pair
    (tmp_path / "b.zip").write_bytes(blob)
    (tmp_path / "b.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path / "b.zip", tmp_path / "b.json"


def test_the_check_accepts_the_same_files_packed_differently(tmp_path):
    assert blb.check(*_repack(tmp_path, stored=True)) == []


def test_the_check_catches_a_changed_file_inside_the_zip(tmp_path):
    problems = blb.check(*_repack(tmp_path, tamper="atlas_service/policy/engine.py"))
    assert problems and "atlas_service/policy/engine.py" in problems[0]


def test_the_check_catches_a_zip_that_does_not_match_its_published_hash(tmp_path):
    bundle, manifest = _repack(tmp_path)
    bundle.write_bytes(bundle.read_bytes() + b"x")
    assert any("bundle_sha256" in p for p in blb.check(bundle, manifest))
