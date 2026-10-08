"""Parity: the "Run it live" page decides exactly as the real ATLAS does (2026-10-02).

The page runs ATLAS's real code in the browser through three adapters (no threads, an
in-process bank call, scrypt from `cryptography`). These tests send the same payments
three ways and require identical answers -- decision, reason, deciding rule, every
matched rule, the bank's verdict and the LED:

  1. the REAL desktop path: FastAPI's thread pool, the bank over HTTP (TestClient),
     ATLAS's code untouched -- the reference;
  2. the browser runner on CPython, adapters on, in a separate interpreter (so its
     patches can never leak into this test process);
  3. opt-in (ATLAS_LIVE_BROWSER=1): the real page in a real browser, with Pyodide from
     jsDelivr -- what a visitor runs. GitHub Actions runs it on every push.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LIVE = ROOT / "docs" / "live"
sys.path.insert(0, str(LIVE))
import atlas_browser  # noqa: E402

KEYS = ("final_status", "decision_reason", "deciding_rule", "matched_rules", "bank_approved", "led")


def _where(r: dict) -> tuple:
    """The location grade, as compared: confidence and geofence (distances differ by
    metres between runs, so they are not compared)."""
    loc = r.get("location") or {}
    return (loc.get("confidence"), loc.get("geofence"))


def shape(results: list[dict]) -> list[tuple]:
    return [(r["label"],) + tuple(sorted(r[k]) if k == "matched_rules" else r[k] for k in KEYS) + (_where(r),)
            for r in results]


def real_desktop_path(tmp_path: Path) -> list[dict]:
    """The reference: ATLAS and the bank exactly as the test suite and demo.py run them."""
    from fastapi.testclient import TestClient

    from atlas_service import crypto
    from atlas_service.db import TransactionStore
    from atlas_service.device.db import DeviceStore
    from atlas_service.device.registry import register_demo_device, set_home_area
    from atlas_service.main import (
        app as atlas_app, get_allow_counter_reset, get_bank_client, get_device_store, get_model_registry,
        get_policy_version_store, get_signing_keys_dir, get_step_up_store, get_transaction_store,
    )
    from atlas_service.ml import registry as model_registry
    from atlas_service.policy.engine import POLICIES_DIR
    from atlas_service.policy.version_store import PolicyVersionStore
    from atlas_service.step_up.db import StepUpStore
    from bank_service import db as bank_db
    from bank_service.main import app as bank_app
    from bank_service.main import get_atlas_public_key, get_replay_cache
    from bank_service.replay_cache import ReplayCache
    from firmware import device_identity, virtual_device as vd

    live_ledger = bank_db.DEFAULT_DB_PATH
    bank_db.DEFAULT_DB_PATH = tmp_path / "bank_ledger.db"
    try:
        keys = tmp_path / "keys"
        crypto.init_device(keys_dir=keys)
        models = tmp_path / "models"
        model_registry.save(model_registry.train_subject(atlas_browser.SUBJECT), models)
        registry = model_registry.ModelRegistry(models)
        bank_app.dependency_overrides[get_atlas_public_key] = lambda: crypto.get_public_key(keys_dir=keys)
        bank_app.dependency_overrides[get_replay_cache] = lambda: ReplayCache(tmp_path / "replay.db")
        bank = TestClient(bank_app)
        policy_state = PolicyVersionStore(tmp_path / "policy_state.db")
        for pub in sorted(POLICIES_DIR.glob("*.pub")):
            policy_state.enroll_owner(pub.stem, pub.read_text(encoding="ascii").strip())
        atlas_app.dependency_overrides.update({
            get_bank_client: lambda: bank, get_signing_keys_dir: lambda: keys,
            get_transaction_store: lambda: TransactionStore(tmp_path / "atlas.db"),
            get_device_store: lambda: DeviceStore(tmp_path / "devices.db"),
            get_step_up_store: lambda: StepUpStore(tmp_path / "step_up.db"),
            get_allow_counter_reset: lambda: False, get_model_registry: lambda: registry,
            get_policy_version_store: lambda: policy_state,
        })
        atlas = TestClient(atlas_app)
        device_keys = tmp_path / "device-keys"
        device_identity.init_device(device_keys)
        register_demo_device(DeviceStore(tmp_path / "devices.db"), device_id=atlas_browser.DEVICE_ID,
                             device_key_id=device_identity.get_key_id(device_keys),
                             public_key=device_identity.get_public_key(device_keys),
                             bound_subject=atlas_browser.SUBJECT)
        boot = vd.new_boot_id()
        results, envelope, home_set = [], None, False

        def post(env, label):
            out = atlas.post("/v2/transact", params={"rail": "UPI"}, json=env).json()
            return {"label": label, "final_status": out.get("final_status"), "decision_reason": out.get("decision_reason"),
                    "deciding_rule": (out.get("decision") or {}).get("deciding_rule"),
                    "matched_rules": (out.get("decision") or {}).get("matched_rules") or [],
                    "bank_approved": (out.get("bank_verdict") or {}).get("approved"),
                    "led": vd.led_for(vd.interpret_response(out)).value, "location": out.get("location")}

        for seq, (label, payee, rupees, hhmm, where) in enumerate(atlas_browser.SCENARIOS, start=1):
            location = None
            if where is not None:
                lat, lon, accuracy = atlas_browser.PARITY_SPOTS[where]
                if not home_set:
                    set_home_area(DeviceStore(tmp_path / "devices.db"), atlas_browser.DEVICE_ID, lat, lon,
                                  atlas_browser.HOME_RADIUS_M)
                    home_set = True
                location = atlas_browser.browser_evidence(lat, lon, accuracy, time.time() * 1000)
            config = vd.DeviceConfig(atlas_url="http://atlas", device_id=atlas_browser.DEVICE_ID,
                                     subject=atlas_browser.SUBJECT, boot_id=boot, location=atlas_browser.PLACE_LABEL,
                                     presets=(vd.Preset(beneficiary=payee, amount_minor=round(float(rupees) * 100)),))
            body = vd.assemble_transaction(vd.RawEvent(preset_id=0, pressed_at=atlas_browser._yesterday_at(hhmm),
                                                       sequence=seq), config)
            envelope = vd.build_envelope(body, config, device_keys, location=location)
            results.append(post(envelope, label))
        results.append(post(envelope, "replay"))
        return results
    finally:
        bank_db.DEFAULT_DB_PATH = live_ledger
        atlas_app.dependency_overrides.clear()
        bank_app.dependency_overrides.clear()


EXPECTED_OUTCOMES = ["ALLOW", "STEP_UP", "DENY", "STEP_UP", "STEP_UP", "ALLOW", "ALLOW", "STEP_UP", "FAIL_CLOSED"]


def test_the_reference_path_gives_the_answers_the_policy_requires(tmp_path):
    ref = real_desktop_path(tmp_path)
    assert [r["final_status"] for r in ref] == EXPECTED_OUTCOMES
    assert [r["deciding_rule"] for r in ref[:5]] == [None, "large_amount", "hard_cap", "odd_hours",
                                                     "new_beneficiary_meaningful_amount"]
    assert ref[-1]["decision_reason"] == "COUNTER_REGRESSION"
    # The visitor's shared location (real on the page; fixed spots here): inside the home
    # area changes nothing, outside it the policy's v6 rule asks to confirm. Browser
    # positions are LOW confidence -- the browser does not say how it placed itself.
    assert [r["location"] for r in ref[:6]] == [{"source": "NONE", "confidence": "UNKNOWN",
                                                 "geofence": "LOCATION_UNKNOWN", "distance_from_home_km": None,
                                                 "fix_age_s": None, "implausible_travel": False,
                                                 "implied_speed_kmh": None,
                                                 "reasons": ["the device sent no location evidence"]}] * 6
    assert _where(ref[6]) == ("LOW", "WITHIN_GEOFENCE") and ref[6]["deciding_rule"] is None
    assert _where(ref[7]) == ("LOW", "OUTSIDE_GEOFENCE") and ref[7]["deciding_rule"] == "outside_home_area"


def test_the_browser_runner_decides_exactly_like_the_real_services(tmp_path):
    """Adapters on, in their own interpreter; the answers must equal the reference."""
    run = subprocess.run([sys.executable, "-W", "ignore", str(LIVE / "atlas_browser.py"), str(tmp_path / "runner")],
                         capture_output=True, text=True, timeout=600, cwd=ROOT)
    assert run.returncode == 0, run.stderr[-2000:]
    got = json.loads(run.stdout.strip().splitlines()[-1])
    assert "bank: in-process verify_endpoint" in got["info"]["adapters"]
    assert shape(got["results"]) == shape(real_desktop_path(tmp_path / "reference"))


@pytest.mark.skipif(os.environ.get("ATLAS_LIVE_BROWSER") != "1",
                    reason="set ATLAS_LIVE_BROWSER=1 to run the real page in a browser (downloads Pyodide from jsDelivr)")
def test_the_real_page_in_a_real_browser_decides_exactly_like_the_real_services(tmp_path):
    from tests.test_dashboard_browsers import _node, _playwright_dir

    node, pw = _node(), _playwright_dir()
    if node is None or pw is None:
        # Asked for explicitly (ATLAS_LIVE_BROWSER=1, as GitHub Actions does): a missing tool
        # is a FAILURE, never a silent skip -- a green check must mean the browser really ran.
        pytest.fail(f"ATLAS_LIVE_BROWSER=1 but the browser cannot run: node={node!r}, Playwright={pw!r}")
    engine = os.environ.get("ATLAS_LIVE_ENGINE", "chromium")
    script = {"scenarios": atlas_browser.SCENARIOS, "spots": atlas_browser.PARITY_SPOTS}
    run = subprocess.run([node, str(ROOT / "tests" / "browser" / "live_page.mjs"), str(pw), str(ROOT / "docs"),
                          json.dumps(script), engine],
                         capture_output=True, text=True, encoding="utf-8", timeout=900)
    assert run.returncode == 0, run.stderr[-2000:]
    got = json.loads(run.stdout.strip().splitlines()[-1])
    assert got["error"] is None, got["error"]
    assert got["ready"]["platform"] == "emscripten"                       # really in the browser
    assert got["origins_before_click"] == ["https://atlas.live"]           # nothing until the click
    assert set(got["origins"]) <= {"https://atlas.live", "https://cdn.jsdelivr.net"}
    assert got["page_errors"] == []
    reference = real_desktop_path(tmp_path)
    matched = sum(a == b for a, b in zip(shape(got["results"]), shape(reference)))
    report = os.environ.get("ATLAS_LIVE_REPORT")
    if report:                                   # what the workflow publishes as a public note
        Path(report).write_text(json.dumps({
            "ran": True, "engine": engine, "platform": got["ready"]["platform"],
            "python": got["ready"]["python"], "startup_s": round(got["startup_s"], 1),
            "matched": matched, "total": len(reference),
            "origins_before_click": got["origins_before_click"], "origins": sorted(got["origins"]),
        }), encoding="utf-8")
    assert shape(got["results"]) == shape(reference)
    assert got["shown_led"] == ["RED"]                                    # the page lit what it said
