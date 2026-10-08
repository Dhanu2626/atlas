"""Location as EVIDENCE, never authority (Phase 3.4 + the approved policy v6 rule, 2026-10-09).

Two location paths reach ATLAS and are graded by the same code
(atlas_service/device/location.py):

  BROWSER  a visitor's REAL position, given by their own browser after they allow it
  GNSS     the ESP32 reading a receiver over UART -- in Wokwi a SIMULATED receiver

What these tests hold ATLAS to:

  * the frozen grading table: MEDIUM needs GNSS <=500 m, <5 min, integrity OK; browser and
    network sources are LOW; HIGH is unreachable without a secure element
  * the geofence against the device's registered home area, and stale / imprecise /
    missing evidence named as such
  * impossible travel recorded as evidence -- no shipped rule acts on it
  * LOCATION CAN ONLY ADD FRICTION: for every payment and every location claim, the
    decision with location is at least as strict as without it. Spoofing "home" gains nothing
  * the security layers come first: a changed location breaks the signature, a replay is
    refused, all before any grading
  * privacy: no coordinates in the response, the audit log or the bank's assertion; the
    previous fix is kept rounded to about 1 km
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from atlas_service import crypto
from atlas_service.db import TransactionStore
from atlas_service.device import location as loc
from atlas_service.device.db import DeviceStore
from atlas_service.device.registry import register_demo_device, set_home_area
from atlas_service.main import (
    app as atlas_app, get_allow_counter_reset, get_bank_client, get_device_store, get_model_registry,
    get_policy_version_store, get_signing_keys_dir, get_step_up_store, get_transaction_store,
)
from atlas_service.policy import engine
from atlas_service.policy.engine import POLICIES_DIR
from atlas_service.policy.version_store import PolicyVersionStore
from atlas_service.step_up.db import StepUpStore
from contracts import (
    GEOFENCE_LOCATION_STALE, GEOFENCE_LOCATION_UNKNOWN, GEOFENCE_OUTSIDE, GEOFENCE_WITHIN, Decision,
    LocationEvidence, RiskEvidence, Transaction,
)
from firmware import device_identity, virtual_device as vd

HOME = loc.HomeArea(17.385044, 78.486671, 10_000)          # Hyderabad, 10 km
NOW = datetime(2026, 10, 9, 6, 30, tzinfo=timezone.utc)
SPOTS = {"home": ("17.385100", "78.486600"), "away": ("17.624800", "78.086700"),   # ~50 km
         "delhi": ("28.613939", "77.209023")}                                     # ~1,250 km


def ev(where="home", *, source="GNSS", accuracy="2.3", age=timedelta(seconds=3), sats=12, now=NOW):
    lat, lon = SPOTS[where]
    return LocationEvidence(source=source, latitude=Decimal(lat), longitude=Decimal(lon),
                            accuracy_m=None if accuracy is None else Decimal(accuracy),
                            captured_at=(now - age).isoformat(), satellites=sats if source == "GNSS" else None)


# ==========================================================================
# 1. Grading: the frozen table
# ==========================================================================

def test_no_evidence_is_unknown():
    for evidence in (None, LocationEvidence(source="NONE")):
        g = loc.grade(evidence, home=HOME, now=NOW)
        assert (g.confidence, g.geofence) == ("UNKNOWN", GEOFENCE_LOCATION_UNKNOWN)


def test_gnss_without_integrity_evidence_is_low_and_says_why():
    g = loc.grade(ev(), home=HOME, now=NOW)
    assert (g.confidence, g.geofence) == ("LOW", GEOFENCE_WITHIN)
    assert any("integrity" in r for r in g.reasons)


def test_gnss_reaches_medium_only_with_every_frozen_condition():
    assert loc.grade(ev(), home=HOME, integrity_ok=True, now=NOW).confidence == "MEDIUM"
    assert loc.grade(ev(accuracy="1800.0"), home=HOME, integrity_ok=True, now=NOW).confidence == "LOW"
    assert loc.grade(ev(accuracy=None), home=HOME, integrity_ok=True, now=NOW).confidence == "LOW"
    assert loc.grade(ev(age=timedelta(minutes=6)), home=HOME, integrity_ok=True, now=NOW).confidence == "LOW"


@pytest.mark.parametrize("source", ["BROWSER", "WIFI", "CELL", "IP", "DECLARED"])
def test_browser_and_network_sources_are_always_low(source):
    g = loc.grade(ev(source=source, accuracy="5"), home=HOME, integrity_ok=True, now=NOW)
    assert g.confidence == "LOW" and g.geofence == GEOFENCE_WITHIN


def test_high_is_unreachable_by_construction():
    for source in ("GNSS", "BROWSER", "WIFI", "CELL", "IP", "DECLARED", "SATELLITE-SECURE"):
        for accuracy in ("0.5", "40", None):
            for integrity in (True, False):
                g = loc.grade(ev(source=source, accuracy=accuracy), home=HOME, integrity_ok=integrity, now=NOW)
                assert g.confidence != "HIGH"
    code = Path(loc.__file__).read_text(encoding="utf-8")
    assert 'confidence="HIGH"' not in code and 'HIGH = "HIGH"' not in code


def test_an_unrecognised_source_is_unknown_not_trusted():
    g = loc.grade(ev(source="QUANTUM"), home=HOME, now=NOW)
    assert (g.confidence, g.geofence) == ("UNKNOWN", GEOFENCE_LOCATION_UNKNOWN)


def test_a_fix_with_no_coordinates_is_unknown_and_named():
    g = loc.grade(LocationEvidence(source="GNSS", satellites=2), home=HOME, now=NOW)
    assert g.confidence == "UNKNOWN" and "no position fix (2 satellites" in g.reasons[0]


@pytest.mark.parametrize("lat,lon", [("91", "78"), ("17", "181"), ("-90.000001", "0")])
def test_impossible_coordinates_are_unknown(lat, lon):
    g = loc.grade(LocationEvidence(source="GNSS", latitude=Decimal(lat), longitude=Decimal(lon),
                                   accuracy_m=Decimal("2"), captured_at=NOW.isoformat()), home=HOME, now=NOW)
    assert g.confidence == "UNKNOWN"


@pytest.mark.parametrize("value", ["NaN", "Infinity", "-Infinity"])
def test_a_non_number_coordinate_is_refused_by_the_contract_itself(value):
    """Never reaches grading: the envelope fails to parse, so the request is malformed."""
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        LocationEvidence(source="GNSS", latitude=Decimal(value), longitude=Decimal("78"))


# ==========================================================================
# 2. Geofence
# ==========================================================================

def test_within_and_outside_the_home_area():
    assert loc.grade(ev("home"), home=HOME, now=NOW).geofence == GEOFENCE_WITHIN
    away = loc.grade(ev("away"), home=HOME, now=NOW)
    assert away.geofence == GEOFENCE_OUTSIDE and 45 < away.distance_from_home_km < 55


def test_a_stale_fix_cannot_place_the_device():
    g = loc.grade(ev("away", age=timedelta(minutes=6)), home=HOME, now=NOW)
    assert g.geofence == GEOFENCE_LOCATION_STALE and g.distance_from_home_km is None


def test_a_capture_time_in_the_future_is_unknown():
    g = loc.grade(ev(age=-timedelta(minutes=10)), home=HOME, now=NOW)
    assert g.confidence == "UNKNOWN"


def test_too_imprecise_to_place_is_unknown_not_outside():
    g = loc.grade(ev("home", source="BROWSER", accuracy="25000"), home=HOME, now=NOW)
    assert g.geofence == GEOFENCE_LOCATION_UNKNOWN


def test_no_home_area_means_no_geofence_answer():
    assert loc.grade(ev("away"), home=None, now=NOW).geofence == GEOFENCE_LOCATION_UNKNOWN


# ==========================================================================
# 3. Impossible travel (evidence only)
# ==========================================================================

def test_impossible_travel_is_flagged_with_its_speed():
    before = loc.PreviousFix(17.39, 78.49, NOW - timedelta(minutes=2))
    g = loc.grade(ev("delhi"), home=HOME, previous=before, now=NOW)
    assert g.implausible_travel and g.implied_speed_kmh > 30_000


def test_ordinary_travel_is_not_flagged():
    an_hour_drive = loc.PreviousFix(17.39, 78.49, NOW - timedelta(minutes=50))
    assert not loc.grade(ev("away"), home=HOME, previous=an_hour_drive, now=NOW).implausible_travel
    a_flight = loc.PreviousFix(17.39, 78.49, NOW - timedelta(hours=3))
    assert not loc.grade(ev("delhi"), home=HOME, previous=a_flight, now=NOW).implausible_travel


def test_short_jumps_are_not_called_impossible():
    """Below 100 km a jump is within what a Wi-Fi or network fallback can produce."""
    just_now = loc.PreviousFix(17.39, 78.49, NOW - timedelta(seconds=5))
    assert not loc.grade(ev("away"), home=HOME, previous=just_now, now=NOW).implausible_travel


# ==========================================================================
# 4. The policy vocabulary: one new optional key
# ==========================================================================

TX = Transaction(transaction_id="t1", subject="user-demo-1", amount="1500.00", currency="INR",
                 beneficiary="ben-mother", location="x", device_id="d",
                 authentication_method="device_button", timestamp="2026-10-08T10:00:00+05:30")
RISK = RiskEvidence(anomaly_score=None, risk_band="INSUFFICIENT_HISTORY", reasons=[])


def _policy(rule_condition):
    return {"version": 1, "rules": [{"name": "r", "condition": rule_condition, "action": "STEP_UP"}]}


def test_geofence_rule_matches_only_its_own_value():
    outside = loc.grade(ev("away"), home=HOME, now=NOW)
    within = loc.grade(ev("home"), home=HOME, now=NOW)
    pol = _policy({"GEOFENCE": GEOFENCE_OUTSIDE})
    assert engine.evaluate(TX, RISK, [], pol, location=outside).decision == Decision.STEP_UP
    assert engine.evaluate(TX, RISK, [], pol, location=within).decision == Decision.ALLOW
    assert engine.evaluate(TX, RISK, [], pol).decision == Decision.ALLOW          # no evidence: nothing judged


def test_a_misspelt_geofence_value_fails_loudly():
    with pytest.raises(ValueError):
        engine.evaluate(TX, RISK, [], _policy({"GEOFENCE": "OUTSIDE"}), location=loc.grade(ev(), home=HOME, now=NOW))


def test_policy_v6_adds_exactly_the_approved_rule_and_nothing_else():
    demo = yaml.safe_load((POLICIES_DIR / "user-demo-1.yaml").read_text(encoding="utf-8"))
    assert demo["version"] == 6
    geo = [r for r in demo["rules"] if "GEOFENCE" in r["condition"]]
    assert geo == [{"name": "outside_home_area", "condition": {"GEOFENCE": "OUTSIDE_GEOFENCE"}, "action": "STEP_UP"}]
    location_keys = {"GEOFENCE", "LOCATION_CONFIDENCE", "DEVICE_TRUST", "IMPOSSIBLE_TRAVEL"}
    for other in ("user-frozen-1.yaml", "user-poor-1.yaml"):
        pol = yaml.safe_load((POLICIES_DIR / other).read_text(encoding="utf-8"))
        assert not any(location_keys & set(r["condition"]) for r in pol["rules"]), other
    assert not any(set(r["condition"]) & (location_keys - {"GEOFENCE"}) for r in demo["rules"])


# ==========================================================================
# 5. End to end through /v2/transact
# ==========================================================================

@pytest.fixture
def atlas(tmp_path, shared_model_registry):
    keys = tmp_path / "keys"
    crypto.init_device(keys_dir=keys)
    from bank_service import db as bank_db
    from bank_service.main import app as bank_app
    from bank_service.main import get_atlas_public_key, get_replay_cache
    from bank_service.replay_cache import ReplayCache
    bank_app.dependency_overrides[get_atlas_public_key] = lambda: crypto.get_public_key(keys_dir=keys)
    bank_app.dependency_overrides[get_replay_cache] = lambda: ReplayCache(tmp_path / "replay.db")
    bank = TestClient(bank_app)
    policy_state = PolicyVersionStore(tmp_path / "policy_state.db")
    for pub in sorted(POLICIES_DIR.glob("*.pub")):
        policy_state.enroll_owner(pub.stem, pub.read_text(encoding="ascii").strip())
    devices = tmp_path / "devices.db"
    atlas_app.dependency_overrides.update({
        get_bank_client: lambda: bank, get_signing_keys_dir: lambda: keys,
        get_transaction_store: lambda: TransactionStore(tmp_path / "atlas.db"),
        get_device_store: lambda: DeviceStore(devices),
        get_step_up_store: lambda: StepUpStore(tmp_path / "step_up.db"),
        get_allow_counter_reset: lambda: False, get_model_registry: lambda: shared_model_registry,
        get_policy_version_store: lambda: policy_state,
    })
    device_keys = tmp_path / "device-keys"
    device_identity.init_device(device_keys)
    store = DeviceStore(devices)
    register_demo_device(store, device_id="esp32-gnss", device_key_id=device_identity.get_key_id(device_keys),
                         public_key=device_identity.get_public_key(device_keys), bound_subject="user-demo-1")
    set_home_area(store, "esp32-gnss", HOME.latitude, HOME.longitude, HOME.radius_m)
    client = TestClient(atlas_app)
    state = {"seq": 0, "last": None, "assertions": []}

    def pay(rupees="1500", payee="ben-mother", where=None, *, hhmm="10:00", age=timedelta(seconds=2),
            source="GNSS", accuracy="2.3", sign_then=None, envelope=None):
        if envelope is None:
            state["seq"] += 1
            now = datetime.now(timezone.utc)
            config = vd.DeviceConfig(atlas_url="http://atlas", device_id="esp32-gnss", subject="user-demo-1",
                                     boot_id="b00t0001", location="x",
                                     presets=(vd.Preset(beneficiary=payee, amount_minor=int(Decimal(rupees) * 100)),))
            day = (now + timedelta(hours=5, minutes=30) - timedelta(days=1)).date()
            h, m = map(int, hhmm.split(":"))
            when = datetime(day.year, day.month, day.day, h, m,
                            tzinfo=timezone(timedelta(hours=5, minutes=30))).isoformat()
            body = vd.assemble_transaction(vd.RawEvent(preset_id=0, pressed_at=when, sequence=state["seq"]), config)
            location = None
            if where is not None:
                location = json.loads(ev(where, source=source, accuracy=accuracy, age=age, now=now)
                                      .model_dump_json())
            envelope = vd.build_envelope(body, config, device_keys, location=location)
            if sign_then:
                envelope = sign_then(envelope)
        state["last"] = envelope
        out = client.post("/v2/transact", params={"rail": "UPI"}, json=envelope).json()
        if out.get("assertion"):
            state["assertions"].append(out["assertion"])
        return out

    pay.store = store
    pay.state = state
    yield pay
    atlas_app.dependency_overrides.clear()
    bank_app.dependency_overrides.clear()
    _ = bank_db


def test_a_payment_at_home_is_decided_as_before(atlas):
    out = atlas("1500", where="home")
    assert out["final_status"] == "ALLOW"
    assert out["location"]["geofence"] == GEOFENCE_WITHIN and out["location"]["confidence"] == "LOW"


def test_outside_the_home_area_the_approved_rule_asks_to_confirm(atlas):
    out = atlas("1500", where="away")
    assert out["final_status"] == "STEP_UP"
    assert out["decision"]["deciding_rule"] == "outside_home_area"


@pytest.mark.parametrize("rupees,payee,hhmm,expected,rule", [
    ("150000", "ben-mother", "10:00", "DENY", "hard_cap"),
    ("60000", "ben-mother", "10:00", "STEP_UP", "large_amount"),
    ("25000", "ben-fresh", "14:00", "STEP_UP", "new_beneficiary_meaningful_amount"),
    ("1500", "ben-mother", "23:30", "STEP_UP", "odd_hours"),
])
def test_faking_home_relaxes_nothing(atlas, rupees, payee, hhmm, expected, rule):
    """The attacker's best move -- claim to be at home -- leaves every other rule in force."""
    out = atlas(rupees, payee, where="home", hhmm=hhmm)
    assert out["final_status"] == expected and out["decision"]["deciding_rule"] == rule


def test_location_can_only_add_friction():
    """Every payment shape, every kind of location claim, under the real signed policy:
    never less strict than with no location at all."""
    severity = {Decision.ALLOW: 0, Decision.STEP_UP: 1, Decision.DELAY: 2, Decision.DENY: 3}
    policy = engine.load_policy(POLICIES_DIR / "user-demo-1.yaml")
    history = [TX.model_copy(update={"transaction_id": f"h{i}", "beneficiary": "ben-mother"}) for i in range(3)]
    crowded = [TX.model_copy(update={"transaction_id": f"c{i}"}) for i in range(25)]
    grades = [None] + [loc.grade(e, home=h, previous=p, now=NOW) for e in (
        ev("home"), ev("away"), ev("delhi"), ev("away", age=timedelta(minutes=7)), ev(age=-timedelta(hours=1)),
        ev("home", source="BROWSER"), ev("away", source="BROWSER", accuracy="50000"), LocationEvidence(source="GNSS"),
        LocationEvidence(source="NONE"), ev(source="QUANTUM"))
        for h in (HOME, None) for p in (None, loc.PreviousFix(28.61, 77.21, NOW - timedelta(minutes=1)))]
    checked = 0
    for amount in ("1500.00", "25000.00", "60000.00", "150000.00"):
        for payee in ("ben-mother", "ben-new"):
            for stamp in ("2026-10-08T10:00:00+05:30", "2026-10-08T23:30:00+05:30"):
                for hist in (history, crowded):
                    tx = TX.model_copy(update={"amount": Decimal(amount), "beneficiary": payee, "timestamp": stamp})
                    without = engine.evaluate(tx, RISK, hist, policy).decision
                    for g in grades:
                        got = engine.evaluate(tx, RISK, hist, policy, location=g).decision
                        assert severity[got] >= severity[without], (amount, payee, stamp, g)
                        checked += 1
    assert checked > 1000


def test_stale_or_imprecise_evidence_adds_no_rule(atlas):
    """The approved rule names OUTSIDE only; old or vague evidence is shown, not acted on."""
    stale = atlas("1500", where="away", age=timedelta(minutes=7))
    assert stale["location"]["geofence"] == GEOFENCE_LOCATION_STALE and stale["final_status"] == "ALLOW"
    vague = atlas("1500", where="away", source="BROWSER", accuracy="50000")
    assert vague["location"]["geofence"] == GEOFENCE_LOCATION_UNKNOWN and vague["final_status"] == "ALLOW"


def test_impossible_travel_is_reported_alongside_the_decision(atlas):
    atlas("1500", where="home")
    out = atlas("1500", where="delhi")
    assert out["location"]["implausible_travel"] is True
    assert out["decision"]["deciding_rule"] == "outside_home_area"          # no rule acts on travel itself


def test_a_changed_location_breaks_the_device_signature(atlas):
    def move(envelope):
        envelope["location"]["latitude"] = "17.385044"   # "home", rewritten in flight
        return envelope
    out = atlas("1500", where="away", sign_then=move)
    assert (out["final_status"], out["decision_reason"]) == ("FAIL_CLOSED", "INVALID_DEVICE_SIGNATURE")
    assert "location" not in out                         # nothing unauthenticated is graded


def test_a_replayed_location_is_refused_before_grading(atlas):
    atlas("1500", where="home")
    out = atlas(envelope=atlas.state["last"])
    assert out["final_status"] == "FAIL_CLOSED" and out["decision_reason"] == "COUNTER_REGRESSION"
    assert "location" not in out


def test_no_coordinates_in_the_response_the_log_or_the_bank_assertion(atlas, caplog):
    import atlas_service.main as atlas_main
    atlas_main.logger.addHandler(caplog.handler)
    try:
        with caplog.at_level(logging.INFO, logger=atlas_main.logger.name):
            out = atlas("1500", where="away")
            atlas("1500", where="home")
    finally:
        atlas_main.logger.removeHandler(caplog.handler)
    text = json.dumps(out) + caplog.text + json.dumps(atlas.state["assertions"])
    for lat, lon in SPOTS.values():
        for token in (lat, lon, lat[:6], lon[:6]):
            assert token not in text, token
    assert "[LOCATION]" in caplog.text and "geofence=OUTSIDE_GEOFENCE" in caplog.text
    assert atlas.state["assertions"] and all("location" not in json.dumps(a["payload"]) for a in atlas.state["assertions"])


def test_the_previous_fix_is_kept_rounded_to_about_a_kilometre(atlas):
    atlas("1500", where="home")
    row = atlas.store.get_last_fix("esp32-gnss")
    assert (row["latitude"], row["longitude"]) == (17.39, 78.49)


def test_payments_without_location_are_unchanged(atlas):
    outs = [atlas(r) for r in ("1500", "60000", "150000")]
    assert [o["final_status"] for o in outs] == ["ALLOW", "STEP_UP", "DENY"]
    assert all(o["location"]["confidence"] == "UNKNOWN" for o in outs)
    assert atlas.store.get_last_fix("esp32-gnss") is None


# ==========================================================================
# 6. Path A: the visitor's real location on the "Run it live" page
# ==========================================================================

LIVE = Path(__file__).resolve().parent.parent / "docs" / "live"
PAGE = (LIVE / "index.html").read_text(encoding="utf-8")


def test_the_page_asks_for_location_only_when_the_visitor_acts():
    """One call site for the browser's position, reached only from the visitor's own
    clicks (Use my real location, the home-area menu, SEND) -- never on load, never
    watched in the background."""
    assert PAGE.count("getCurrentPosition") == 1 and "watchPosition" not in PAGE
    callers = [line.strip() for line in PAGE.splitlines() if "position()" in line and "function position" not in line]
    assert callers and all(("await position()" in c) for c in callers), callers
    assert '$("useloc").addEventListener("click", useLocation)' in PAGE
    assert "if (!locOn) return call(" in PAGE      # no permission given: payments carry no location


def test_the_page_never_shows_stores_or_sends_coordinates():
    for forbidden in ("localStorage", "sessionStorage", "indexedDB", "sendBeacon", "XMLHttpRequest", "WebSocket"):
        assert forbidden not in PAGE, forbidden
    shown = [line for line in PAGE.splitlines() if "coords.latitude" in line or "coords.longitude" in line]
    assert shown and all("live.pay(" in line or "live.set_home_here(" in line for line in shown), shown
    assert "coords.accuracy" in PAGE                 # the only number about the position the page shows


def test_the_page_says_the_browser_location_is_real_and_the_gnss_simulated():
    assert "your location is <b>real</b>" in PAGE and "<b>simulated</b>" in PAGE
    assert "graded <b>LOW</b> confidence" in PAGE


def test_every_visitor_brings_their_own_location():
    """No fixed city stands in for the visitor: the place label is "unstated" and the
    home area is the visitor's own position or a city they pick."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("atlas_browser_for_test", LIVE / "atlas_browser.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    assert runner.PLACE_LABEL == "unstated"
    src = (LIVE / "atlas_browser.py").read_text(encoding="utf-8")
    assert "Hyderabad,IN" not in src
    ev = runner.browser_evidence(12.9, 77.6, 35.4, 1_760_000_000_000)
    assert ev["source"] == "BROWSER" and ev["latitude"] == "12.900000" and ev["accuracy_m"] == "35.4"
    LocationEvidence(**ev)                            # the contract accepts exactly this shape
    for bad in ((91, 0, 5, 1), (0, 181, 5, 1), (float("nan"), 0, 5, 1), (0, 0, -1, 1), ("x", 0, 5, 1)):
        with pytest.raises(ValueError):
            runner.browser_evidence(*bad)


def test_the_page_stamps_a_position_with_its_own_clock():
    """Browsers disagree on position.timestamp (WebKit gives microseconds, found
    2026-10-09 by the WebKit run), so the page records when the position arrived,
    as the ESP32 stamps a fix with its own clock."""
    assert "received: Date.now()" in PAGE and "pos.received" in PAGE
    assert ".timestamp)" not in PAGE and "pos.timestamp" not in PAGE
