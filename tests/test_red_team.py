"""Phase 3.8's dedicated red-team suite (built 2026-09-22).

The source of truth is the attack list Dhanush gave when Phase 3 was specified
(PHASE3-SPEC.md, section H: "the 25 attacks ... each with an explicit expected
outcome"). CATALOGUE below is that list, in its original order, with the outcome
each attack must produce in this release. Every attack is driven through the
real services on temporary stores -- signed envelopes to /v2/transact, a real
bank_service behind it -- not against a mock.

The governing rule from the same brief: UNKNOWN / UNVERIFIED = NOT TRUSTED. No
attack below may end in ALLOW, and none may reach the bank unless the request is
genuine and the policy allowed it.

Three outcomes are stated with care because the capability they probe is only
partly built, and the suite records what actually happens rather than what a
finished system would do:

  * 19 -- device health is carried inside the signed envelope (tamper-evident)
    but graded by nothing yet (Phase 3.5 is not built). The pinned outcome is that
    it neither authorizes nor refuses.
  * 18 -- CHANGED 2026-10-09, recorded here as the directive asks. Until then
    location was pinned like 19 ("not graded, Phase 3.4 not built"). Phase 3.4 now
    grades it, and policy v6 (approved by Dhanush) acts on it, so the attack's
    outcome is STRONGER, never weaker: a fix outside the device's home area is
    graded OUTSIDE_GEOFENCE and the ₹1,500 payment that was ALLOW becomes STEP_UP
    by outside_home_area; ₹1,50,000 stays DENY; a fix moved after signing is still
    INVALID_DEVICE_SIGNATURE. Location still cannot authorize anything.
  * 20 -- the velocity rule fires at the policy layer AND in the running service.
    Until 2026-09-23 the service supplied it the subject's modelled history, so a
    live burst did not trip it and this suite pinned that as found. Changing the
    history source was an explicit architecture decision, taken on 2026-09-23:
    decisions now read the subject's own persisted payments (tests/test_live_history.py).
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from atlas_service.db import TransactionStore
from atlas_service.device.db import DeviceStore
from atlas_service.device.registry import register_demo_device, revoke, set_home_area
from atlas_service.main import (
    app as atlas_app,
    get_allow_counter_reset,
    get_bank_client,
    get_device_store,
    get_model_registry,
    get_signing_keys_dir,
    get_step_up_store,
    get_transaction_store,
)
from atlas_service.ml.registry import ModelRegistry
from atlas_service.ml.synth import Persona, generate_normal_history
from atlas_service.policy.engine import POLICIES_DIR, evaluate, load_policy
from atlas_service.step_up.db import StepUpStore
from bank_service.main import app as bank_app
from contracts import (
    DeviceEnvelope,
    DeviceHealth,
    LocationEvidence,
    RiskEvidence,
    Transaction,
    canonical_envelope_bytes,
)
from firmware import device_identity
from firmware import virtual_device as vd
from tests.conftest import wire_bank_app_to_keys

DEVICE_ID = "esp32-atlas-redteam-01"
SUBJECT = "user-demo-1"

#: (id, attack, explicit expected outcome) -- the 25 attacks, original order.
CATALOGUE = [
    (1, "Fake device_id", "FAIL_CLOSED: DEVICE_UNKNOWN for an unenrolled key; DEVICE_ID_MISMATCH for a signed but wrong device_id"),
    (2, "Unknown device", "FAIL_CLOSED: DEVICE_UNKNOWN"),
    (3, "Revoked device", "FAIL_CLOSED: DEVICE_REVOKED"),
    (4, "Modified amount", "FAIL_CLOSED: INVALID_DEVICE_SIGNATURE"),
    (5, "Modified beneficiary", "FAIL_CLOSED: INVALID_DEVICE_SIGNATURE"),
    (6, "Modified currency", "FAIL_CLOSED: INVALID_DEVICE_SIGNATURE"),
    (7, "Modified location", "FAIL_CLOSED: INVALID_DEVICE_SIGNATURE"),
    (8, "Modified timestamp", "FAIL_CLOSED: INVALID_DEVICE_SIGNATURE"),
    (9, "Invalid signature", "FAIL_CLOSED: INVALID_DEVICE_SIGNATURE"),
    (10, "Missing signature", "FAIL_CLOSED: MISSING_DEVICE_SIGNATURE"),
    (11, "Replayed transaction", "FAIL_CLOSED: COUNTER_REGRESSION (the first of three replay layers to answer)"),
    (12, "Replayed nonce", "FAIL_CLOSED: REPLAYED_NONCE, even with a fresh counter and a valid signature"),
    (13, "Stale request", "FAIL_CLOSED: STALE_REQUEST (issued_at more than 5 minutes old)"),
    (14, "Future timestamp", "FAIL_CLOSED: FUTURE_TIMESTAMP (issued_at more than 5 minutes ahead)"),
    (15, "Backend unavailable", "device: FAIL_CLOSED, red LED, never green"),
    (16, "Bank unavailable", "PENDING: BANK_UNREACHABLE, transaction UNKNOWN for reconciliation, never ALLOW"),
    (17, "ML unavailable", "FAIL_CLOSED: INTERNAL_ERROR, nothing persisted, bank not contacted"),
    (18, "Location outside geofence", "graded OUTSIDE_GEOFENCE (Phase 3.4): STEP_UP by outside_home_area where it was ALLOW, DENY stays DENY, never ALLOW; moved after signing: INVALID_DEVICE_SIGNATURE"),
    (19, "Firmware integrity failure", "signed and tamper-evident but not graded (Phase 3.5 not built): the decision is the policy's, unchanged"),
    (20, "Excessive transaction velocity", "DENY by velocity_burst, at the policy layer and in the running service: since 2026-09-23 the service counts the subject's own persisted payments, so a live burst trips it from the 21st payment"),
    (21, "New beneficiary + high amount", "STEP_UP by new_beneficiary_meaningful_amount; not signed; bank not contacted"),
    (22, "Multiple failed attempts", "each refused FAIL_CLOSED with no state change and no lockout; the genuine request still succeeds"),
    (23, "Malformed JSON", "HTTP 422, FAIL_CLOSED: MALFORMED_ENVELOPE, nothing persisted, input not echoed"),
    (24, "Oversized request", "HTTP 413, FAIL_CLOSED: MALFORMED_ENVELOPE, refused before parsing"),
    (25, "Duplicate transaction ID", "FAIL_CLOSED: DUPLICATE_TRANSACTION_ID, even with a fresh counter and nonce"),
]


# ---- the real services on temporary stores ----------------------------------------

@pytest.fixture
def device_keys(tmp_path) -> Path:
    keys = tmp_path / "device-keys"
    device_identity.init_device(keys)
    return keys


@pytest.fixture
def rig(tmp_path, device_keys):
    device_db = tmp_path / "devices.db"
    store = DeviceStore(device_db)
    register_demo_device(store, device_id=DEVICE_ID,
                         device_key_id=device_identity.get_key_id(device_keys),
                         public_key=device_identity.get_public_key(device_keys),
                         bound_subject=SUBJECT)
    store.close()
    wire_bank_app_to_keys(tmp_path / "atlas-keys", tmp_path / "replay.db")
    bank = TestClient(bank_app)
    atlas_app.dependency_overrides.update({
        get_bank_client: lambda: bank,
        get_signing_keys_dir: lambda: tmp_path / "atlas-keys",
        get_transaction_store: lambda: TransactionStore(tmp_path / "atlas.db"),
        get_device_store: lambda: DeviceStore(device_db),
        get_step_up_store: lambda: StepUpStore(tmp_path / "step_up.db"),
        get_allow_counter_reset: lambda: False,
    })
    yield {"client": TestClient(atlas_app), "tmp": tmp_path, "device_db": device_db}
    atlas_app.dependency_overrides.clear()
    bank_app.dependency_overrides.clear()


def _txn(**overrides) -> dict:
    body = dict(transaction_id=f"rt-{secrets.token_hex(4)}", subject=SUBJECT, amount="1500.00",
                currency="INR", beneficiary="ben-mother", location="Hyderabad,IN",
                device_id=DEVICE_ID, authentication_method="device_button",
                timestamp="2026-09-22T04:30:00+00:00")   # 10:00 IST: no odd_hours
    body.update(overrides)
    return body


def _envelope(keys: Path, *, counter: int, txn: dict | None = None, now=None,
              sign_with: Path | None = None, **overrides) -> DeviceEnvelope:
    now = now or datetime.now(timezone.utc)
    fields = dict(device_id=DEVICE_ID, device_key_id=device_identity.get_key_id(keys),
                  boot_id="boot-redteam", counter=counter, nonce=secrets.token_hex(16),
                  issued_at=now.isoformat(), transaction=txn or _txn(), location=None,
                  health=None, signature="")
    fields.update(overrides)
    unsigned = DeviceEnvelope(**fields)
    signature = device_identity.secure_sign(canonical_envelope_bytes(unsigned), sign_with or keys)
    return unsigned.model_copy(update={"signature": signature})


def _post(rig, envelope: DeviceEnvelope | dict):
    body = envelope.model_dump(mode="json") if isinstance(envelope, DeviceEnvelope) else envelope
    return rig["client"].post("/v2/transact", json=body)


def _refused(reply, reason: str) -> None:
    body = reply.json()
    assert body["final_status"] == "FAIL_CLOSED", body
    assert body["decision_reason"] == reason, body
    assert body.get("assertion") is None and body.get("bank_verdict") is None


def _tampered(envelope: DeviceEnvelope, **txn_changes) -> dict:
    """The attacker's move: change fields AFTER the device signed."""
    body = envelope.model_dump(mode="json")
    body["transaction"].update(txn_changes)
    return body


# ---- 1-3: device identity ----------------------------------------------------------

def test_rt01_fake_device_id(rig, device_keys, tmp_path):
    impostor = tmp_path / "impostor-keys"
    device_identity.init_device(impostor)
    _refused(_post(rig, _envelope(impostor, counter=1)), "DEVICE_UNKNOWN")
    # The genuine key, but a device_id it was not enrolled under.
    _refused(_post(rig, _envelope(device_keys, counter=1, device_id="esp32-someone-else",
                                  txn=_txn(device_id="esp32-someone-else"))), "DEVICE_ID_MISMATCH")


def test_rt02_unknown_device(rig, tmp_path):
    stranger = tmp_path / "stranger-keys"
    device_identity.init_device(stranger)
    _refused(_post(rig, _envelope(stranger, counter=1, device_id="esp32-never-enrolled",
                                  txn=_txn(device_id="esp32-never-enrolled"))), "DEVICE_UNKNOWN")


def test_rt03_revoked_device(rig, device_keys):
    store = DeviceStore(rig["device_db"])
    revoke(store, DEVICE_ID, "red team: stolen")
    store.close()
    _refused(_post(rig, _envelope(device_keys, counter=1)), "DEVICE_REVOKED")


# ---- 4-10: tampering and signatures ------------------------------------------------

@pytest.mark.parametrize("attack_id, change", [
    (4, {"amount": "1.00"}),
    (5, {"beneficiary": "ben-attacker"}),
    (6, {"currency": "USD"}),
    (7, {"location": "Lagos,NG"}),
    (8, {"timestamp": "2026-09-22T19:00:00+00:00"}),
], ids=["rt04-amount", "rt05-beneficiary", "rt06-currency", "rt07-location", "rt08-timestamp"])
def test_rt04_to_rt08_modified_fields_break_the_signature(rig, device_keys, attack_id, change):
    signed = _envelope(device_keys, counter=1)
    _refused(_post(rig, _tampered(signed, **change)), "INVALID_DEVICE_SIGNATURE")


def test_rt09_invalid_signature(rig, device_keys):
    body = _envelope(device_keys, counter=1).model_dump(mode="json")
    body["signature"] = secrets.token_hex(64)
    _refused(_post(rig, body), "INVALID_DEVICE_SIGNATURE")


def test_rt10_missing_signature(rig, device_keys):
    body = _envelope(device_keys, counter=1).model_dump(mode="json")
    body["signature"] = ""
    _refused(_post(rig, body), "MISSING_DEVICE_SIGNATURE")


# ---- 11-14: replay and freshness ----------------------------------------------------

def test_rt11_replayed_transaction(rig, device_keys):
    envelope = _envelope(device_keys, counter=1)
    assert _post(rig, envelope).json()["final_status"] == "ALLOW"
    _refused(_post(rig, envelope), "COUNTER_REGRESSION")


def test_rt12_replayed_nonce(rig, device_keys):
    first = _envelope(device_keys, counter=1)
    assert _post(rig, first).json()["final_status"] == "ALLOW"
    again = _envelope(device_keys, counter=2, nonce=first.nonce)
    _refused(_post(rig, again), "REPLAYED_NONCE")


def test_rt13_stale_request(rig, device_keys):
    old = datetime.now(timezone.utc) - timedelta(minutes=10)
    _refused(_post(rig, _envelope(device_keys, counter=1, now=old)), "STALE_REQUEST")


def test_rt14_future_timestamp(rig, device_keys):
    ahead = datetime.now(timezone.utc) + timedelta(minutes=10)
    _refused(_post(rig, _envelope(device_keys, counter=1, now=ahead)), "FUTURE_TIMESTAMP")


# ---- 15-17: dependencies down ------------------------------------------------------

def test_rt15_backend_unavailable(device_keys):
    config = vd.DeviceConfig(atlas_url="http://127.0.0.1:1", device_id=DEVICE_ID, timeout_seconds=1.0)
    result = vd.handle_event_signed(vd.read_event(0, 1), config, httpx.Client(), device_keys)
    assert result.state == vd.DeviceState.FAIL_CLOSED
    assert result.led == vd.Led.RED and result.final_status is None


def test_rt16_bank_unavailable(rig, device_keys):
    atlas_app.dependency_overrides[get_bank_client] = lambda: httpx.Client(timeout=1.0)
    import atlas_service.main as atlas_main
    original = atlas_main.BANK_SERVICE_URL
    atlas_main.BANK_SERVICE_URL = "http://127.0.0.1:1"   # a genuinely closed port
    try:
        txn = _txn()
        body = _post(rig, _envelope(device_keys, counter=1, txn=txn)).json()
    finally:
        atlas_main.BANK_SERVICE_URL = original
    assert (body["final_status"], body["decision_reason"]) == ("PENDING", "BANK_UNREACHABLE")
    store = TransactionStore(rig["tmp"] / "atlas.db")
    assert store.get_state(txn["transaction_id"]).value == "UNKNOWN"
    store.close()


def test_rt17_ml_unavailable(rig, device_keys):
    atlas_app.dependency_overrides[get_model_registry] = lambda: ModelRegistry(rig["tmp"] / "no-models")
    txn = _txn()
    _refused(_post(rig, _envelope(device_keys, counter=1, txn=txn)), "INTERNAL_ERROR")
    store = TransactionStore(rig["tmp"] / "atlas.db")
    assert store.get_state(txn["transaction_id"]) is None
    store.close()


# ---- 18: graded location; 19: health, carried but not graded ------------------------

def test_rt18_location_outside_geofence(rig, device_keys):
    store = DeviceStore(rig["device_db"])
    set_home_area(store, DEVICE_ID, 17.385044, 78.486671, 10_000)       # Hyderabad, 10 km
    store.close()
    far_away = LocationEvidence(source="GNSS", latitude=Decimal("-33.868800"),
                                longitude=Decimal("151.209300"), accuracy_m=Decimal("12.0"),
                                captured_at=datetime.now(timezone.utc).isoformat())
    for amount, plain_expected, located_expected in (("1500.00", "ALLOW", "STEP_UP"),
                                                      ("150000.00", "DENY", "DENY")):
        plain = _post(rig, _envelope(device_keys, counter=1 if amount == "1500.00" else 3,
                                     txn=_txn(amount=amount))).json()
        located = _post(rig, _envelope(device_keys, counter=2 if amount == "1500.00" else 4,
                                       txn=_txn(amount=amount), location=far_away)).json()
        assert plain["final_status"] == plain_expected
        assert located["final_status"] == located_expected, "location must only ever add friction"
        assert located["location"]["geofence"] == "OUTSIDE_GEOFENCE"
        assert "outside_home_area" in located["decision"]["matched_rules"]
    # ...and it IS tamper-evident: moving the fix after signing breaks the signature.
    body = _envelope(device_keys, counter=5, location=far_away).model_dump(mode="json")
    body["location"]["latitude"] = "17.385000"
    _refused(_post(rig, body), "INVALID_DEVICE_SIGNATURE")


def test_rt19_firmware_integrity_failure(rig, device_keys):
    compromised = DeviceHealth(firmware_version="unknown", secure_boot_enabled=False,
                               tamper_detected=True, reset_reason="brownout")
    for n, (amount, expected) in enumerate((("1500.00", "ALLOW"), ("150000.00", "DENY"))):
        body = _post(rig, _envelope(device_keys, counter=n + 1, txn=_txn(amount=amount),
                                    health=compromised)).json()
        assert body["final_status"] == expected
    body = _envelope(device_keys, counter=3, health=compromised).model_dump(mode="json")
    body["health"]["tamper_detected"] = False
    _refused(_post(rig, body), "INVALID_DEVICE_SIGNATURE")


# ---- 20-21: policy ------------------------------------------------------------------

def test_rt20_excessive_velocity(rig, device_keys):
    policy = load_policy(POLICIES_DIR / f"{SUBJECT}.yaml")
    base = datetime(2026, 9, 22, 4, 30, tzinfo=timezone.utc)
    history = generate_normal_history(Persona(subject=SUBJECT), n=200, seed=42)
    burst = [Transaction(**_txn(transaction_id=f"burst-{i}",
                                timestamp=(base - timedelta(minutes=i)).isoformat()))
             for i in range(25)]
    decision = evaluate(Transaction(**_txn(transaction_id="burst-final", timestamp=base.isoformat())),
                        RiskEvidence(anomaly_score=0.0, risk_band="LOW", reasons=[]),
                        history + burst, policy)
    assert decision.decision.value == "DENY" and decision.deciding_rule == "velocity_burst"

    # ... and since 2026-09-23 the RUNNING SERVICE answers the same way, because it
    # counts the subject's own persisted payments instead of their modelled history.
    # Until then this attack was pinned as "not triggered by live payments", which is
    # what the fix removed. VELOCITY: 20 means the rule fires once this payment makes
    # the 24-hour count exceed 20, i.e. from the 21st payment onward.
    replies = [_post(rig, _envelope(device_keys, counter=i + 1)).json() for i in range(22)]
    assert {r["final_status"] for r in replies[:20]} == {"ALLOW"}, (
        "payments below the velocity limit stopped being allowed")
    for late in replies[20:]:
        assert late["final_status"] == "DENY", "a live burst no longer trips the rule"
        assert late["decision"]["deciding_rule"] == "velocity_burst"


def test_rt21_new_beneficiary_with_a_high_amount(rig, device_keys):
    body = _post(rig, _envelope(device_keys, counter=1,
                                txn=_txn(amount="25000.00", beneficiary="ben-never-paid-before"))).json()
    assert body["final_status"] == "STEP_UP"
    assert "new_beneficiary_meaningful_amount" in body["decision"]["matched_rules"]
    assert body["assertion"] is None and body["bank_verdict"] is None


# ---- 22-25: abuse of the interface --------------------------------------------------

def test_rt22_multiple_failed_attempts(rig, device_keys, tmp_path):
    impostor = tmp_path / "impostor-keys"
    device_identity.init_device(impostor)
    for i in range(12):
        body = _envelope(device_keys, counter=i + 1).model_dump(mode="json")
        body["signature"] = secrets.token_hex(64)
        _refused(_post(rig, body), "INVALID_DEVICE_SIGNATURE")
    # No lockout was created and the counter was not advanced by the failures:
    # the genuine device's next request, at counter 1, still goes through.
    assert _post(rig, _envelope(device_keys, counter=1)).json()["final_status"] == "ALLOW"


def test_rt23_malformed_json(rig):
    # The needle carries no quotes or braces on purpose: an echo of the rejected
    # body survives JSON escaping, so this catches it however it is re-embedded.
    # (A literal '"counter": ' check did not -- proven by deliberate break, 2026-09-23.)
    needle = "RT23-NEEDLE-d41d8cd98f"
    reply = rig["client"].post("/v2/transact",
                               content=b'{"device_id": "' + needle.encode() + b'", "counter": ',
                               headers={"content-type": "application/json"})
    assert reply.status_code == 422
    body = reply.json()
    assert (body["final_status"], body["decision_reason"]) == ("FAIL_CLOSED", "MALFORMED_ENVELOPE")
    assert needle not in reply.text, "the rejected input was echoed back"
    assert '"counter": ' not in reply.text, "the rejected input was echoed back"


def test_rt23_a_wellformed_body_of_the_wrong_shape_is_not_echoed_either(rig):
    """The other half of attack 23. Malformed JSON never reaches field validation,
    so its rejected values stay in `exc.body`; a body that parses but has the wrong
    shape does reach it, and each error then carries the offending value in `input`.
    Neither may come back: an error response that quotes what was sent turns the
    endpoint into a reflector. Added 2026-09-23 after a deliberate break showed the
    malformed-JSON test alone could not see an `input` echo."""
    needle = "RT23-SHAPE-NEEDLE-e3b0c44298"
    reply = rig["client"].post("/v2/transact", json={"device_id": needle, "counter": needle})
    assert reply.status_code == 422
    body = reply.json()
    assert (body["final_status"], body["decision_reason"]) == ("FAIL_CLOSED", "MALFORMED_ENVELOPE")
    assert needle not in reply.text, "the rejected input was echoed back"


def test_rt24_oversized_request(rig, device_keys):
    body = _envelope(device_keys, counter=1).model_dump(mode="json")
    body["transaction"]["beneficiary"] = "x" * (200 * 1024)
    reply = _post(rig, body)
    assert reply.status_code == 413
    assert reply.json()["decision_reason"] == "MALFORMED_ENVELOPE"


def test_rt25_duplicate_transaction_id(rig, device_keys):
    txn = _txn()
    assert _post(rig, _envelope(device_keys, counter=1, txn=txn)).json()["final_status"] == "ALLOW"
    _refused(_post(rig, _envelope(device_keys, counter=2, txn=txn)), "DUPLICATE_TRANSACTION_ID")


# ---- the catalogue itself -----------------------------------------------------------

def test_every_catalogued_attack_has_a_test_and_an_explicit_outcome():
    assert [entry[0] for entry in CATALOGUE] == list(range(1, 26))
    names = [n for n in globals() if n.startswith("test_rt")]
    covered = set()
    for name in names:
        head = name.split("_")[1]                      # "rt04"
        covered.add(int(head[2:]))
        if "_to_rt" in name:                           # "rt04_to_rt08"
            last = int(name.split("_to_rt")[1][:2])
            covered.update(range(int(head[2:]), last + 1))
    assert covered == set(range(1, 26)), f"attacks without a test: {sorted(set(range(1, 26)) - covered)}"
    assert all(outcome.strip() for _, _, outcome in CATALOGUE)
