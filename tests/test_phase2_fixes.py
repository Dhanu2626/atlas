"""Phase 2 regression tests: the three defects found in the Phase 1 audit.

1. Duplicate/replayed transaction_id crashed /transact with an unhandled
   HTTP 500 (InvalidTransitionError: DENIED -> EVALUATING), because the
   firmware's RAM sequence counter reset to 0 on every simulator restart.
2. TIME_WINDOW compared the raw UTC hour against rules that plainly mean
   local night, so identical transactions decided differently by wall clock.
3. DENY (something deliberately said no) and FAIL_CLOSED (no trustworthy
   decision was possible) were indistinguishable in state, response, and logs.

Each test below fails against the pre-fix code.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from atlas_service.db import TransactionStore
from atlas_service.main import app as atlas_app
from atlas_service.main import (
    get_bank_client,
    get_require_device_auth,
    get_signing_keys_dir,
    get_transaction_store,
)
from atlas_service.policy.engine import POLICIES_DIR, evaluate, load_policy, policy_hour
from bank_service.main import app as bank_app
from contracts import (
    FAIL_CLOSED_REASONS,
    Decision,
    DecisionReason,
    FinalStatus,
    RiskEvidence,
    Transaction,
    TxnState,
)
from firmware.virtual_device import (
    DeviceConfig,
    DeviceState,
    Led,
    assemble_transaction,
    handle_event,
    interpret_response,
    new_boot_id,
    read_event,
)
from tests.conftest import wire_bank_app_to_keys

POLICY_PATH = POLICIES_DIR / "user-demo-1.yaml"


def _tx(**overrides) -> dict:
    defaults = dict(
        transaction_id="p2-1",
        subject="user-demo-1",
        amount="1500.00",
        currency="INR",
        beneficiary="ben-mother",
        location="Bengaluru,IN",
        device_id="esp32-atlas-demo-01",
        authentication_method="device_button",
        timestamp="2026-08-26T12:00:00+00:00",
    )
    defaults.update(overrides)
    return defaults


@pytest.fixture
def keys_dir(tmp_path) -> Path:
    return tmp_path / "atlas-keys"


@pytest.fixture
def store_path(tmp_path) -> Path:
    return tmp_path / "atlas.db"


@pytest.fixture(autouse=True)
def _wire(keys_dir, tmp_path):
    wire_bank_app_to_keys(keys_dir, tmp_path / "replay.db")
    yield
    bank_app.dependency_overrides.clear()
    atlas_app.dependency_overrides.clear()


@pytest.fixture
def atlas_client(keys_dir, store_path) -> TestClient:
    bank = TestClient(bank_app)
    atlas_app.dependency_overrides[get_bank_client] = lambda: bank
    atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: keys_dir
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(store_path)
    # The legacy unsigned /transact has been closed by default since 2026-09-18
    # (D5). These tests exercise that compatibility contract on purpose, so they
    # open it explicitly instead of relying on a default.
    atlas_app.dependency_overrides[get_require_device_auth] = lambda: False
    return TestClient(atlas_app)


# ===========================================================================
# FIX 1 -- duplicate / replayed transaction_id must never be a 500
# ===========================================================================


def test_replaying_a_confirmed_transaction_id_does_not_500(atlas_client):
    """The exact reported failure: an id that already reached a terminal
    state, re-sent. Previously InvalidTransitionError -> unhandled -> 500."""
    body = _tx(transaction_id="p2-dup-confirmed", amount="1500.00")
    first = atlas_client.post("/transact", json=body)
    assert first.status_code == 200
    assert first.json()["final_status"] == "ALLOW"

    second = atlas_client.post("/transact", json=body)

    assert second.status_code == 200, "a duplicate id must not crash the service"
    assert second.json()["final_status"] == FinalStatus.FAIL_CLOSED.value
    assert second.json()["decision_reason"] == DecisionReason.DUPLICATE_TRANSACTION_ID.value


def test_replaying_a_denied_transaction_id_does_not_500(atlas_client):
    """The literal reproduction from the audit: DENIED -> EVALUATING."""
    body = _tx(transaction_id="p2-dup-denied", amount="150000.00")
    first = atlas_client.post("/transact", json=body)
    assert first.json()["final_status"] == "DENY"

    second = atlas_client.post("/transact", json=body)

    assert second.status_code == 200
    assert second.json()["final_status"] == FinalStatus.FAIL_CLOSED.value
    assert second.json()["decision_reason"] == DecisionReason.DUPLICATE_TRANSACTION_ID.value


def test_duplicate_is_fail_closed_not_deny(atlas_client):
    """The separation that matters: a replayed id is a SECURITY condition,
    not the policy engine refusing. It must never be reported as DENY, which
    would hide a replay attempt inside normal risk behaviour."""
    body = _tx(transaction_id="p2-dup-class")
    atlas_client.post("/transact", json=body)
    second = atlas_client.json = atlas_client.post("/transact", json=body).json()

    assert second["final_status"] != FinalStatus.DENY.value
    assert DecisionReason(second["decision_reason"]) in FAIL_CLOSED_REASONS


def test_duplicate_does_not_re_run_policy_or_mutate_state(atlas_client, store_path):
    """A duplicate must not re-evaluate (which could yield a different answer
    for an id the bank already settled) and must not disturb the stored
    state of the original transaction."""
    body = _tx(transaction_id="p2-dup-nostate", amount="1500.00")
    atlas_client.post("/transact", json=body)
    state_before = TransactionStore(store_path).get_state("p2-dup-nostate")

    second = atlas_client.post("/transact", json=body).json()

    assert second["risk"] is None, "duplicate must not re-run ML"
    assert second["decision"] is None, "duplicate must not re-run policy"
    assert TransactionStore(store_path).get_state("p2-dup-nostate") == state_before


def test_device_reports_duplicate_as_fail_closed_red(atlas_client, keys_dir):
    """End-to-end through the device model: the LED is red and the reason is
    explicit, rather than the device seeing an opaque 500."""
    config = DeviceConfig(atlas_url="http://atlas", boot_id="fixedboot")
    event = read_event(preset_id=0, sequence=1, now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc))

    first = handle_event(event, config, atlas_client)
    second = handle_event(event, config, atlas_client)  # identical id

    assert first.state == DeviceState.APPROVED
    assert second.state == DeviceState.FAIL_CLOSED
    assert second.led == Led.RED
    assert second.decision_reason == DecisionReason.DUPLICATE_TRANSACTION_ID.value


# --- the underlying cause: boot-safe transaction ids ------------------------


def test_boot_ids_differ_between_boots():
    assert len({new_boot_id() for _ in range(20)}) == 20


def test_ids_from_different_boots_do_not_collide_after_counter_reset():
    """The actual defect. Both 'boots' start their sequence at 1, exactly as
    the firmware's RAM counter does after a Wokwi restart. With a per-boot
    component the ids must still differ."""
    boot_a = DeviceConfig(boot_id=new_boot_id())
    boot_b = DeviceConfig(boot_id=new_boot_id())
    now = datetime(2026, 8, 26, 12, tzinfo=timezone.utc)

    id_a = assemble_transaction(read_event(0, 1, now=now), boot_a)["transaction_id"]
    id_b = assemble_transaction(read_event(0, 1, now=now), boot_b)["transaction_id"]

    assert id_a != id_b


def test_firmware_and_python_model_use_the_same_id_format():
    """These two silently diverged -- the .ino omitted the boot component the
    Python model had, so the tested model could not catch the firmware's
    collision. Pin the format in both so they cannot drift again."""
    ino = (Path(__file__).resolve().parent.parent
           / "firmware" / "atlas_device" / "atlas_device.ino").read_text(encoding="utf-8")

    assert '"%s-%s-%04ld"' in ino, "firmware id must be device-boot-sequence"
    # Checks the ARGUMENTS, not the exact C identifier. F3 renamed the third
    # argument from `event.sequence` to `e.counter` when the RAM sequence
    # became the NVS-persisted monotonic counter -- a real semantic change,
    # not a drift, and the id format it produces is unchanged. Pinning the
    # spelling made this test fail for a rename while the property it exists
    # to protect was still satisfied.
    #
    # Coverage is not weakened: tests/test_f3_firmware_parity.py's
    # test_firmware_argument_order_matches_the_template now pins the FULL
    # 15-argument list exactly, which is strictly stronger than this line was.
    assert "DEVICE_ID, g_bootId," in ino, "id must be built from device id + boot id"
    assert "esp_random()" in ino, "boot id must be random per power-on"

    body = assemble_transaction(
        read_event(0, 1, now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc)),
        DeviceConfig(device_id="dev", boot_id="abcd1234"),
    )
    assert body["transaction_id"] == "dev-abcd1234-0001"


# ===========================================================================
# FIX 2 -- TIME_WINDOW must be evaluated in the policy's timezone
# ===========================================================================


def _risk(band: str = "LOW") -> RiskEvidence:
    return RiskEvidence(anomaly_score=0.0, risk_band=band, reasons=[])


@pytest.fixture
def policy() -> dict:
    return load_policy(POLICY_PATH)


def test_policy_hour_without_timezone_is_unchanged():
    """Backward compatibility: a policy with no timezone behaves exactly as
    before, so existing policies are untouched by this fix."""
    assert policy_hour("2026-08-26T03:54:00+00:00", None) == 3
    assert policy_hour("2026-08-26T21:00:00+05:30", None) == 21


def test_policy_hour_converts_into_the_configured_timezone():
    # 03:54 UTC is 09:24 IST -- morning, NOT odd hours
    assert policy_hour("2026-08-26T03:54:00+00:00", "Asia/Kolkata") == 9
    # 17:46 UTC is 23:16 IST -- night, IS odd hours
    assert policy_hour("2026-08-26T17:46:00+00:00", "Asia/Kolkata") == 23


def test_naive_timestamp_is_treated_as_utc_not_as_local():
    """Guessing 'probably local' would silently shift every decision by the
    offset -- the exact class of bug being fixed."""
    assert policy_hour("2026-08-26T03:54:00", "Asia/Kolkata") == 9


def test_the_reported_defect_is_fixed_morning_utc_no_longer_odd_hours(policy):
    """THE regression. 03:54 UTC = 09:24 IST. Before the fix this matched
    odd_hours and turned a Rs 1,500 payment amber; it must now be ALLOW."""
    d = evaluate(
        Transaction(**_tx(timestamp="2026-08-26T03:54:00+00:00")),
        _risk(), _history(), policy,
    )
    assert "odd_hours" not in d.matched_rules
    assert d.decision == Decision.ALLOW


def test_genuine_local_night_still_triggers_odd_hours(policy):
    """The rule must still do its job: 23:16 IST is genuinely odd hours."""
    d = evaluate(
        Transaction(**_tx(timestamp="2026-08-26T17:46:00+00:00")),
        _risk(), _history(), policy,
    )
    assert "odd_hours" in d.matched_rules
    assert d.decision == Decision.STEP_UP


@pytest.mark.parametrize(
    "ist_hour,expect_odd",
    [(21, False), (22, True), (23, True), (0, True), (5, True), (6, False), (9, False)],
)
def test_time_window_boundaries_in_local_time(policy, ist_hour, expect_odd):
    """[22, 6) semantics preserved exactly -- start inclusive, end exclusive,
    wrapping past midnight -- but now anchored to IST rather than UTC."""
    ts = f"2026-08-26T{ist_hour:02d}:00:00+05:30"
    d = evaluate(Transaction(**_tx(timestamp=ts)), _risk(), _history(), policy)
    assert ("odd_hours" in d.matched_rules) is expect_odd


def _history() -> list[Transaction]:
    """Known beneficiary, so NEW_BENEFICIARY never confounds these tests."""
    return [
        Transaction(**_tx(transaction_id=f"h-{i}", timestamp="2026-08-01T12:00:00+00:00"))
        for i in range(3)
    ]


# ===========================================================================
# FIX 3 -- DENY vs FAIL_CLOSED must be distinguishable everywhere
# ===========================================================================


def test_policy_deny_is_reported_as_a_decision_not_a_failure(atlas_client):
    r = atlas_client.post("/transact", json=_tx(
        transaction_id="p2-deny", amount="150000.00")).json()
    assert r["final_status"] == FinalStatus.DENY.value
    assert r["decision_reason"] == DecisionReason.POLICY_DENY.value
    assert DecisionReason(r["decision_reason"]) not in FAIL_CLOSED_REASONS


def test_step_up_carries_its_own_reason(atlas_client):
    r = atlas_client.post("/transact", json=_tx(
        transaction_id="p2-stepup", amount="60000.00")).json()
    assert r["final_status"] == FinalStatus.STEP_UP.value
    assert r["decision_reason"] == DecisionReason.POLICY_STEP_UP.value


def test_allow_carries_its_own_reason(atlas_client):
    r = atlas_client.post("/transact", json=_tx(
        transaction_id="p2-allow", amount="1500.00")).json()
    assert r["final_status"] == FinalStatus.ALLOW.value
    assert r["decision_reason"] == DecisionReason.POLICY_ALLOW.value


def test_bank_rejection_is_deny_with_bank_reason(atlas_client):
    """The bank refusing is still a real decision -- DENY, not FAIL_CLOSED."""
    r = atlas_client.post("/transact", json=_tx(
        transaction_id="p2-bank-deny", subject="user-frozen-1", amount="500.00")).json()
    assert r["final_status"] == FinalStatus.DENY.value
    assert r["decision_reason"] == DecisionReason.BANK_REJECTED.value


def test_unknown_rail_is_fail_closed_with_a_usable_status(atlas_client):
    """Previously returned {"error": ...} with NO final_status, which the
    device could only classify as malformed."""
    r = atlas_client.post("/transact", params={"rail": "SWIFT"},
                          json=_tx(transaction_id="p2-rail")).json()
    assert r["final_status"] == FinalStatus.FAIL_CLOSED.value
    assert r["decision_reason"] == DecisionReason.UNKNOWN_RAIL.value


def test_bank_unreachable_is_pending_not_deny_and_not_fail_closed(keys_dir, store_path, tmp_path):
    """An availability failure stays PENDING -> reconcile, per the frozen
    failure-mode table. It is emphatically NOT a DENY (nothing refused it)
    and not FAIL_CLOSED (the payment may yet have succeeded)."""
    atlas_app.dependency_overrides[get_bank_client] = lambda: httpx.Client()
    atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: keys_dir
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(store_path)
    atlas_app.dependency_overrides[get_require_device_auth] = lambda: False  # legacy path, see above
    import atlas_service.main as atlas_main
    original = atlas_main.BANK_SERVICE_URL
    atlas_main.BANK_SERVICE_URL = "http://127.0.0.1:1"
    try:
        r = TestClient(atlas_app).post("/transact", json=_tx(
            transaction_id="p2-pending", amount="1500.00")).json()
    finally:
        atlas_main.BANK_SERVICE_URL = original

    assert r["final_status"] == FinalStatus.PENDING.value
    assert r["decision_reason"] == DecisionReason.BANK_UNREACHABLE.value
    assert r["final_status"] != FinalStatus.DENY.value


def test_device_distinguishes_backend_failure_from_a_deny(atlas_client, tmp_path):
    """Both light red. The device must still record WHICH -- reading a red
    LED as 'the bank declined' when ATLAS was down is exactly the confusion
    this separation exists to prevent."""
    config = DeviceConfig(atlas_url="http://atlas")
    denied = handle_event(read_event(2, 1, now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc)),
                          config, atlas_client)

    unreachable_cfg = DeviceConfig(atlas_url="http://127.0.0.1:1", timeout_seconds=1.0)
    failed = handle_event(read_event(0, 1, now=datetime(2026, 8, 26, 12, tzinfo=timezone.utc)),
                          unreachable_cfg, httpx.Client())

    assert denied.led == Led.RED and failed.led == Led.RED
    assert denied.state == DeviceState.REFUSED
    assert failed.state == DeviceState.FAIL_CLOSED
    assert denied.decision_reason == DecisionReason.POLICY_DENY.value
    assert failed.decision_reason == "ATLAS_UNREACHABLE"
    assert denied.state != failed.state


def test_device_maps_explicit_fail_closed_status():
    assert interpret_response({"final_status": "FAIL_CLOSED"}) == DeviceState.FAIL_CLOSED


def test_backend_failure_never_becomes_allow(atlas_client):
    """The invariant the whole separation protects."""
    for body in [
        {"final_status": "FAIL_CLOSED", "decision_reason": "INTERNAL_ERROR"},
        {"final_status": "FAIL_CLOSED", "decision_reason": "DUPLICATE_TRANSACTION_ID"},
        {"decision_reason": "INTERNAL_ERROR"},
        {"error": "boom"},
    ]:
        assert interpret_response(body) != DeviceState.APPROVED
