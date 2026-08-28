"""Phase 3.1-3.3: device registry, device identity, device authentication.

Implements Blueprint 24.3's already-specified design rather than a new one.

The invariant every test here defends: ATLAS must stop believing `device_id`
just because a caller typed it. Identity comes from an enrolled key, and the
signature is checked BEFORE any authenticated field is used.

Nothing in Phase 3.3 changes a financial decision. The three demo amounts are
pinned below to prove it.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from atlas_service.db import TransactionStore
from atlas_service.device.db import DeviceStore
from atlas_service.device.envelope import verify_envelope
from atlas_service.device.registry import (
    DeviceAlreadyRegisteredError,
    reactivate,
    register_demo_device,
    revoke,
    suspend,
)
from atlas_service.main import app as atlas_app
from atlas_service.main import (
    get_allow_counter_reset,
    get_bank_client,
    get_device_store,
    get_require_device_auth,
    get_signing_keys_dir,
    get_transaction_store,
)
from bank_service.main import app as bank_app
from contracts import (
    FAIL_CLOSED_REASONS,
    DecisionReason,
    DeviceEnvelope,
    DeviceStatus,
    FinalStatus,
    canonical_envelope_bytes,
)
from firmware import device_identity
from tests.conftest import wire_bank_app_to_keys

DEVICE_ID = "esp32-atlas-demo-01"
SUBJECT = "user-demo-1"


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def device_keys(tmp_path) -> Path:
    d = tmp_path / "device-keys"
    device_identity.init_device(d)
    return d


@pytest.fixture
def device_db_path(tmp_path) -> Path:
    return tmp_path / "devices.db"


@pytest.fixture
def device_store(device_db_path) -> DeviceStore:
    """Direct-use store for the unit-level tests. HTTP-level tests must build
    a fresh store per request instead -- a sqlite3 connection belongs to the
    thread that made it, and FastAPI runs sync endpoints in a worker thread.
    Same reason atlas_service/db.py's TransactionStore is constructed
    per-request rather than shared."""
    return DeviceStore(device_db_path)


@pytest.fixture
def enrolled(device_store, device_keys) -> DeviceStore:
    register_demo_device(
        device_store,
        device_id=DEVICE_ID,
        device_key_id=device_identity.get_key_id(device_keys),
        public_key=device_identity.get_public_key(device_keys),
        bound_subject=SUBJECT,
    )
    return device_store


def _txn(**overrides) -> dict:
    d = dict(
        transaction_id="p3-1",
        subject=SUBJECT,
        amount="1500.00",
        currency="INR",
        beneficiary="ben-mother",
        location="Bengaluru,IN",
        device_id=DEVICE_ID,
        authentication_method="device_button",
        timestamp="2026-08-27T12:00:00+00:00",
    )
    d.update(overrides)
    return d


def _envelope(device_keys: Path, *, counter=1, txn=None, now=None, **overrides) -> DeviceEnvelope:
    """Builds the model FIRST, then signs canonical_envelope_bytes of it.

    Signing a hand-built dict instead would sign a different byte string than
    the verifier derives -- pydantic fills in Transaction's defaults
    (merchant_category, is_new_beneficiary, ...) that a sparse dict omits.
    Deriving the signing input from the model is the only way both sides
    agree, and it is what firmware/virtual_device.build_envelope does too.
    """
    import secrets

    now = now or datetime.now(timezone.utc)
    body = dict(
        device_id=DEVICE_ID,
        device_key_id=device_identity.get_key_id(device_keys),
        boot_id="boot-aaaa",
        counter=counter,
        nonce=secrets.token_hex(16),
        issued_at=now.isoformat(),
        transaction=txn or _txn(),
        location=None,
        health=None,
        signature="",
    )
    body.update(overrides)
    unsigned = DeviceEnvelope(**body)
    signature = device_identity.secure_sign(canonical_envelope_bytes(unsigned), device_keys)
    return unsigned.model_copy(update={"signature": signature})


# ==========================================================================
# 3.1 REGISTRY
# ==========================================================================


def test_unknown_device_is_absence_not_a_status(device_store):
    assert device_store.get_by_device_id("never-enrolled") is None


def test_enrolled_device_is_active(enrolled):
    assert enrolled.get_by_device_id(DEVICE_ID)["status"] == DeviceStatus.ACTIVE.value


def test_reenrolling_same_device_id_is_refused(enrolled, device_keys):
    """Silently replacing an enrolled key would be an account-takeover
    primitive, not a convenience."""
    with pytest.raises(DeviceAlreadyRegisteredError):
        register_demo_device(
            enrolled, device_id=DEVICE_ID, device_key_id="dev-other",
            public_key="aa" * 32, bound_subject=SUBJECT,
        )


def test_reenrolling_same_key_under_a_new_device_id_is_refused(enrolled, device_keys):
    with pytest.raises(DeviceAlreadyRegisteredError):
        register_demo_device(
            enrolled, device_id="another-device",
            device_key_id=device_identity.get_key_id(device_keys),
            public_key=device_identity.get_public_key(device_keys), bound_subject=SUBJECT,
        )


def test_revocation_is_terminal(enrolled):
    revoke(enrolled, DEVICE_ID, "stolen")
    assert enrolled.get_by_device_id(DEVICE_ID)["status"] == DeviceStatus.REVOKED.value
    with pytest.raises(ValueError):
        reactivate(enrolled, DEVICE_ID)


def test_suspension_is_reversible(enrolled):
    suspend(enrolled, DEVICE_ID, "investigating")
    assert enrolled.get_by_device_id(DEVICE_ID)["status"] == DeviceStatus.SUSPENDED.value
    reactivate(enrolled, DEVICE_ID)
    assert enrolled.get_by_device_id(DEVICE_ID)["status"] == DeviceStatus.ACTIVE.value


def test_registry_never_stores_a_private_key(enrolled, device_keys):
    row = dict(enrolled.get_by_device_id(DEVICE_ID))
    private_hex = device_identity._load_private_key(device_keys).private_bytes_raw().hex()
    for value in row.values():
        assert private_hex != str(value)
    assert "private" not in " ".join(row.keys())


def test_demo_provisioning_is_labelled_as_such(enrolled):
    """A demo-enrolled device must never be indistinguishable from a
    production-enrolled one."""
    assert enrolled.get_by_device_id(DEVICE_ID)["provisioning_mode"] == "DEMO"


def test_registration_and_revocation_are_audited(enrolled):
    revoke(enrolled, DEVICE_ID, "stolen")
    events = [e["event"] for e in enrolled.events_for(DEVICE_ID)]
    assert events == ["REGISTERED", "REVOKED"]


# ==========================================================================
# 3.2 DEVICE IDENTITY
# ==========================================================================


def test_device_key_is_separate_from_the_atlas_key(device_keys, tmp_path):
    """Mixing them would let a compromised device mint bank assertions."""
    from atlas_service import crypto

    atlas_keys = tmp_path / "atlas-keys"
    crypto.init_device(keys_dir=atlas_keys)
    assert device_identity.get_public_key(device_keys) != crypto.get_public_key(atlas_keys)


def test_device_identity_is_stable_across_calls(device_keys):
    assert device_identity.init_device(device_keys) == device_identity.get_key_id(device_keys)


def test_regenerating_identity_produces_an_unenrolled_key(device_store, device_keys):
    register_demo_device(
        device_store, device_id=DEVICE_ID,
        device_key_id=device_identity.get_key_id(device_keys),
        public_key=device_identity.get_public_key(device_keys), bound_subject=SUBJECT,
    )
    new_key_id = device_identity.generate_identity(device_keys)
    assert device_store.get_by_key_id(new_key_id) is None  # wiped device fails closed


def test_counter_persists_and_is_monotonic(device_keys):
    assert [device_identity.next_counter(device_keys) for _ in range(3)] == [1, 2, 3]
    assert device_identity.peek_counter(device_keys) == 3


# ==========================================================================
# 3.3 AUTHENTICATION -- the core
# ==========================================================================


def test_valid_envelope_is_accepted(enrolled, device_keys):
    assert verify_envelope(_envelope(device_keys), enrolled).ok is True


def test_unknown_key_is_rejected(device_store, device_keys):
    v = verify_envelope(_envelope(device_keys), device_store)
    assert v.ok is False and v.reason == DecisionReason.DEVICE_UNKNOWN


def test_revoked_device_is_rejected_despite_a_valid_signature(enrolled, device_keys):
    revoke(enrolled, DEVICE_ID, "stolen")
    v = verify_envelope(_envelope(device_keys), enrolled)
    assert v.ok is False and v.reason == DecisionReason.DEVICE_REVOKED


def test_suspended_device_is_rejected(enrolled, device_keys):
    suspend(enrolled, DEVICE_ID)
    v = verify_envelope(_envelope(device_keys), enrolled)
    assert v.ok is False and v.reason == DecisionReason.DEVICE_SUSPENDED


def test_a_claimed_device_id_alone_proves_nothing(enrolled, tmp_path):
    """THE Phase 3 headline. An attacker's own key, claiming the enrolled
    device's id and subject, is rejected -- device_id is a label, not an
    identity."""
    attacker_keys = tmp_path / "attacker"
    device_identity.init_device(attacker_keys)
    forged = _envelope(attacker_keys)  # device_id says esp32-atlas-demo-01
    v = verify_envelope(forged, enrolled)
    assert v.ok is False and v.reason == DecisionReason.DEVICE_UNKNOWN


def test_valid_key_cannot_impersonate_another_device_id(enrolled, device_keys):
    v = verify_envelope(_envelope(device_keys, device_id="some-other-device"), enrolled)
    assert v.ok is False and v.reason == DecisionReason.DEVICE_ID_MISMATCH


def test_device_cannot_move_another_subjects_money(enrolled, device_keys):
    v = verify_envelope(
        _envelope(device_keys, txn=_txn(subject="user-poor-1")), enrolled)
    assert v.ok is False and v.reason == DecisionReason.DEVICE_SUBJECT_MISMATCH


@pytest.mark.parametrize("field,value", [
    ("amount", "1.00"),
    ("beneficiary", "attacker-account"),
    ("currency", "USD"),
    ("transaction_id", "rewritten"),
    ("subject", "user-poor-1"),
])
def test_tampering_with_any_transaction_field_breaks_the_signature(
    enrolled, device_keys, field, value
):
    env = _envelope(device_keys)
    tampered = env.model_copy(deep=True)
    setattr(tampered.transaction, field, value)
    v = verify_envelope(tampered, enrolled)
    assert v.ok is False
    assert v.reason == DecisionReason.INVALID_DEVICE_SIGNATURE


@pytest.mark.parametrize("field,value", [
    ("counter", 9999),
    ("nonce", "rewritten-nonce"),
    ("boot_id", "boot-zzzz"),
    ("issued_at", "2026-08-27T13:00:00+00:00"),
])
def test_tampering_with_any_envelope_field_breaks_the_signature(
    enrolled, device_keys, field, value
):
    env = _envelope(device_keys)
    v = verify_envelope(env.model_copy(update={field: value}), enrolled)
    assert v.ok is False and v.reason == DecisionReason.INVALID_DEVICE_SIGNATURE


def test_missing_signature_is_rejected(enrolled, device_keys):
    v = verify_envelope(_envelope(device_keys).model_copy(update={"signature": ""}), enrolled)
    assert v.ok is False and v.reason == DecisionReason.MISSING_DEVICE_SIGNATURE


def test_signature_covers_every_field_except_itself(device_keys):
    env = _envelope(device_keys)
    signed = canonical_envelope_bytes(env).decode()
    assert "signature" not in signed
    for field in ("device_id", "device_key_id", "boot_id", "counter",
                  "nonce", "issued_at", "transaction"):
        assert field in signed


# --- freshness ------------------------------------------------------------


def test_stale_request_is_rejected(enrolled, device_keys):
    old = datetime.now(timezone.utc) - timedelta(minutes=30)
    v = verify_envelope(_envelope(device_keys, now=old), enrolled)
    assert v.ok is False and v.reason == DecisionReason.STALE_REQUEST


def test_future_timestamp_is_rejected(enrolled, device_keys):
    ahead = datetime.now(timezone.utc) + timedelta(minutes=30)
    v = verify_envelope(_envelope(device_keys, now=ahead), enrolled)
    assert v.ok is False and v.reason == DecisionReason.FUTURE_TIMESTAMP


# --- replay: three independent layers -------------------------------------


def test_verbatim_replay_is_rejected(enrolled, device_keys):
    env = _envelope(device_keys, counter=5)
    assert verify_envelope(env, enrolled).ok is True
    v = verify_envelope(env, enrolled)
    assert v.ok is False
    assert v.reason in (DecisionReason.COUNTER_REGRESSION, DecisionReason.REPLAYED_NONCE)


def test_counter_must_strictly_increase(enrolled, device_keys):
    assert verify_envelope(_envelope(device_keys, counter=5), enrolled).ok is True
    v = verify_envelope(_envelope(device_keys, counter=5), enrolled)
    assert v.ok is False and v.reason == DecisionReason.COUNTER_REGRESSION


def test_counter_regression_is_rejected(enrolled, device_keys):
    verify_envelope(_envelope(device_keys, counter=10), enrolled)
    v = verify_envelope(_envelope(device_keys, counter=3), enrolled)
    assert v.ok is False and v.reason == DecisionReason.COUNTER_REGRESSION


def test_reused_nonce_is_rejected_even_with_a_higher_counter(enrolled, device_keys):
    first = _envelope(device_keys, counter=1)
    verify_envelope(first, enrolled)
    v = verify_envelope(_envelope(device_keys, counter=2, nonce=first.nonce), enrolled)
    assert v.ok is False and v.reason == DecisionReason.REPLAYED_NONCE


def test_rejected_envelope_does_not_burn_its_nonce_or_advance_the_counter(enrolled, device_keys):
    """A failed probe must not lock out the legitimate device."""
    revoke(enrolled, DEVICE_ID)
    env = _envelope(device_keys, counter=7)
    verify_envelope(env, enrolled)
    assert enrolled.nonce_seen(DEVICE_ID, env.nonce) is False
    assert enrolled.get_counter(DEVICE_ID) is None


# --- the Wokwi counter-reset affordance -----------------------------------


def test_counter_reset_is_rejected_by_default(enrolled, device_keys):
    """Real-device behaviour: NVS persists the counter, so a regression is
    an attack."""
    verify_envelope(_envelope(device_keys, counter=50), enrolled)
    v = verify_envelope(_envelope(device_keys, counter=1, boot_id="boot-new"), enrolled)
    assert v.ok is False and v.reason == DecisionReason.COUNTER_REGRESSION


def test_counter_reset_accepted_only_in_simulation_with_a_fresh_boot_id(enrolled, device_keys):
    verify_envelope(_envelope(device_keys, counter=50, boot_id="boot-old"), enrolled)
    v = verify_envelope(_envelope(device_keys, counter=1, boot_id="boot-new"),
                        enrolled, allow_counter_reset=True)
    assert v.ok is True


def test_simulation_mode_still_rejects_a_replay_with_the_same_boot_id(enrolled, device_keys):
    """The affordance must not become a general replay bypass."""
    env = _envelope(device_keys, counter=50, boot_id="boot-same")
    verify_envelope(env, enrolled, allow_counter_reset=True)
    v = verify_envelope(env, enrolled, allow_counter_reset=True)
    assert v.ok is False


def test_counter_reset_acceptance_is_always_audited(enrolled, device_keys):
    verify_envelope(_envelope(device_keys, counter=50, boot_id="b1"), enrolled)
    verify_envelope(_envelope(device_keys, counter=1, boot_id="b2"),
                    enrolled, allow_counter_reset=True)
    events = [e["event"] for e in enrolled.events_for(DEVICE_ID)]
    assert "COUNTER_RESET_ACCEPTED" in events


# ==========================================================================
# /v2/transact -- authentication in front of the UNCHANGED pipeline
# ==========================================================================


@pytest.fixture
def clients(tmp_path, device_keys, enrolled, device_db_path):
    wire_bank_app_to_keys(tmp_path / "atlas-keys", tmp_path / "replay.db")
    bank = TestClient(bank_app)
    atlas_app.dependency_overrides[get_bank_client] = lambda: bank
    atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: tmp_path / "atlas-keys"
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(
        tmp_path / "atlas.db")
    atlas_app.dependency_overrides[get_device_store] = lambda: DeviceStore(device_db_path)
    atlas_app.dependency_overrides[get_allow_counter_reset] = lambda: False
    atlas_app.dependency_overrides[get_require_device_auth] = lambda: False
    yield TestClient(atlas_app)
    atlas_app.dependency_overrides.clear()
    bank_app.dependency_overrides.clear()


def _post(client, env: DeviceEnvelope):
    return client.post("/v2/transact", json=env.model_dump(mode="json")).json()


@pytest.mark.parametrize("amount,expected_status,expected_reason", [
    ("1500.00", "ALLOW", "POLICY_ALLOW"),
    ("60000.00", "STEP_UP", "POLICY_STEP_UP"),
    ("150000.00", "DENY", "POLICY_DENY"),
])
def test_frozen_demo_amounts_are_unchanged_over_the_signed_path(
    clients, device_keys, amount, expected_status, expected_reason
):
    """Phase 3 adds authenticity in front of the decision pipeline and
    changes nothing about how decisions are made."""
    body = _post(clients, _envelope(
        device_keys, counter=1,
        txn=_txn(transaction_id=f"p3-amt-{amount}", amount=amount)))
    assert body["final_status"] == expected_status
    assert body["decision_reason"] == expected_reason


def test_unknown_device_fails_closed_over_http(clients, tmp_path):
    attacker = tmp_path / "attacker"
    device_identity.init_device(attacker)
    body = _post(clients, _envelope(attacker, txn=_txn(transaction_id="p3-http-unknown")))
    assert body["final_status"] == FinalStatus.FAIL_CLOSED.value
    assert body["decision_reason"] == DecisionReason.DEVICE_UNKNOWN.value


def test_revoked_device_fails_closed_over_http(clients, device_keys, enrolled):
    revoke(enrolled, DEVICE_ID, "stolen")
    body = _post(clients, _envelope(device_keys, txn=_txn(transaction_id="p3-http-revoked")))
    assert body["final_status"] == FinalStatus.FAIL_CLOSED.value
    assert body["decision_reason"] == DecisionReason.DEVICE_REVOKED.value


def test_auth_failure_is_never_a_deny(clients, tmp_path):
    """Authentication failure means nothing refused the payment -- ATLAS
    could not establish who was asking. Reporting DENY would hide an attack
    inside normal risk behaviour."""
    attacker = tmp_path / "attacker2"
    device_identity.init_device(attacker)
    body = _post(clients, _envelope(attacker, txn=_txn(transaction_id="p3-notdeny")))
    assert body["final_status"] != FinalStatus.DENY.value
    assert DecisionReason(body["decision_reason"]) in FAIL_CLOSED_REASONS
    assert body["risk"] is None and body["decision"] is None


def test_tampered_amount_never_reaches_the_policy_engine(clients, device_keys):
    env = _envelope(device_keys, txn=_txn(transaction_id="p3-tamper-http"))
    tampered = env.model_copy(deep=True)
    tampered.transaction.amount = "1.00"
    body = _post(clients, tampered)
    assert body["decision_reason"] == DecisionReason.INVALID_DEVICE_SIGNATURE.value
    assert body["risk"] is None, "ML must not run on an unauthenticated request"


def test_bank_unreachable_over_signed_path_is_still_pending(
    tmp_path, device_keys, enrolled, device_db_path
):
    """Phase 2 semantics preserved exactly: an availability failure is
    PENDING -> reconcile, never FAIL_CLOSED and never DENY."""
    wire_bank_app_to_keys(tmp_path / "atlas-keys", tmp_path / "replay.db")
    atlas_app.dependency_overrides[get_bank_client] = lambda: httpx.Client()
    atlas_app.dependency_overrides[get_signing_keys_dir] = lambda: tmp_path / "atlas-keys"
    atlas_app.dependency_overrides[get_transaction_store] = lambda: TransactionStore(
        tmp_path / "atlas.db")
    atlas_app.dependency_overrides[get_device_store] = lambda: DeviceStore(device_db_path)
    atlas_app.dependency_overrides[get_allow_counter_reset] = lambda: False
    atlas_app.dependency_overrides[get_require_device_auth] = lambda: False
    import atlas_service.main as m
    original = m.BANK_SERVICE_URL
    m.BANK_SERVICE_URL = "http://127.0.0.1:1"
    try:
        body = _post(TestClient(atlas_app),
                     _envelope(device_keys, txn=_txn(transaction_id="p3-pending")))
    finally:
        m.BANK_SERVICE_URL = original
        atlas_app.dependency_overrides.clear()
        bank_app.dependency_overrides.clear()

    assert body["final_status"] == FinalStatus.PENDING.value
    assert body["decision_reason"] == DecisionReason.BANK_UNREACHABLE.value


def test_phase2_duplicate_transaction_id_still_enforced_on_signed_path(clients, device_keys):
    """Phase 3 must not weaken the Phase 2 replay fix."""
    txn = _txn(transaction_id="p3-dup")
    assert _post(clients, _envelope(device_keys, counter=1, txn=txn))["final_status"] == "ALLOW"
    body = _post(clients, _envelope(device_keys, counter=2, txn=txn))
    assert body["decision_reason"] == DecisionReason.DUPLICATE_TRANSACTION_ID.value


# --- legacy path -----------------------------------------------------------


def test_legacy_transact_still_works_by_default(clients):
    body = clients.post("/transact", json=_txn(transaction_id="p3-legacy")).json()
    assert body["final_status"] == "ALLOW"


def test_legacy_transact_closes_when_device_auth_is_required(
    tmp_path, enrolled, device_db_path
):
    atlas_app.dependency_overrides[get_require_device_auth] = lambda: True
    atlas_app.dependency_overrides[get_device_store] = lambda: DeviceStore(device_db_path)
    try:
        body = TestClient(atlas_app).post(
            "/transact", json=_txn(transaction_id="p3-legacy-closed")).json()
    finally:
        atlas_app.dependency_overrides.clear()
    assert body["final_status"] == FinalStatus.FAIL_CLOSED.value
    assert body["decision_reason"] == DecisionReason.DEVICE_AUTH_REQUIRED.value
