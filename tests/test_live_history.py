"""Decisions are made against the subject's OWN persisted payments (2026-09-23).

Until this change both halves of a decision read the model's generated training
history: `_verified_new_beneficiary` and `_check_velocity` in the policy engine, and
every history-derived ML feature. A real burst of payments therefore moved nothing --
`velocity_burst` could not fire however many payments a device actually sent -- and a
beneficiary the subject had really paid was still "new".

What these tests pin, all of it through the real signed endpoint on temporary stores:

  * a payment is persisted in full and becomes history for the next one;
  * the burst rule fires on REAL payments, and still fires after the store is closed
    and reopened, and after a second service instance is built on the same file;
  * a beneficiary becomes known because the subject actually paid it;
  * the transaction being decided never appears in its own history (no look-ahead);
  * an empty history is treated as "nothing known", never silently replaced by the
    generated history the model was trained on;
  * pre-2026-09-23 rows, which carry no detail, are skipped rather than invented;
  * training/reference history is still exactly what the model was fitted on.

The decisive one is
test_a_burst_of_real_payments_denies_and_generated_history_would_not: it fails if the
live path ever falls back to generated history, because that history cannot produce a
burst. It asserts the DOWNSTREAM DECISION, not the presence of a database row.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from atlas_service.db import TransactionStore
from atlas_service.device.db import DeviceStore
from atlas_service.device.registry import register_demo_device
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
from atlas_service import main as atlas_main
from atlas_service.ml.registry import training_history
from atlas_service.policy.engine import POLICIES_DIR, evaluate, load_policy
from atlas_service.step_up.db import StepUpStore
from bank_service.main import app as bank_app
from contracts import DeviceEnvelope, Transaction, canonical_envelope_bytes
from firmware import device_identity
from tests.conftest import wire_bank_app_to_keys

DEVICE_ID = "esp32-atlas-history-01"
SUBJECT = "user-demo-1"
#: The demo persona's own device and location, so the only thing these tests vary is
#: the subject's history -- not who is asking or from where.
DEMO_DEVICE = "device-primary-01"
DEMO_LOCATION = "Hyderabad,IN"


@pytest.fixture
def device_keys(tmp_path) -> Path:
    keys = tmp_path / "device-keys"
    device_identity.init_device(keys)
    return keys


@pytest.fixture
def rig(tmp_path, device_keys):
    """The real signed endpoint, with every store in tmp_path. The transaction
    store is a single shared instance so a test can close and reopen the file."""
    device_db = tmp_path / "devices.db"
    store = DeviceStore(device_db)
    register_demo_device(store, device_id=DEVICE_ID,
                         device_key_id=device_identity.get_key_id(device_keys),
                         public_key=device_identity.get_public_key(device_keys),
                         bound_subject=SUBJECT)
    store.close()
    wire_bank_app_to_keys(tmp_path / "atlas-keys", tmp_path / "replay.db")
    bank = TestClient(bank_app)
    txn_db = tmp_path / "atlas.db"
    holder = {"store": TransactionStore(txn_db)}
    atlas_app.dependency_overrides.update({
        get_bank_client: lambda: bank,
        get_signing_keys_dir: lambda: tmp_path / "atlas-keys",
        get_transaction_store: lambda: holder["store"],
        get_device_store: lambda: DeviceStore(device_db),
        get_step_up_store: lambda: StepUpStore(tmp_path / "step_up.db"),
        get_allow_counter_reset: lambda: False,
    })
    yield {"client": TestClient(atlas_app), "db": txn_db, "holder": holder, "tmp": tmp_path}
    holder["store"].close()
    atlas_app.dependency_overrides.clear()
    bank_app.dependency_overrides.clear()


def _txn(**overrides) -> dict:
    body = dict(transaction_id=f"hist-{secrets.token_hex(4)}", subject=SUBJECT,
                amount="1500.00", currency="INR", beneficiary="ben-mother",
                location=DEMO_LOCATION, device_id=DEMO_DEVICE,
                merchant_category="utilities", authentication_method="device_button",
                timestamp="2026-09-23T04:30:00+00:00")   # 10:00 IST: outside odd_hours
    body.update(overrides)
    return body


def _send(rig, counter: int, keys: Path, txn: dict) -> dict:
    """One real payment through /v2/transact, signed as the enrolled device."""
    fields = dict(device_id=DEVICE_ID, device_key_id=device_identity.get_key_id(keys),
                  boot_id="boot-history", counter=counter, nonce=secrets.token_hex(16),
                  issued_at=datetime.now(timezone.utc).isoformat(), transaction=txn,
                  location=None, health=None, signature="")
    unsigned = DeviceEnvelope(**fields)
    signed = unsigned.model_copy(update={
        "signature": device_identity.secure_sign(canonical_envelope_bytes(unsigned), keys)})
    reply = rig["client"].post("/v2/transact", json=signed.model_dump(mode="json"))
    # `sent_id` is the id this test issued; not every exit path echoes it back.
    return {"sent_id": txn["transaction_id"], **reply.json()}


def _burst(rig, keys, *, count: int, start_counter: int = 1) -> list[dict]:
    """`count` real payments inside one hour, each its own transaction."""
    base = datetime(2026, 9, 23, 4, 30, tzinfo=timezone.utc)
    out = []
    for i in range(count):
        when = (base + timedelta(minutes=i)).isoformat()
        out.append(_send(rig, start_counter + i, keys,
                         _txn(timestamp=when, amount="900.00", beneficiary="ben-mother")))
    return out


# ---- the decisive test -------------------------------------------------------------

def test_a_burst_of_real_payments_denies_and_generated_history_would_not(rig, device_keys):
    """THE regression test for this change.

    21 real payments in 21 minutes must trip `velocity_burst` (VELOCITY: 20 -> DENY).
    The same rule evaluated against the model's generated history does NOT fire, which
    is asserted here so the test cannot pass if the live path ever falls back to it.
    Nothing is mocked and no feature value is written by hand: the payments go through
    the real signed endpoint and the rule is read from the shipped policy."""
    replies = _burst(rig, device_keys, count=21)

    denied = [r for r in replies if r["final_status"] == "DENY"]
    assert denied, "a burst of 21 real payments never tripped the velocity rule"
    assert "velocity_burst" in denied[0]["decision"]["matched_rules"]
    assert denied[0]["decision_reason"] == "POLICY_DENY"

    # ... and the generated history the model was trained on could not have produced
    # this, which is exactly why the old implementation could not see a burst.
    policy = load_policy(POLICIES_DIR / f"{SUBJECT}.yaml")
    trained = atlas_main.MODEL_REGISTRY.get(SUBJECT)   # the session's trained model (conftest)
    last = Transaction(**_txn(timestamp="2026-09-23T04:50:00+00:00", amount="900.00"))
    generated = evaluate(last, trained.score(last, trained.history), trained.history, policy)
    assert "velocity_burst" not in generated.matched_rules, (
        "the generated history now contains a burst; this test can no longer tell the "
        "two history sources apart and must be rewritten"
    )


def test_the_burst_verdict_survives_closing_and_reopening_the_store(rig, device_keys):
    """Same burst, but the store is closed and reopened partway through, and the
    service is handed a second TransactionStore instance on the same file. History
    that only lived in memory would vanish here."""
    _burst(rig, device_keys, count=18)

    rig["holder"]["store"].close()
    rig["holder"]["store"] = TransactionStore(rig["db"])       # new instance, same file

    replies = _burst(rig, device_keys, count=4, start_counter=19)
    denied = [r for r in replies if r["final_status"] == "DENY"]
    assert denied, "the burst was forgotten when the store was reopened"
    assert "velocity_burst" in denied[0]["decision"]["matched_rules"]


# ---- new payee, known payee --------------------------------------------------------

def test_a_payee_becomes_known_because_the_subject_really_paid_it(rig, device_keys):
    """First payment to a payee is new; the second is not. The policy semantics are
    untouched -- NEW_BENEFICIARY still means "not in this subject's history"; what
    changed is that the history is now real."""
    payee = "ben-newshop-live"
    first = _send(rig, 1, device_keys, _txn(beneficiary=payee, amount="25000.00"))
    assert "new_beneficiary_meaningful_amount" in first["decision"]["matched_rules"], (
        "a genuinely new payee over the rule's amount was not treated as new")

    second = _send(rig, 2, device_keys, _txn(beneficiary=payee, amount="25000.00"))
    assert "new_beneficiary_meaningful_amount" not in second["decision"]["matched_rules"], (
        "a payee the subject really paid is still being called new")


def test_a_known_payee_stays_known_after_the_store_is_reopened(rig, device_keys):
    payee = "ben-recurring-live"
    _send(rig, 1, device_keys, _txn(beneficiary=payee, amount="25000.00"))

    rig["holder"]["store"].close()
    rig["holder"]["store"] = TransactionStore(rig["db"])

    again = _send(rig, 2, device_keys, _txn(beneficiary=payee, amount="25000.00"))
    assert "new_beneficiary_meaningful_amount" not in again["decision"]["matched_rules"], (
        "reopening the store erased a payee the subject had really paid")


# ---- what the history is, and is not ------------------------------------------------

def test_the_transaction_being_decided_is_never_in_its_own_history(rig, device_keys):
    """Look-ahead leakage: the row is written before the decision, so the decision
    must exclude it explicitly. If it did not, a payment would make its own payee
    'known' and would count itself twice in the 24-hour window."""
    payee = "ben-selfcheck"
    reply = _send(rig, 1, device_keys, _txn(beneficiary=payee, amount="25000.00"))
    assert "new_beneficiary_meaningful_amount" in reply["decision"]["matched_rules"], (
        "the transaction saw itself in its own history")

    store = rig["holder"]["store"]
    txn_id = reply["sent_id"]
    assert [t.transaction_id for t in store.history_for(SUBJECT)] == [txn_id]
    assert store.history_for(SUBJECT, exclude_transaction_id=txn_id) == []


def test_an_unseen_subject_has_no_history_rather_than_a_generated_one(rig):
    """The cold-start case, stated explicitly: ATLAS knows nothing about a subject it
    has never seen, and says so. It must NOT hand back the 200 generated transactions
    the model was trained on."""
    store = rig["holder"]["store"]
    assert store.history_for("user-never-seen") == []
    assert len(training_history(SUBJECT)) == 200        # the reference data still exists
    assert store.history_for(SUBJECT) == []             # and is not what the store returns


def test_rows_written_before_the_migration_are_skipped_not_invented(tmp_path):
    """An existing database keeps its rows, gains the new columns, and its old rows --
    which have no beneficiary, timestamp or device -- are left out of history rather
    than filled in with guesses."""
    import sqlite3
    db = tmp_path / "legacy.db"
    with sqlite3.connect(db) as conn:                   # the pre-2026-09-23 schema
        conn.execute("CREATE TABLE transactions (transaction_id TEXT PRIMARY KEY, "
                     "subject TEXT NOT NULL, amount TEXT NOT NULL, state TEXT NOT NULL, "
                     "created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
        conn.execute("INSERT INTO transactions VALUES ('old-1', ?, '500.00', 'CONFIRMED', "
                     "'2026-09-01T00:00:00+00:00', '2026-09-01T00:00:00+00:00')", (SUBJECT,))

    store = TransactionStore(db)                        # migrates in place
    assert store.get_state("old-1") is not None, "migration lost an existing row"
    assert store.history_for(SUBJECT) == [], "a detail-less row was invented into history"

    fresh = Transaction(**_txn(transaction_id="new-1", beneficiary="ben-after-migration"))
    store.claim_new("new-1", SUBJECT, str(fresh.amount), "2026-09-23T04:30:00+00:00")
    store.record_details(fresh)
    assert [t.transaction_id for t in store.history_for(SUBJECT)] == ["new-1"]
    store.close()


def test_history_is_per_subject(rig, device_keys):
    _send(rig, 1, device_keys, _txn(beneficiary="ben-mine"))
    store = rig["holder"]["store"]
    assert [t.beneficiary for t in store.history_for(SUBJECT)] == ["ben-mine"]
    assert store.history_for("user-poor-1") == []


def test_every_state_counts_as_history_including_a_refused_payment(rig, device_keys):
    """A denied payment is still something the subject did. Dropping it would let
    anyone reset their own velocity window by being refused."""
    denied = _send(rig, 1, device_keys, _txn(amount="150000.00"))    # hard_cap -> DENY
    assert denied["final_status"] == "DENY"
    store = rig["holder"]["store"]
    assert [t.transaction_id for t in store.history_for(SUBJECT)] == [denied["sent_id"]]


def test_history_is_ordered_oldest_first_and_bounded(rig, device_keys):
    from atlas_service.db import HISTORY_LIMIT
    replies = _burst(rig, device_keys, count=5)
    history = rig["holder"]["store"].history_for(SUBJECT)
    times = [t.timestamp for t in history]
    assert times == sorted(times), "history is not oldest-first"
    assert len(history) <= HISTORY_LIMIT
    assert [t.transaction_id for t in history] == [r["sent_id"] for r in replies]


# ---- the ML side ---------------------------------------------------------------------

def test_the_ml_features_move_with_real_history(rig, device_keys):
    """The same payment scores differently once the subject has really paid that payee
    before -- proof that the feature vector, not just the policy rule, reads live
    history. Nothing here asserts a particular band: only that real history changes the
    evidence, and in the direction of 'more familiar'."""
    from atlas_service.ml.features import FEATURE_NAMES, extract_features

    payee, store = "ben-ml-live", rig["holder"]["store"]
    probe = Transaction(**_txn(transaction_id="probe-ml", beneficiary=payee))

    cold = extract_features(probe, store.history_for(SUBJECT))
    _send(rig, 1, device_keys, _txn(beneficiary=payee))
    warm = extract_features(probe, store.history_for(SUBJECT))

    i_ben = FEATURE_NAMES.index("is_new_beneficiary")
    i_dev = FEATURE_NAMES.index("is_new_device")
    assert cold[i_ben] == 1.0 and warm[i_ben] == 0.0, "the payee never became known"
    assert cold[i_dev] == 1.0 and warm[i_dev] == 0.0, "the device never became known"


def test_training_history_is_still_the_reference_the_model_was_fitted_on(rig):
    """Training/reference data (A) and live subject history (B) stay separate: the
    model keeps the 200 generated transactions it was fitted on, and the live path
    never writes to them."""
    trained = atlas_main.MODEL_REGISTRY.get(SUBJECT)
    assert len(trained.history) == 200
    assert trained.history == training_history(SUBJECT)
    assert rig["holder"]["store"].history_for(SUBJECT) == []


# ---- cold start: unknown is not anomalous -------------------------------------------

def test_cold_start_reports_missing_history_instead_of_calling_it_anomalous(rig, device_keys):
    """A subject ATLAS has never seen must not be graded as an outlier for the sole
    reason that nothing about them is known yet. Since 2026-09-25 (approved
    specification change) the ML layer says so explicitly: INSUFFICIENT_HISTORY, no
    score -- not LOW, which would claim a judgement it never made."""
    from atlas_service.ml.registry import MIN_HISTORY_FOR_BANDS
    from contracts import INSUFFICIENT_HISTORY

    trained = atlas_main.MODEL_REGISTRY.get(SUBJECT)
    probe = Transaction(**_txn(transaction_id="cold-1"))
    evidence = trained.score(probe, [])

    assert evidence.risk_band == INSUFFICIENT_HISTORY
    assert evidence.risk_band != "LOW"
    assert evidence.anomaly_score is None, "an unscored customer was given a score"
    assert evidence.range_signal is None, "the burst signal ran below the minimum history"
    assert any("not enough payment history" in r for r in evidence.reasons), evidence.reasons
    assert str(MIN_HISTORY_FOR_BANDS) in evidence.reasons[0]


def test_the_deterministic_rules_still_decide_when_there_is_no_history(rig, device_keys):
    """The sufficiency rule silences the ML band only. Everything the policy can
    check without history still applies in full on a subject's very first payment."""
    over_cap = _send(rig, 1, device_keys, _txn(amount="150000.00"))
    assert over_cap["final_status"] == "DENY"
    assert "hard_cap" in over_cap["decision"]["matched_rules"]

    new_payee = _send(rig, 2, device_keys, _txn(amount="25000.00", beneficiary="ben-brand-new"))
    assert "new_beneficiary_meaningful_amount" in new_payee["decision"]["matched_rules"]
    assert "large_amount" not in new_payee["decision"]["matched_rules"]


def test_a_first_ordinary_payment_is_still_allowed(rig, device_keys):
    """The behaviour this rule exists to protect: an ordinary payment from a subject
    with no history is ALLOWED, not stepped up because ATLAS has never met them."""
    reply = _send(rig, 1, device_keys, _txn(amount="1500.00"))
    assert reply["final_status"] == "ALLOW", reply.get("decision")


def test_the_band_is_graded_once_the_subject_has_enough_real_history(rig):
    """The threshold is a threshold, not an off switch: fill the store with enough of
    the subject's own payments and the model grades them normally again. Built through
    the store's own API rather than 200 HTTP calls, which is the same write path the
    endpoint uses."""
    from atlas_service.ml.registry import MIN_HISTORY_FOR_BANDS

    store, base = rig["holder"]["store"], datetime(2026, 3, 1, 9, 0, tzinfo=timezone.utc)
    for i in range(MIN_HISTORY_FOR_BANDS):
        t = Transaction(**_txn(transaction_id=f"seed-{i}", amount="1200.00",
                               beneficiary="ben-mother",
                               timestamp=(base + timedelta(hours=6 * i)).isoformat()))
        store.claim_new(t.transaction_id, SUBJECT, str(t.amount), t.timestamp)
        store.record_details(t)

    history = store.history_for(SUBJECT)
    assert len(history) == MIN_HISTORY_FOR_BANDS

    trained = atlas_main.MODEL_REGISTRY.get(SUBJECT)
    graded = trained.score(Transaction(**_txn(transaction_id="graded-1")), history)
    assert not any("not enough payment history" in r for r in graded.reasons), graded.reasons
    assert graded.risk_band in {"LOW", "MEDIUM", "HIGH"}


# ---- which layer actually catches a burst --------------------------------------------

def test_a_live_burst_is_refused_by_the_policy_rule_with_no_help_from_the_model(rig, device_keys):
    """Which layer actually stops a burst, stated so neither can be over-claimed.

    During a real burst the subject has far fewer than MIN_HISTORY_FOR_BANDS payments
    on record, so the ML layer reports "not enough history" and contributes nothing:
    the refusal comes entirely from `velocity_burst`, a deterministic policy rule
    reading the subject's real payments.

    The model's own burst behaviour is measured separately and is not flattering --
    on the four held-out evaluation personas the anomaly score barely moves with the
    24-hour count and burst recall is 0.0 (docs/ATLAS-Blueprint.md 19.3). It is not
    what protects this path."""
    replies = _burst(rig, device_keys, count=21)

    refused = [r for r in replies if r["final_status"] == "DENY"]
    assert refused, "a live burst was not refused"
    assert "velocity_burst" in refused[0]["decision"]["matched_rules"]
    assert refused[0]["decision"]["deciding_rule"] == "velocity_burst"

    # ML said nothing, and said why -- explicitly, not as LOW (2026-09-25).
    assert refused[0]["risk"]["risk_band"] == "INSUFFICIENT_HISTORY"
    assert refused[0]["risk"]["anomaly_score"] is None
    assert any("not enough payment history" in r for r in refused[0]["risk"]["reasons"])
