"""INSUFFICIENT_HISTORY: the explicit cold-start state (2026-09-25, approved).

Until 2026-09-25 a customer with fewer than MIN_HISTORY_FOR_BANDS payments got
risk_band LOW and anomaly_score 0.0 -- a judgement that was never made. The ML
layer now says INSUFFICIENT_HISTORY with no score. The approved requirement is that
this is honest labelling, not a decision change: no RISK_THRESHOLD rule matches it,
and every payment decision is what it was under LOW.

Pinned here: (1) an insufficient-history customer gets INSUFFICIENT_HISTORY, through
the real signed endpoint too; (2) RISK_THRESHOLD never matches it, at any threshold;
(3) the deterministic rules still decide, and decide exactly as under the old LOW;
(4) a customer with enough history keeps the forest's own band and score unchanged;
(5) closing and reopening the stores, and the step-up context's round trip through
SQLite, never turn it back into LOW.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from atlas_service import main as atlas_main
from atlas_service.db import TransactionStore
from atlas_service.ml.registry import MIN_HISTORY_FOR_BANDS
from atlas_service.policy.engine import POLICIES_DIR, evaluate, load_policy
from atlas_service.step_up.db import StepUpStore
from atlas_service.step_up.service import freeze_context, issue_challenge
from contracts import INSUFFICIENT_HISTORY, FrozenDecisionContext, RiskEvidence, Transaction
from tests.test_live_history import SUBJECT, _send, _txn, device_keys, rig  # noqa: F401  (fixtures)

POLICY = load_policy(POLICIES_DIR / f"{SUBJECT}.yaml")
UNJUDGED = RiskEvidence(anomaly_score=None, risk_band=INSUFFICIENT_HISTORY, reasons=["x"])
OLD_LOW = RiskEvidence(anomaly_score=0.0, risk_band="LOW", reasons=["x"])   # the pre-2026-09-25 answer


def _seed(store: TransactionStore, n: int, *, start: datetime) -> list[Transaction]:
    rows = []
    for i in range(n):
        t = Transaction(**_txn(transaction_id=f"seed-{i}", amount="1200.00", beneficiary="ben-mother",
                               timestamp=(start + timedelta(hours=6 * i)).isoformat()))
        store.claim_new(t.transaction_id, SUBJECT, str(t.amount), t.timestamp)
        store.record_details(t)
        rows.append(t)
    return rows


# ---- 1. the state itself ---------------------------------------------------------------

def test_one_payment_short_of_the_minimum_is_insufficient_not_low(rig):
    store = rig["holder"]["store"]
    _seed(store, MIN_HISTORY_FOR_BANDS - 1, start=datetime(2026, 3, 1, 9, tzinfo=timezone.utc))
    history = store.history_for(SUBJECT)
    evidence = atlas_main.MODEL_REGISTRY.get(SUBJECT).score(Transaction(**_txn(transaction_id="p")), history)
    assert (evidence.risk_band, evidence.anomaly_score) == (INSUFFICIENT_HISTORY, None)
    assert evidence.range_signal is None
    assert f"{MIN_HISTORY_FOR_BANDS - 1} of {MIN_HISTORY_FOR_BANDS}" in evidence.reasons[0]


def test_the_signed_endpoint_reports_insufficient_history_for_a_new_customer(rig, device_keys):
    reply = _send(rig, 1, device_keys, _txn(amount="1500.00"))
    assert reply["risk"]["risk_band"] == INSUFFICIENT_HISTORY
    assert reply["risk"]["anomaly_score"] is None
    assert reply["final_status"] == "ALLOW"


# ---- 2. RISK_THRESHOLD never matches it ---------------------------------------------------

@pytest.mark.parametrize("threshold", ["LOW", "MEDIUM", "HIGH"])
def test_no_risk_threshold_matches_insufficient_history(threshold):
    """Even RISK_THRESHOLD: LOW -- which every real band meets -- does not match."""
    policy = {"version": 1, "subject": SUBJECT, "rules": [
        {"name": "ml_rule", "condition": {"RISK_THRESHOLD": threshold}, "action": "DENY"}]}
    decision = evaluate(Transaction(**_txn()), UNJUDGED, [], policy)
    assert "ml_rule" not in decision.matched_rules
    assert decision.decision.value == "ALLOW"
    judged_low = evaluate(Transaction(**_txn()), OLD_LOW, [], policy)
    assert ("ml_rule" in judged_low.matched_rules) is (threshold == "LOW")


def test_an_unrecognised_band_still_fails_loudly():
    """Only the named state is exempt; anything else is still a contract error."""
    policy = {"version": 1, "subject": SUBJECT, "rules": [
        {"name": "ml_rule", "condition": {"RISK_THRESHOLD": "HIGH"}, "action": "DENY"}]}
    with pytest.raises(KeyError):
        evaluate(Transaction(**_txn()), RiskEvidence(anomaly_score=None, risk_band="UNKNOWN"), [], policy)


# ---- 3. deterministic rules decide, exactly as before ----------------------------------------

@pytest.mark.parametrize("amount, beneficiary, when", [
    ("1500.00", "ben-mother", "2026-09-23T04:30:00+00:00"),       # ordinary
    ("60000.00", "ben-mother", "2026-09-23T04:30:00+00:00"),      # large_amount
    ("150000.00", "ben-mother", "2026-09-23T04:30:00+00:00"),     # hard_cap
    ("25000.00", "ben-brand-new", "2026-09-23T04:30:00+00:00"),   # new payee
    ("1500.00", "ben-mother", "2026-09-23T18:30:00+00:00"),       # odd_hours (00:00 IST)
])
def test_every_decision_is_identical_to_the_old_low_answer(amount, beneficiary, when):
    tx = Transaction(**_txn(amount=amount, beneficiary=beneficiary, timestamp=when))
    old = evaluate(tx, OLD_LOW, [], POLICY)
    new = evaluate(tx, UNJUDGED, [], POLICY)
    assert (new.decision, new.matched_rules, new.deciding_rule) == \
           (old.decision, old.matched_rules, old.deciding_rule)


def test_velocity_burst_still_decides_with_no_ml_judgement():
    base = datetime(2026, 9, 23, 4, 30, tzinfo=timezone.utc)
    history = [Transaction(**_txn(transaction_id=f"h{i}", timestamp=(base + timedelta(minutes=i)).isoformat()))
               for i in range(20)]
    tx = Transaction(**_txn(transaction_id="h20", timestamp=(base + timedelta(minutes=20)).isoformat()))
    decision = evaluate(tx, UNJUDGED, history, POLICY)
    assert decision.deciding_rule == "velocity_burst" and decision.decision.value == "DENY"
    assert decision == evaluate(tx, OLD_LOW, history, POLICY)


# ---- 4. enough history: the forest's own answer, untouched ----------------------------------

def test_a_customer_with_enough_history_keeps_the_forests_band_and_score(rig):
    store = rig["holder"]["store"]
    _seed(store, MIN_HISTORY_FOR_BANDS, start=datetime(2026, 3, 1, 9, tzinfo=timezone.utc))
    history = store.history_for(SUBJECT)
    trained = atlas_main.MODEL_REGISTRY.get(SUBJECT)
    tx = Transaction(**_txn(transaction_id="graded"))
    via_layer = trained.score(tx, history)
    forest_alone = trained.model.score(tx, history)
    assert via_layer.risk_band == forest_alone.risk_band in {"LOW", "MEDIUM", "HIGH"}
    assert via_layer.anomaly_score == forest_alone.anomaly_score is not None
    assert via_layer.range_signal is not None


# ---- 5. persistence never turns it into LOW --------------------------------------------------

def test_reopening_the_store_keeps_an_insufficient_customer_insufficient(rig, device_keys):
    _send(rig, 1, device_keys, _txn(amount="1500.00"))
    rig["holder"]["store"].close()
    rig["holder"]["store"] = TransactionStore(rig["db"])            # a restart
    reply = _send(rig, 2, device_keys, _txn(amount="1500.00"))
    assert reply["risk"]["risk_band"] == INSUFFICIENT_HISTORY
    assert reply["risk"]["anomaly_score"] is None
    second_instance = TransactionStore(rig["db"])
    history = second_instance.history_for(SUBJECT)
    second_instance.close()
    assert len(history) == 2
    evidence = atlas_main.MODEL_REGISTRY.get(SUBJECT).score(Transaction(**_txn(transaction_id="p")), history)
    assert evidence.risk_band == INSUFFICIENT_HISTORY


def test_the_step_up_context_survives_sqlite_as_insufficient_history(tmp_path):
    """The frozen step-up context is stored as JSON and reloaded on resolution. A
    None score must come back as None and the state as INSUFFICIENT_HISTORY -- not
    coerced to 0.0 / LOW by the round trip."""
    tx = Transaction(**_txn(transaction_id="su-1", amount="60000.00"))
    decision = evaluate(tx, UNJUDGED, [], POLICY)
    assert decision.decision.value == "STEP_UP"
    context = freeze_context(tx, "UPI", decision, UNJUDGED, POLICY, "0" * 64)
    store = StepUpStore(tmp_path / "step_up.db")
    challenge_id, _ = issue_challenge(store, context, datetime.now(timezone.utc))
    store.close()
    reopened = StepUpStore(tmp_path / "step_up.db")
    loaded = reopened.load_context(reopened.get_challenge(challenge_id))
    raw = json.loads(reopened.get_challenge(challenge_id)["context_json"])
    reopened.close()
    assert (loaded.risk_band, loaded.anomaly_score) == (INSUFFICIENT_HISTORY, None)
    assert (raw["risk_band"], raw["anomaly_score"]) == (INSUFFICIENT_HISTORY, None)


def test_a_context_frozen_before_2026_09_25_still_loads():
    """Old contexts carry a float score; the widened type still accepts them."""
    ctx = FrozenDecisionContext.model_validate({
        **json.loads(freeze_context(Transaction(**_txn(transaction_id="old")), "UPI",
                                    evaluate(Transaction(**_txn(transaction_id="old", amount="60000.00")),
                                             OLD_LOW, [], POLICY),
                                    OLD_LOW, POLICY, "0" * 64).model_dump_json())})
    assert (ctx.risk_band, ctx.anomaly_score) == ("LOW", 0.0)
