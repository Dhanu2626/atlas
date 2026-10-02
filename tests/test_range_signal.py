"""beyond_observed_range: the separate burst evidence signal (2026-09-25, approved).

The Isolation Forest is untouched and still does not see bursts; these tests show
that too, so the signal's work is never credited to the forest. What is pinned:

  1. normal activity does not fire;
  2. activity beyond the customer's own busiest earlier 24 hours fires;
  3. bursts of 13, 23, 48 and 103 payments -- the sizes the forest scored
     identically on 2026-09-25 -- against the held-out persona holdout-kochi, whose
     busiest earlier 24 hours hold 2 payments;
  4. the multiplier comes from the VALIDATION split only, and the shipped constant
     is exactly what that calibration produces;
  5. rows dated after the payment, and test-split cases, cannot move the signal or
     its multiplier;
  6. a customer below the minimum history gets INSUFFICIENT_HISTORY and no signal;
  7. velocity_burst is unchanged, and the signal changes a decision only through the
     customer's own BEYOND_OBSERVED_RANGE rule (policy v5, 2026-09-29).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from atlas_service.ml import evaluation as ev
from atlas_service.ml import range_signal as rs
from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.registry import MIN_HISTORY_FOR_BANDS, TrainedModel
from atlas_service.ml.synth import generate_normal_history
from atlas_service.policy.engine import POLICIES_DIR, evaluate, load_policy
from contracts import INSUFFICIENT_HISTORY, RangeSignal, RiskEvidence, Transaction

KOCHI = next(p for p in ev.HELD_OUT_PERSONAS if p.subject == "holdout-kochi")


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value)


@pytest.fixture(scope="module")
def kochi():
    history = generate_normal_history(KOCHI, n=200, seed=ev.TRAIN_SEEDS[KOCHI.subject])
    return PersonaAnomalyModel().fit(history), history


def _after(history, *, days: float, extras: int = 0):
    """A payment `days` after the history's last row, with `extras` payments in the
    two hours before it (4 minutes apart), exactly as the evaluation's bursts are."""
    last = max(_ts(t.timestamp) for t in history)
    base = history[-1]
    when = last + timedelta(days=days)
    tx = base.model_copy(update={"transaction_id": "probe", "timestamp": when.isoformat()})
    burst = [base.model_copy(update={"transaction_id": f"b{k}",
                                     "timestamp": (when - timedelta(minutes=4 * (k + 1))).isoformat()})
             for k in range(extras)]
    return tx, burst


# ---- 1 & 2: normal activity versus beyond the observed range --------------------------

def test_normal_activity_does_not_fire(kochi):
    _, history = kochi
    tx, _ = _after(history, days=2)
    signal = rs.beyond_observed_range(tx, history)
    assert signal.current_24h == 1 and signal.observed_max_24h == 2
    assert signal.fired is False


def test_the_busiest_day_itself_does_not_fire(kochi):
    _, history = kochi
    tx, burst = _after(history, days=2, extras=1)           # 2 in 24h: a normal busy day
    assert rs.beyond_observed_range(tx, history + burst).fired is False


def test_activity_beyond_the_observed_range_fires_and_says_why(kochi):
    _, history = kochi
    tx, burst = _after(history, days=2, extras=15)
    signal = rs.beyond_observed_range(tx, history + burst)
    assert signal.fired and signal.current_24h == 16 and signal.observed_max_24h == 2
    reason = rs.range_reason(signal)
    assert "beyond_observed_range" in reason and "separate from the anomaly score" in reason
    # the firmware scans reasons for these phrases; the signal must never trip them
    assert "new beneficiary" not in reason and "new device" not in reason


# ---- 3: the four burst sizes ---------------------------------------------------------

@pytest.mark.parametrize("size", [13, 23, 48, 103])
def test_bursts_of_13_23_48_and_103_fire_and_the_forest_still_does_not_see_them(kochi, size):
    model, history = kochi
    tx, burst = _after(history, days=2, extras=size - 1)
    signal = rs.beyond_observed_range(tx, history + burst)
    assert signal.current_24h == size and signal.observed_max_24h == 2
    assert signal.fired, f"{size} > {rs.RANGE_MULTIPLIER} x 2 should fire"
    # The forest does not see it -- the signal does. Measured 2026-09-25: the band
    # stays LOW and the anomaly score does not rise (it falls slightly: the forest
    # reads the burst as, if anything, more ordinary).
    alone = model.score(tx, history)
    with_burst = model.score(tx, history + burst)
    assert with_burst.risk_band == alone.risk_band == "LOW"
    assert with_burst.anomaly_score <= alone.anomaly_score


def test_the_forest_score_is_flat_from_13_to_103(kochi):
    model, history = kochi
    scores = []
    for size in (13, 23, 48, 103):
        tx, burst = _after(history, days=2, extras=size - 1)
        scores.append(model.score(tx, history + burst).anomaly_score)
    assert max(scores) - min(scores) < 0.005, scores


def test_the_threshold_is_strictly_greater_than_multiplier_times_the_busiest_day(kochi):
    _, history = kochi
    at = int(rs.RANGE_MULTIPLIER * 2)                        # 12 for kochi
    tx, burst = _after(history, days=2, extras=at - 1)
    assert rs.beyond_observed_range(tx, history + burst).fired is False
    tx, burst = _after(history, days=2, extras=at)
    assert rs.beyond_observed_range(tx, history + burst).fired is True


def test_no_earlier_history_outside_the_window_means_no_verdict(kochi):
    _, history = kochi
    tx, burst = _after(history, days=2, extras=40)
    signal = rs.beyond_observed_range(tx, burst)             # only the burst itself is known
    assert signal.observed_max_24h is None and signal.fired is False


# ---- 4 & 5: calibration uses validation only; the future cannot leak in -----------------

@pytest.fixture(scope="module")
def models():
    return ev.train_models()


def test_the_shipped_multiplier_is_what_validation_calibration_chooses(models):
    validation = [c for c in ev.build_cases() if c.split == "validation"]
    chosen, table = ev.calibrate_range_multiplier(validation, models)
    assert chosen == rs.RANGE_MULTIPLIER
    assert [row["multiplier"] for row in table] == list(ev.RANGE_GRID)
    eligible = [r for r in table if r["false_positive_rate"] <= ev.RANGE_MAX_FPR]
    best = max(r["burst_recall"] for r in eligible)
    assert chosen == max(r["multiplier"] for r in eligible if r["burst_recall"] == best)


def test_calibration_refuses_any_split_but_validation(models):
    test_cases = [c for c in ev.build_cases() if c.split == "test"]
    with pytest.raises(ValueError, match="validation cases only"):
        ev.calibrate_range_multiplier(test_cases, models)
    mixed = ev.build_cases()
    with pytest.raises(ValueError, match="validation cases only"):
        ev.calibrate_range_multiplier(mixed, models)


def test_rewriting_the_test_split_cannot_move_the_chosen_multiplier(models, monkeypatch):
    """Held-out data must not reach the choice: turn every test-split case into an
    enormous burst and the multiplier the full evaluation selects is unchanged."""
    real = ev.build_cases

    def poisoned():
        out = []
        for c in real():
            if c.split == "test":
                when = _ts(c.transaction.timestamp)
                huge = tuple(c.transaction.model_copy(update={
                    "transaction_id": f"{c.transaction.transaction_id}-x{k}",
                    "timestamp": (when - timedelta(seconds=10 * (k + 1))).isoformat()})
                    for k in range(500))
                c = ev.Case(c.split, c.persona, c.label, c.kind, c.transaction, huge)
            out.append(c)
        return out

    monkeypatch.setattr(ev, "build_cases", poisoned)
    monkeypatch.setattr(ev, "train_models", lambda: models)
    result = ev.evaluate_held_out()["beyond_observed_range"]
    assert result["selected_multiplier"] == rs.RANGE_MULTIPLIER


def test_rows_dated_after_the_payment_cannot_influence_the_signal(kochi):
    """The look-ahead rule: a history that ALSO contains a huge burst dated just after
    the payment -- and a busiest-ever day in the future -- gives the same signal."""
    _, history = kochi
    tx, burst = _after(history, days=2, extras=3)
    honest = rs.beyond_observed_range(tx, history + burst)
    t = _ts(tx.timestamp)
    future = [tx.model_copy(update={"transaction_id": f"f{k}",
                                    "timestamp": (t + timedelta(minutes=k + 1)).isoformat()})
              for k in range(300)]
    leaked = rs.beyond_observed_range(tx, history + burst + future)
    assert leaked == honest


def test_the_evaluation_measures_the_signal_only_against_earlier_rows(models, monkeypatch):
    seen = []
    original = rs.measure

    def spy(transaction, history):
        t = _ts(transaction.timestamp)
        seen.append(max(_ts(h.timestamp) for h in history) < t)
        return original(transaction, history)

    monkeypatch.setattr(rs, "measure", spy)
    ev.range_measurements([c for c in ev.build_cases() if c.split == "validation"][:60], models)
    assert seen and all(seen)


# ---- 6: below the minimum history, the approved cold-start behaviour ---------------------

def test_a_customer_below_the_minimum_gets_no_signal_even_mid_burst(kochi):
    model, history = kochi
    trained = TrainedModel(subject=KOCHI.subject, model=model, history=history,
                           trained_at="t", sklearn_version="x")
    tx, burst = _after(history, days=2, extras=60)
    short = (history[-(MIN_HISTORY_FOR_BANDS - 61):] + burst)
    assert len(short) == MIN_HISTORY_FOR_BANDS - 1
    evidence = trained.score(tx, short)
    assert evidence.risk_band == INSUFFICIENT_HISTORY and evidence.range_signal is None


def test_with_enough_history_the_layer_attaches_the_signal_and_leaves_the_band_alone(kochi):
    model, history = kochi
    trained = TrainedModel(subject=KOCHI.subject, model=model, history=history,
                           trained_at="t", sklearn_version="x")
    tx, burst = _after(history, days=2, extras=30)
    evidence = trained.score(tx, history + burst)
    forest = model.score(tx, history + burst)
    assert evidence.range_signal.fired
    assert (evidence.risk_band, evidence.anomaly_score) == (forest.risk_band, forest.anomaly_score)
    assert evidence.reasons[:len(forest.reasons)] == forest.reasons
    assert evidence.reasons[-1] == rs.range_reason(evidence.range_signal)


# ---- 7: velocity_burst and decisions unchanged ------------------------------------------

def test_velocity_burst_is_unchanged_in_the_policy():
    policy = load_policy(POLICIES_DIR / "user-demo-1.yaml")
    rule = next(r for r in policy["rules"] if r["name"] == "velocity_burst")
    assert rule == {"name": "velocity_burst", "condition": {"VELOCITY": 20}, "action": "DENY"}


def _burst_case(count):
    base = datetime(2026, 9, 23, 4, 30, tzinfo=timezone.utc)
    body = dict(subject="user-demo-1", amount="900.00", currency="INR", beneficiary="ben-mother",
                location="Hyderabad,IN", device_id="device-primary-01", merchant_category="utilities",
                authentication_method="device_button")
    history = [Transaction(transaction_id=f"h{i}", timestamp=(base + timedelta(minutes=i)).isoformat(), **body)
               for i in range(count - 1)]
    tx = Transaction(transaction_id="now", timestamp=(base + timedelta(minutes=count)).isoformat(), **body)
    quiet = RiskEvidence(anomaly_score=-0.3, risk_band="LOW", reasons=[])
    loud = quiet.model_copy(update={"range_signal": RangeSignal(
        fired=True, current_24h=count, observed_max_24h=2, multiplier=rs.RANGE_MULTIPLIER),
        "reasons": ["beyond_observed_range fired"]})
    return tx, history, quiet, loud


@pytest.mark.parametrize("count, expect_velocity", [(20, False), (21, True)])
def test_a_fired_signal_acts_only_through_the_customers_own_rule(count, expect_velocity):
    """Since policy v5 (2026-09-29) user-demo-1's burst_beyond_own_history rule asks
    for confirmation when the signal fires. The signal itself still changes no band,
    and with the rule removed it changes nothing at all -- it is the RULE that acts."""
    policy = load_policy(POLICIES_DIR / "user-demo-1.yaml")
    tx, history, quiet, loud = _burst_case(count)
    a, b = evaluate(tx, quiet, history, policy), evaluate(tx, loud, history, policy)
    assert "burst_beyond_own_history" not in a.matched_rules
    assert b.matched_rules == a.matched_rules + ["burst_beyond_own_history"]
    assert ("velocity_burst" in a.matched_rules) is expect_velocity
    if expect_velocity:                           # the stricter rule still wins: DENY
        assert (b.decision.value, b.deciding_rule) == ("DENY", "velocity_burst")
    else:                                         # under velocity's limit, the new rule catches it
        assert (a.decision.value, b.decision.value, b.deciding_rule) == \
               ("ALLOW", "STEP_UP", "burst_beyond_own_history")

    without_rule = {**policy, "rules": [r for r in policy["rules"] if r["name"] != "burst_beyond_own_history"]}
    c, d = evaluate(tx, quiet, history, without_rule), evaluate(tx, loud, history, without_rule)
    assert (c.decision, c.matched_rules, c.deciding_rule) == (d.decision, d.matched_rules, d.deciding_rule)


def test_the_burst_condition_needs_evidence_and_a_true_or_false():
    policy = {"version": 1, "rules": [{"name": "r", "condition": {"BEYOND_OBSERVED_RANGE": True},
                                       "action": "STEP_UP"}]}
    tx, history, quiet, loud = _burst_case(5)
    assert evaluate(tx, quiet, history, policy).decision.value == "ALLOW"      # no evidence: not judged
    assert evaluate(tx, loud, history, policy).decision.value == "STEP_UP"
    unfired = loud.model_copy(update={"range_signal": loud.range_signal.model_copy(update={"fired": False})})
    assert evaluate(tx, unfired, history, policy).decision.value == "ALLOW"
    policy["rules"][0]["condition"] = {"BEYOND_OBSERVED_RANGE": "yes"}
    with pytest.raises(ValueError, match="true or false"):
        evaluate(tx, loud, history, policy)


# ---- 2026-09-26: through the real signed endpoint, and across a restart -----------------

from atlas_service import main as atlas_main  # noqa: E402
from atlas_service.db import TransactionStore  # noqa: E402
from atlas_service.ml.registry import ModelRegistry  # noqa: E402
from tests.test_live_history import SUBJECT, _burst, _txn, device_keys, rig  # noqa: E402,F401


def _seed_daily(store, n: int = MIN_HISTORY_FOR_BANDS):
    """n real payments, one every 25 hours: the customer's busiest 24 hours hold 1."""
    base = datetime(2026, 1, 1, 9, 0, tzinfo=timezone.utc)
    for i in range(n):
        t = Transaction(**_txn(transaction_id=f"daily-{i}", amount="900.00", beneficiary="ben-mother",
                               timestamp=(base + timedelta(hours=25 * i)).isoformat()))
        store.claim_new(t.transaction_id, SUBJECT, str(t.amount), t.timestamp)
        store.record_details(t)


def test_a_live_burst_shows_the_signal_in_the_reply_the_reasons_and_the_log(rig, device_keys, caplog):
    """A customer with 200 real payments sends 8 in eight minutes -- under velocity_burst's
    limit of 20. The 7th and 8th exceed 6 x 1 and fire; the 6th sits on the boundary and
    does not. Visible in the reply, in the reasons and in the RISK audit line."""
    _seed_daily(rig["holder"]["store"])
    caplog.set_level("INFO")
    replies = _burst(rig, device_keys, count=8)
    signals = [r["risk"]["range_signal"] for r in replies]
    assert [s["current_24h"] for s in signals] == list(range(1, 9))
    assert all(s["observed_max_24h"] == 1 for s in signals)
    assert [s["fired"] for s in signals] == [False] * 6 + [True] * 2
    last = replies[-1]
    assert any("beyond_observed_range" in r for r in last["risk"]["reasons"])
    assert not any("beyond_observed_range" in r for r in replies[5]["risk"]["reasons"])
    assert "velocity_burst" not in last["decision"]["matched_rules"]
    # Policy v5: the two payments that fire the signal are stepped up by the
    # customer's burst rule; the six before it are not.
    assert [r["decision"]["deciding_rule"] == "burst_beyond_own_history" for r in replies] == [False] * 6 + [True] * 2
    assert [r["final_status"] for r in replies[6:]] == ["STEP_UP", "STEP_UP"]
    risk_lines = [m for m in caplog.messages if "[RISK]" in m and last["sent_id"] in m]
    assert risk_lines and "beyond_observed_range=FIRED current_24h=8 observed_max_24h=1 x6" in risk_lines[-1]


def test_the_live_decision_is_the_policys_and_the_signal_adds_only_the_burst_rule(rig, device_keys):
    """The decision ATLAS returned is the policy's on the evidence it had, and taking
    the signal away removes exactly one thing -- the burst rule. The band stays the
    forest's own: the signal never moves it."""
    store = rig["holder"]["store"]
    _seed_daily(store)
    replies = _burst(rig, device_keys, count=8)
    last = replies[-1]
    assert last["risk"]["range_signal"]["fired"]
    tx = Transaction(**_txn(transaction_id=last["sent_id"], amount="900.00", beneficiary="ben-mother",
                            timestamp=(datetime(2026, 9, 23, 4, 30, tzinfo=timezone.utc)
                                       + timedelta(minutes=7)).isoformat()))
    history = store.history_for(SUBJECT, exclude_transaction_id=last["sent_id"])
    trained = atlas_main.MODEL_REGISTRY.get(SUBJECT)
    forest = trained.model.score(tx, history)
    policy = load_policy(POLICIES_DIR / f"{SUBJECT}.yaml")
    with_signal = evaluate(tx, trained.score(tx, history), history, policy)
    without = evaluate(tx, forest, history, policy)
    assert last["risk"]["risk_band"] == forest.risk_band
    assert (last["final_status"], last["decision"]["matched_rules"], last["decision"]["deciding_rule"]) == \
           (with_signal.decision.value, with_signal.matched_rules, with_signal.deciding_rule)
    assert with_signal.matched_rules == without.matched_rules + ["burst_beyond_own_history"]


def test_restarting_the_store_and_reloading_the_model_gives_the_same_signal(rig, device_keys, trained_model_dir):
    store = rig["holder"]["store"]
    _seed_daily(store)
    replies = _burst(rig, device_keys, count=8)
    before = replies[-1]["risk"]["range_signal"]

    store.close()
    reopened = TransactionStore(rig["db"])                       # a restart
    rig["holder"]["store"] = reopened
    fresh = ModelRegistry(trained_model_dir)                    # models reloaded from disk
    tx = Transaction(**_txn(transaction_id=replies[-1]["sent_id"], amount="900.00", beneficiary="ben-mother",
                            timestamp=(datetime(2026, 9, 23, 4, 30, tzinfo=timezone.utc)
                                       + timedelta(minutes=7)).isoformat()))
    after = fresh.get(SUBJECT).score(tx, reopened.history_for(SUBJECT, exclude_transaction_id=tx.transaction_id))
    assert after.range_signal.model_dump() == before


def test_payments_at_the_same_instant_count_and_later_ones_never_do(kochi):
    """The window is (t - 24h, t]: a payment stamped the same second has already been
    received and counts -- otherwise 30 payments sharing one timestamp would read as 1.
    A payment stamped even one second later never counts."""
    _, history = kochi
    tx, _ = _after(history, days=2)
    same_instant = [tx.model_copy(update={"transaction_id": f"s{k}"}) for k in range(29)]
    one_second_later = [tx.model_copy(update={"transaction_id": f"l{k}",
                        "timestamp": (_ts(tx.timestamp) + timedelta(seconds=1)).isoformat()})
                        for k in range(29)]
    assert rs.beyond_observed_range(tx, history + same_instant).current_24h == 30
    assert rs.beyond_observed_range(tx, history + one_second_later).current_24h == 1
