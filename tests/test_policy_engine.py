"""Deliberately adversarial: boundary conditions, multi-rule conflicts, and an
attempt to fool the "is this a new beneficiary" check by lying about it on the
transaction itself, not just the happy path.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from atlas_service.policy.engine import (
    POLICIES_DIR,
    RolledBackPolicyError,
    check_rollback,
    compute_policy_hash,
    evaluate,
    load_policy,
)
from contracts import Decision, RiskEvidence, Transaction

POLICY_PATH = POLICIES_DIR / "user-demo-1.yaml"


def _tx(**overrides) -> Transaction:
    defaults = dict(
        transaction_id="tx-1",
        subject="user-demo-1",
        amount=Decimal("1000.00"),
        currency="INR",
        beneficiary="ben-known",
        location="Bengaluru,IN",
        device_id="device-1",
        merchant_category="amazon",
        authentication_method="pin",
        is_new_beneficiary=False,
        is_new_device=False,
        is_international=False,
        declared_travel_mode=False,
        is_emergency_request=False,
        timestamp="2026-08-24T12:00:00+00:00",
    )
    defaults.update(overrides)
    return Transaction(**defaults)


def _risk(band: str = "LOW") -> RiskEvidence:
    return RiskEvidence(anomaly_score=0.0, risk_band=band, reasons=[])


KNOWN_HISTORY = [_tx(transaction_id=f"hist-{i}", beneficiary="ben-known") for i in range(5)]


@pytest.fixture
def policy() -> dict:
    return load_policy(POLICY_PATH)


# --- happy path -------------------------------------------------------------


def test_normal_transaction_allowed(policy):
    d = evaluate(_tx(), _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.ALLOW
    assert d.matched_rules == []


def test_large_amount_steps_up(policy):
    d = evaluate(_tx(amount=Decimal("60000")), _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.STEP_UP
    assert "large_amount" in d.matched_rules


def test_international_steps_up(policy):
    d = evaluate(_tx(is_international=True), _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.STEP_UP


def test_high_ml_risk_steps_up(policy):
    d = evaluate(_tx(), _risk("HIGH"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.STEP_UP
    assert "high_ml_risk" in d.matched_rules


# --- boundary conditions ------------------------------------------------


def test_amount_exactly_at_limit_does_not_trigger(policy):
    """MAX_AMOUNT: 50000 means "exceeds", not "reaches" — exactly 50000 should
    not fire large_amount. Off-by-one is exactly the kind of bug a boundary
    test catches and a happy-path test never would."""
    d = evaluate(_tx(amount=Decimal("50000")), _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.ALLOW


def test_amount_one_paisa_over_limit_triggers(policy):
    d = evaluate(_tx(amount=Decimal("50000.01")), _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.STEP_UP


# Timestamps below carry an explicit +05:30 offset as of 2026-08-26.
#
# These three tests always MEANT "hour N in the user's day", and their names
# say so -- but they were written with +00:00 timestamps back when the engine
# read the raw hour of whatever offset arrived. user-demo-1.yaml now declares
# `timezone: Asia/Kolkata` (the Phase 2 timezone fix), so a UTC timestamp no
# longer denotes the local hour these tests claim to check: 21:59Z is 03:29
# IST, squarely inside odd_hours, which is why the old fixture started
# failing. The window semantics are untouched -- still [22, 6), still
# wrapping past midnight. Only the fixtures were corrected to actually
# express the local hour they were always describing.
#
# Boundary coverage against the IST-anchored window also lives in
# tests/test_phase2_fixes.py::test_time_window_boundaries_in_local_time.


def test_time_window_boundary_start_inclusive(policy):
    """odd_hours: [22, 6]. Hour 22 exactly should trigger (window starts at 22)."""
    d = evaluate(_tx(timestamp="2026-08-24T22:00:00+05:30"), _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.STEP_UP


def test_time_window_boundary_end_exclusive(policy):
    """Hour 6 exactly should NOT trigger — the window is [22, 6), matching how
    MAX_AMOUNT's own boundary is handled (consistent semantics across
    primitives, not an arbitrary difference between them)."""
    d = evaluate(_tx(timestamp="2026-08-24T06:00:00+05:30"), _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.ALLOW


def test_time_window_hour_21_does_not_trigger(policy):
    d = evaluate(_tx(timestamp="2026-08-24T21:59:00+05:30"), _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.ALLOW


def test_velocity_exactly_at_limit_does_not_trigger(policy):
    base = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
    history = [
        _tx(transaction_id=f"v-{i}", timestamp=(base - timedelta(minutes=i)).isoformat())
        for i in range(19)  # 19 prior + this one = 20, at the limit, not over
    ]
    d = evaluate(_tx(timestamp=base.isoformat()), _risk("LOW"), history, policy)
    assert d.decision == Decision.ALLOW


def test_velocity_one_over_limit_triggers_deny(policy):
    base = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
    history = [
        _tx(transaction_id=f"v-{i}", timestamp=(base - timedelta(minutes=i)).isoformat())
        for i in range(20)  # 20 prior + this one = 21, over the limit
    ]
    d = evaluate(_tx(timestamp=base.isoformat()), _risk("LOW"), history, policy)
    assert d.decision == Decision.DENY
    assert "velocity_burst" in d.matched_rules


# --- conflicting rules: most-restrictive-wins -------------------------------


def test_conflicting_rules_most_restrictive_wins(policy):
    """amount=150000 matches BOTH large_amount (STEP_UP) and hard_cap (DENY).
    DENY must win — this is the actual point of Test 2 in BUILD-PLAN.md's list
    and the whole reason the severity ordering exists."""
    d = evaluate(_tx(amount=Decimal("150000")), _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.DENY
    assert set(d.matched_rules) >= {"large_amount", "hard_cap"}


def test_two_step_up_rules_both_recorded(policy):
    """international_txn and high_ml_risk both fire (both STEP_UP, no severity
    conflict) — the decision should still be STEP_UP, and both reasons should
    be visible in matched_rules for audit, not just the first one found."""
    d = evaluate(_tx(is_international=True), _risk("HIGH"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.STEP_UP
    assert set(d.matched_rules) >= {"international_txn", "high_ml_risk"}


def test_trusted_beneficiary_does_not_exempt_from_ml_risk(policy):
    """The reframed Test 3: a KNOWN (trusted) beneficiary means NEW_BENEFICIARY
    never fires, but that must not exempt the transaction from RISK_THRESHOLD —
    trust in the beneficiary and risk in the behavior are independent axes.
    This is the actual conflict Test 3 is checking, expressed with the frozen
    seven primitives rather than an invented eighth one."""
    known_beneficiary_tx = _tx(beneficiary="ben-known")  # in KNOWN_HISTORY already
    d = evaluate(known_beneficiary_tx, _risk("HIGH"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.STEP_UP
    assert "new_beneficiary_meaningful_amount" not in d.matched_rules
    assert "high_ml_risk" in d.matched_rules


def test_new_beneficiary_alone_below_amount_threshold_does_not_trigger(policy):
    """new_beneficiary_meaningful_amount requires BOTH conditions (AND). A new
    beneficiary for a small amount should not fire it — only the combination
    should, matching the research's own worked example exactly."""
    d = evaluate(
        _tx(beneficiary="ben-brand-new", amount=Decimal("500")),
        _risk("LOW"), KNOWN_HISTORY, policy,
    )
    assert d.decision == Decision.ALLOW


# --- the adversarial one: lying about is_new_beneficiary --------------------


def test_client_lying_about_new_beneficiary_is_ignored(policy):
    """Sets is_new_beneficiary=False on the transaction for a beneficiary that
    has never actually appeared in history — simulating a compromised client
    trying to evade the rule. The engine must catch this by checking history
    itself, exactly per Day 13's red-team finding, not trust the flag."""
    lying_tx = _tx(
        beneficiary="ben-never-seen-before",
        amount=Decimal("25000"),
        is_new_beneficiary=False,  # the lie
    )
    d = evaluate(lying_tx, _risk("LOW"), KNOWN_HISTORY, policy)
    assert d.decision == Decision.STEP_UP
    assert "new_beneficiary_meaningful_amount" in d.matched_rules


# --- policy hashing and rollback protection ---------------------------------


def test_hash_is_deterministic(policy):
    assert compute_policy_hash(policy) == compute_policy_hash(load_policy(POLICY_PATH))


def test_hash_changes_if_policy_content_changes(policy):
    import copy
    mutated = copy.deepcopy(policy)
    mutated["rules"][0]["condition"]["MAX_AMOUNT"] = 999999
    assert compute_policy_hash(mutated) != compute_policy_hash(policy)


def test_rollback_rejected():
    with pytest.raises(RolledBackPolicyError):
        check_rollback("user-demo-1", seen_version=5, attempted_version=4)


def test_same_version_is_not_a_rollback():
    check_rollback("user-demo-1", seen_version=5, attempted_version=5)  # must not raise


def test_newer_version_is_fine():
    check_rollback("user-demo-1", seen_version=5, attempted_version=6)  # must not raise


def test_first_ever_policy_has_nothing_to_roll_back_from():
    check_rollback("user-demo-1", seen_version=None, attempted_version=1)  # must not raise


def test_decision_is_deterministic_same_inputs_same_output(policy):
    """The core claim in engine.py's own docstring: no hidden state, no
    randomness. Run it five times, must get exactly the same answer."""
    tx = _tx(amount=Decimal("60000"))
    results = {evaluate(tx, _risk("LOW"), KNOWN_HISTORY, policy).decision for _ in range(5)}
    assert results == {Decision.STEP_UP}


def test_unknown_condition_key_fails_closed():
    """A malformed/tampered policy should error, not silently ignore the
    unrecognised condition and evaluate as if it weren't there — the
    failure-mode table says policy corrupted -> deny, and a policy engine that
    quietly no-ops on garbage input is the opposite of that."""
    bad_policy = {
        "version": 1,
        "subject": "user-demo-1",
        "rules": [{"name": "bogus", "condition": {"NOT_A_REAL_PRIMITIVE": True}, "action": "DENY"}],
    }
    with pytest.raises(ValueError):
        evaluate(_tx(), _risk("LOW"), KNOWN_HISTORY, bad_policy)
