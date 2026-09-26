"""Validates the ML model against the exact planted anomalies from the original
research (ledger/SYNTHESIS.md #4), not generic substitutes.

Per ARCHITECTURE.md principle 1, this only tests that ML correctly produces
behavioral evidence (RiskEvidence). It does NOT test ALLOW/DENY/STEP_UP — that's
the policy engine's job (step 2, not built yet). In particular, the "legitimate
large purchase" case is expected to score as anomalous (that's the correct, honest
ML behavior) — the fact that it should NOT simply be denied is a policy-layer
concern, deliberately not asserted here.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import numpy as np
import pytest

from atlas_service.ml.features import (
    FEATURE_NAMES,
    _REASON_TEXT,
    _REASON_TEXT_BELOW,
    explain,
    extract_features,
    extract_training_matrix,
)
from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.synth import Persona, generate_normal_history, planted_anomalies
from contracts import Transaction


def _fitted_model_and_history():
    persona = Persona(subject="user-test-1")
    history = generate_normal_history(persona, n=200, seed=42)
    model = PersonaAnomalyModel().fit(history)
    return model, history, persona


def test_normal_holdout_transactions_score_low():
    model, history, persona = _fitted_model_and_history()
    # a fresh, unseen everyday-sized transaction (not one used in training).
    # Index 0 deliberately avoided: generate_normal_history's own recurring-rent
    # rule (i % 30 == 0) makes index 0 a Rs 15,000 rent payment, not a typical
    # small purchase — see SYNTHESIS.md-style note in model.py about the amount
    # baseline being global-per-subject, not per-beneficiary: a legitimately
    # recurring large payment can read as elevated by amount alone in this V1,
    # which is a documented simplification, not something to test around by
    # accident. Index 1 is guaranteed to hit neither the rent nor travel branch.
    holdout = generate_normal_history(persona, n=5, seed=999)[1]
    evidence = model.score(holdout, history)
    assert evidence.risk_band == "LOW", (
        f"expected a normal transaction to score LOW, got {evidence.risk_band} "
        f"(score={evidence.anomaly_score:.3f})"
    )


def _anomaly_band(model, history, name):
    tx_list = planted_anomalies(Persona(subject="user-test-1"))[name]
    # for the velocity burst, score the LAST transaction — that's the one whose
    # own 24h window contains the full spike
    tx = tx_list[-1]
    local_history = history + tx_list[:-1] if len(tx_list) > 1 else history
    return model.score(tx, local_history)


def test_time_amount_anomaly_flagged_high():
    model, history, _ = _fitted_model_and_history()
    evidence = _anomaly_band(model, history, "time_amount_anomaly")
    assert evidence.risk_band in ("MEDIUM", "HIGH"), (
        f"3:12 AM / Rs 70,000 (original pre-Day-1 example) should not score LOW, "
        f"got {evidence.risk_band} (score={evidence.anomaly_score:.3f})"
    )


def test_velocity_burst_flagged():
    model, history, _ = _fitted_model_and_history()
    evidence = _anomaly_band(model, history, "velocity_burst")
    assert evidence.risk_band in ("MEDIUM", "HIGH"), (
        f"45 transactions in ~90 seconds should not score LOW, got "
        f"{evidence.risk_band} (score={evidence.anomaly_score:.3f})"
    )
    assert "frequency" in " ".join(evidence.reasons) or evidence.risk_band == "HIGH"


def test_unknown_merchant_flagged():
    model, history, _ = _fitted_model_and_history()
    evidence = _anomaly_band(model, history, "unknown_merchant")
    assert evidence.risk_band in ("MEDIUM", "HIGH"), (
        f"unknown cryptocurrency exchange should not score LOW, got "
        f"{evidence.risk_band} (score={evidence.anomaly_score:.3f})"
    )


def test_device_location_anomaly_flagged_high():
    model, history, _ = _fitted_model_and_history()
    evidence = _anomaly_band(model, history, "device_location_anomaly")
    assert evidence.risk_band in ("MEDIUM", "HIGH"), (
        f"unknown device + new country (no travel mode declared) should not score "
        f"LOW, got {evidence.risk_band} (score={evidence.anomaly_score:.3f})"
    )


def test_legitimate_large_purchase_is_anomalous_not_asserted_as_fraud():
    """Anomaly != fraud (Day 7's own words). This transaction SHOULD register as
    unusual — that's ML doing its job correctly. Whether ATLAS should DENY or
    STEP-UP it is a policy-engine decision, out of scope here on purpose."""
    model, history, _ = _fitted_model_and_history()
    evidence = _anomaly_band(model, history, "legitimate_large_purchase")
    assert evidence.risk_band in ("MEDIUM", "HIGH")


def test_travel_mode_reduces_anomaly_vs_undeclared_international():
    """The actual point of declared_travel_mode existing at all: an otherwise
    similar international/new-location/new-beneficiary transaction should read as
    LESS anomalous when travel mode is declared, because the model has seen that
    combination as part of this persona's normal pattern during training."""
    model, history, _ = _fitted_model_and_history()
    with_travel_mode = _anomaly_band(model, history, "travel_mode_international")
    without_travel_mode = _anomaly_band(model, history, "device_location_anomaly")
    assert with_travel_mode.anomaly_score < without_travel_mode.anomaly_score, (
        f"travel_mode_international scored {with_travel_mode.anomaly_score:.3f}, "
        f"device_location_anomaly (no travel mode) scored "
        f"{without_travel_mode.anomaly_score:.3f} — travel mode should reduce "
        f"anomaly, not leave it unchanged or raise it"
    )


def test_reasons_are_explainable_not_a_bare_number():
    """Day 7's explicit rule: 'Risk = 0.37' is not an acceptable answer to 'why'."""
    model, history, _ = _fitted_model_and_history()
    evidence = _anomaly_band(model, history, "time_amount_anomaly")
    assert len(evidence.reasons) > 0
    for reason in evidence.reasons:
        assert not reason.replace(".", "").isdigit()  # not just a raw number


def test_a_value_below_the_usual_level_is_never_described_as_high():
    """Found on the Step 9 dashboard, 2026-09-17: an everyday Rs 1,500 payment,
    the only transaction in its 24 hours, was explained as "unusually high
    transaction frequency". Its count was 1 against a usual 1.67 -- lower, not
    higher. explain() ranks features by the size of the deviation, so the words
    must follow its direction. The score and the band do not depend on this:
    explain() only words evidence that has already been scored."""
    model, history, _ = _fitted_model_and_history()
    quiet_day = Transaction(
        transaction_id="t-quiet-day", subject="user-test-1", amount="1500.00", currency="INR",
        beneficiary="ben-friend", location="Hyderabad,IN", device_id="device-primary-01",
        merchant_category="transfer", authentication_method="pin",
        is_new_beneficiary=False, is_new_device=False, is_international=False,
        declared_travel_mode=False, is_emergency_request=False,
        # 10:00 UTC, mid-window for this persona, so the hour is not one of the
        # top three deviations and the frequency wording is what gets checked.
        # Written in UTC since D2 (2026-09-18) made UTC the canonical basis.
        timestamp="2026-09-17T10:00:00+00:00",
    )

    evidence = model.score(quiet_day, history)

    assert "unusually high transaction frequency" not in evidence.reasons
    assert "fewer transactions than usual in the last 24 hours" in evidence.reasons

    burst = _anomaly_band(model, history, "velocity_burst")
    assert "fewer transactions than usual in the last 24 hours" not in burst.reasons


def test_every_reason_is_worded_for_the_direction_it_actually_went():
    mean = np.full(len(FEATURE_NAMES), 5.0)
    std = np.ones(len(FEATURE_NAMES))
    for i, name in enumerate(FEATURE_NAMES):
        above, below = mean.copy(), mean.copy()
        above[i], below[i] = 9.0, 1.0

        (worded_above,) = explain(above, mean, std, top_n=1)
        (worded_below,) = explain(below, mean, std, top_n=1)

        assert worded_above == _REASON_TEXT[name]
        if name == "hour_of_day":
            assert worded_below == worded_above  # "unusual" is true in both directions
        else:
            assert worded_below == _REASON_TEXT_BELOW[name], (
                f"{name}: a value below the usual level reused the wording for above"
            )


def test_the_wording_fix_changes_words_never_which_reasons_or_their_order():
    """Same features, same order, same 0.5 threshold as before the fix, checked
    against the original selection rule on random evidence."""
    rng = np.random.default_rng(7)
    to_name = {text: name for name, text in _REASON_TEXT.items()}
    to_name.update({text: name for name, text in _REASON_TEXT_BELOW.items()})
    for _ in range(300):
        mean = rng.normal(size=len(FEATURE_NAMES))
        std = rng.uniform(0.2, 2.0, size=len(FEATURE_NAMES))
        vector = rng.normal(scale=3.0, size=len(FEATURE_NAMES))
        original_rule = sorted(
            ((abs((vector[i] - mean[i]) / std[i]), name) for i, name in enumerate(FEATURE_NAMES)),
            reverse=True,
        )
        expected = [name for z, name in original_rule[:3] if z > 0.5]

        assert [to_name[text] for text in explain(vector, mean, std)] == expected


# ==========================================================================
# D2 (2026-09-18): UTC is the canonical time basis for ML features.
#
# Before this, the hour came from whatever offset the caller wrote, so one
# instant sent as +05:30 and as +00:00 produced different hours, different
# scores and sometimes different reasons -- against a model trained only on UTC
# hours. These tests pin the convention rather than the numbers it produces.
# ==========================================================================

_IST = timezone(timedelta(hours=5, minutes=30))
_INSTANT = datetime(2026, 9, 17, 23, 30, tzinfo=_IST)  # 18:00 UTC


def _probe(history, persona, when: str) -> Transaction:
    return Transaction(
        transaction_id="tz-probe", subject=persona.subject, amount="1500.00",
        currency="INR", beneficiary=history[0].beneficiary, location=persona.home_location,
        device_id=history[0].device_id, authentication_method="device_button",
        timestamp=when,
    )


@pytest.mark.parametrize("offset_hours,offset_minutes", [
    (5, 30), (0, 0), (-7, 0), (5, 45), (14, 0), (-12, 0),
], ids=["IST", "UTC", "US-Pacific", "Nepal", "Kiritimati", "Baker"])
def test_one_instant_scores_the_same_in_every_offset(offset_hours, offset_minutes):
    """The feature vector, the band and the score must depend on the instant,
    never on how the sender chose to write it."""
    model, history, persona = _fitted_model_and_history()
    tz = timezone(timedelta(hours=offset_hours, minutes=offset_minutes))
    canonical = _probe(history, persona, _INSTANT.astimezone(timezone.utc).isoformat())
    written = _probe(history, persona, _INSTANT.astimezone(tz).isoformat())

    assert np.array_equal(extract_features(written, history),
                          extract_features(canonical, history))
    assert model.score(written, history).anomaly_score == model.score(canonical, history).anomaly_score
    assert model.score(written, history).risk_band == model.score(canonical, history).risk_band


def test_the_hour_feature_is_the_utc_hour_not_the_written_one():
    model, history, persona = _fitted_model_and_history()
    hour = FEATURE_NAMES.index("hour_of_day")

    assert extract_features(_probe(history, persona, _INSTANT.isoformat()), history)[hour] == 18.0, (
        "23:30+05:30 is 18:00 UTC"
    )


def test_a_timestamp_without_an_offset_is_read_as_utc_not_local_time():
    """Otherwise the same request scores differently on two machines."""
    model, history, persona = _fitted_model_and_history()
    naive = _INSTANT.astimezone(timezone.utc).replace(tzinfo=None).isoformat()

    assert np.array_equal(
        extract_features(_probe(history, persona, naive), history),
        extract_features(_probe(history, persona, _INSTANT.isoformat()), history),
    )


def test_daylight_saving_changes_the_instant_not_the_convention():
    """Berlin noon is 11:00 UTC in winter and 10:00 UTC in summer: two different
    instants, so two different hours -- and each still scores identically to its
    own UTC spelling. A feature that silently followed the wall clock would call
    both of them 12."""
    model, history, persona = _fitted_model_and_history()
    hour = FEATURE_NAMES.index("hour_of_day")
    berlin = ZoneInfo("Europe/Berlin")
    winter = datetime(2026, 1, 15, 12, 0, tzinfo=berlin)
    summer = datetime(2026, 7, 15, 12, 0, tzinfo=berlin)

    winter_hour = extract_features(_probe(history, persona, winter.isoformat()), history)[hour]
    summer_hour = extract_features(_probe(history, persona, summer.isoformat()), history)[hour]

    assert (winter_hour, summer_hour) == (11.0, 10.0)
    for local in (winter, summer):
        assert np.array_equal(
            extract_features(_probe(history, persona, local.isoformat()), history),
            extract_features(_probe(history, persona, local.astimezone(timezone.utc).isoformat()), history),
        )


def test_training_hours_are_utc_hours_too():
    """Both halves share one basis: a history written in mixed offsets trains
    the same matrix as the same history written in UTC."""
    _, history, _ = _fitted_model_and_history()
    shifted = [
        t.model_copy(update={"timestamp": datetime.fromisoformat(t.timestamp)
                             .astimezone(_IST if i % 2 else timezone(timedelta(hours=-7)))
                             .isoformat()})
        for i, t in enumerate(history)
    ]

    assert np.array_equal(extract_training_matrix(shifted), extract_training_matrix(history))


def test_generated_history_is_spread_across_the_clock():
    """A documented weakness of the synthetic data, pinned so it cannot be
    "fixed" silently.

    Persona.normal_hour_low/high sample 8-20 UTC, but generate_normal_history's
    fractional day spacing shifts each timestamp's time of day, so the finished
    history covers every hour. hour_of_day therefore carries little signal and
    "unusual time of day for you" is weak evidence. Measured 2026-09-18:
    rounding the spacing to whole days honours the window and lifts the planted
    3am purchase to HIGH, but flags 64 of 120 unseen ordinary transactions
    instead of 0 of 120 -- a worse model. Anyone changing this must re-measure
    both numbers, not just this assertion.
    """
    _, history, _ = _fitted_model_and_history()
    hours = extract_training_matrix(history)[:, FEATURE_NAMES.index("hour_of_day")]

    assert len(set(hours)) == 24, f"expected the full clock, got {sorted(set(hours))}"
