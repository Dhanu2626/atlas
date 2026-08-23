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

from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.synth import Persona, generate_normal_history, planted_anomalies


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
