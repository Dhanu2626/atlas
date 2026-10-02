"""An independent, held-out evaluation of the per-subject model (2026-09-22).

The first evaluation (scripts/evaluate_ml.py, 2026-09-18) scored ordinary
transactions against the six anomalies the research planted -- produced by the
same synth.py module that generates the training history. This adds a stricter
design, all synthetic still, with the separation stated explicitly:

  TRAIN       each persona's 200-transaction history (the model's only input);
  VALIDATION  ordinary transactions and generated anomalies from one seed range;
  TEST        the same, from a DISJOINT seed range -- the headline figures.

and three independences the first evaluation lacked:

  * held-out PERSONAS: home city, payees, amount band and device differ from the
    demo persona, so the result is not about one hand-tuned profile;
  * an INDEPENDENT anomaly generator (this module), written without reference to
    synth.planted_anomalies() and never used to build or tune the model;
  * HARD NEGATIVES: legitimate-but-larger payments to known payees, the easy
    source of false positives a planted-case test never exercises.

NO LOOK-AHEAD (2026-09-25). Every case is scored against history that is entirely
EARLIER than it -- the only history a live decision can have. Until 2026-09-25 each
case kept the date its generator gave it (6 February for the ordinary ones) and was
scored against a training history running 1 January to 29 June, so "is this payee
new?", the amount baseline and the 24-hour count all saw up to five months of the
case's own future. place_after_history() now moves each case, and any burst that
goes with it, to the day after the history ends, keeping its time of day (the hour
is a feature) and every interval inside a burst. tests/test_ml_evaluation_no_lookahead.py
pins it. The figures published before that date were measured with the look-ahead.

Nothing is tuned on the validation or test data: the risk bands are fixed by
design at the 90th (MEDIUM) and 98th (HIGH) percentiles of each persona's own
training scores. Validation is reported beside test to show the figures are
stable, not to pick anything.

THE SEPARATE BURST SIGNAL (2026-09-25). beyond_observed_range
(atlas_service/ml/range_signal.py) is measured here BESIDE the forest, never merged
into its figures: the forest's own metrics below are unchanged and its burst recall
is still 0.0. The signal's one parameter, the multiplier, is chosen by
calibrate_range_multiplier() from the VALIDATION cases alone, under a rule fixed
before it was run (RANGE_GRID, RANGE_MAX_FPR); the test split is then scored with
that multiplier and reported. Both are synthetic.

WHAT THIS STILL DOES NOT SHOW: fraud detection. Every transaction is generated,
and the anomaly families are this module's own specification of "unusual" --
the figures measure how well the model separates those specified deviations
from a persona's generated normal, nothing about real payments or real fraud.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from atlas_service.ml import range_signal
from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.synth import Persona, generate_normal_history
from contracts import Transaction

#: Held-out personas: deliberately unlike the demo persona.
HELD_OUT_PERSONAS = (
    Persona(subject="holdout-mumbai", home_location="Mumbai,IN",
            devices=("dev-mum-phone",), known_beneficiaries=("ben-sister", "ben-dairy", "ben-gym"),
            known_merchant_categories=("bigbasket", "uber", "netflix", "water"),
            normal_amount_low=Decimal("200"), normal_amount_high=Decimal("1800")),
    Persona(subject="holdout-delhi", home_location="Delhi,IN",
            devices=("dev-del-phone", "dev-del-tablet"),
            known_beneficiaries=("ben-father", "ben-tutor", "ben-chemist", "ben-driver"),
            known_merchant_categories=("myntra", "swiggy", "airtel", "gas"),
            normal_amount_low=Decimal("1000"), normal_amount_high=Decimal("6000")),
    Persona(subject="holdout-pune", home_location="Pune,IN",
            devices=("dev-pune-01",), known_beneficiaries=("ben-roommate", "ben-canteen"),
            known_merchant_categories=("zepto", "bookmyshow", "electricity"),
            normal_amount_low=Decimal("100"), normal_amount_high=Decimal("900")),
    Persona(subject="holdout-kochi", home_location="Kochi,IN",
            devices=("dev-kochi-phone",), known_beneficiaries=("ben-wife", "ben-school", "ben-temple"),
            known_merchant_categories=("reliance", "ola", "broadband", "insurance"),
            normal_amount_low=Decimal("800"), normal_amount_high=Decimal("4500")),
)

TRAIN_SEEDS = {p.subject: 1_000 + i for i, p in enumerate(HELD_OUT_PERSONAS)}
VALIDATION_SEEDS = range(20_000, 20_060)
TEST_SEEDS = range(40_000, 40_060)
HOLDOUT_INDEX = 1           # index 0 of a fresh history is the recurring rent payment

FAMILIES = ("amount_spike", "new_payee_large", "foreign_new_device", "odd_hour_new_merchant",
            "burst", "combined_mild")


@dataclass(frozen=True)
class Case:
    split: str
    persona: str
    label: int                 # 1 = generated anomaly, 0 = ordinary or hard negative
    kind: str                  # family, "ordinary" or "hard_negative"
    transaction: Transaction
    extra_history: tuple = ()  # transactions the target is scored after (the burst family)


def _ordinary(persona: Persona, seed: int) -> Transaction:
    tx = generate_normal_history(persona, n=5, seed=seed)[HOLDOUT_INDEX]
    return tx.model_copy(update={"transaction_id": f"{persona.subject}-ordinary-{seed}"})


def _anomaly(persona: Persona, family: str, seed: int) -> tuple[Transaction, tuple]:
    rng = random.Random(seed)
    base = _ordinary(persona, seed)
    when = datetime.fromisoformat(base.timestamp)
    high = persona.normal_amount_high
    extra: tuple = ()
    if family == "amount_spike":
        tx = replace_tx(base, amount=_money(high * Decimal(str(rng.uniform(8, 40)))))
    elif family == "new_payee_large":
        tx = replace_tx(base, beneficiary=f"ben-unseen-{seed}",
                        amount=_money(high * Decimal(str(rng.uniform(4, 15)))))
    elif family == "foreign_new_device":
        tx = replace_tx(base, location=rng.choice(("Lagos,NG", "Minsk,BY", "Manila,PH")),
                        device_id=f"dev-unknown-{seed}", is_international=True, currency="USD",
                        amount=_money(high * Decimal(str(rng.uniform(1, 3)))))
    elif family == "odd_hour_new_merchant":
        night = when.replace(hour=rng.randint(21, 23), minute=rng.randint(0, 59))
        tx = replace_tx(base, timestamp=night.isoformat(),
                        merchant_category=rng.choice(("crypto-exchange", "gift-cards", "betting")),
                        amount=_money(high * Decimal(str(rng.uniform(2, 6)))))
    elif family == "burst":
        count = rng.randint(15, 30)
        extra = tuple(replace_tx(base, transaction_id=f"{base.transaction_id}-burst-{k}",
                                 timestamp=(when - timedelta(minutes=4 * (k + 1))).isoformat())
                      for k in range(count))
        tx = base
    elif family == "combined_mild":
        tx = replace_tx(base, beneficiary=f"ben-unseen-{seed}", device_id=f"dev-unknown-{seed}",
                        amount=_money(high * Decimal(str(rng.uniform(1.5, 3)))))
    else:
        raise ValueError(family)
    return replace_tx(tx, transaction_id=f"{persona.subject}-{family}-{seed}"), extra


def _hard_negative(persona: Persona, seed: int) -> Transaction:
    """Legitimate but a little larger than usual, to a known payee."""
    rng = random.Random(seed)
    base = _ordinary(persona, seed)
    return replace_tx(base, amount=_money(persona.normal_amount_high * Decimal(str(rng.uniform(1.1, 1.6)))),
                      transaction_id=f"{persona.subject}-hardneg-{seed}")


def replace_tx(tx: Transaction, **changes) -> Transaction:
    return tx.model_copy(update=changes)


def _money(value: Decimal) -> Decimal:
    return value.quantize(Decimal("0.01"))


def _ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def place_after_history(history: list[Transaction], transaction: Transaction,
                        extra: tuple = ()) -> tuple[Transaction, tuple]:
    """Moves `transaction` -- and `extra`, the payments scored just before it --
    forward by whole days so that everything is later than the last row of
    `history`. Whole days keep the hour of day and every gap inside a burst
    exactly as generated; nothing else about the case changes."""
    last = max(_ts(t.timestamp) for t in history)
    earliest = min([_ts(transaction.timestamp)] + [_ts(t.timestamp) for t in extra])
    days = max(0, (last - earliest).days + 1)
    while earliest + timedelta(days=days) <= last:
        days += 1
    shift = timedelta(days=days)

    def moved(t: Transaction) -> Transaction:
        return t.model_copy(update={"timestamp": (_ts(t.timestamp) + shift).isoformat()})

    return moved(transaction), tuple(moved(t) for t in extra)


def scoring_inputs(case: "Case", history: list[Transaction]) -> tuple[Transaction, list[Transaction]]:
    """What a held-out case is scored WITH: the case placed after the persona's
    history, and that history plus the case's own preceding payments."""
    tx, extra = place_after_history(history, case.transaction, case.extra_history)
    return tx, history + list(extra)


def build_cases() -> list[Case]:
    cases = []
    for persona in HELD_OUT_PERSONAS:
        for split, seeds in (("validation", VALIDATION_SEEDS), ("test", TEST_SEEDS)):
            for i, seed in enumerate(seeds):
                cases.append(Case(split, persona.subject, 0, "ordinary", _ordinary(persona, seed)))
                if i % 3 == 0:
                    cases.append(Case(split, persona.subject, 0, "hard_negative",
                                      _hard_negative(persona, seed + 500)))
                family = FAMILIES[i % len(FAMILIES)]
                tx, extra = _anomaly(persona, family, seed + 900)
                cases.append(Case(split, persona.subject, 1, family, tx, extra))
    return cases


def train_models() -> dict[str, tuple[PersonaAnomalyModel, list[Transaction]]]:
    models = {}
    for persona in HELD_OUT_PERSONAS:
        history = generate_normal_history(persona, n=200, seed=TRAIN_SEEDS[persona.subject])
        models[persona.subject] = (PersonaAnomalyModel().fit(history), history)
    return models


#: The multipliers calibrate_range_multiplier() may choose from, and its rule: the
#: LARGEST multiplier whose validation false-positive rate (over ordinary and
#: hard-negative cases) is at most RANGE_MAX_FPR, among those reaching the best
#: validation burst recall any such multiplier reaches. Largest, because among
#: equally good choices the one that fires least readily is the conservative one.
#: Fixed 2026-09-25 before the calibration was first run.
RANGE_GRID = (1.5, 2.0, 2.5, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0)
RANGE_MAX_FPR = 0.01


def range_measurements(cases, models) -> list[tuple["Case", int, int | None]]:
    """(case, current_24h, observed_max_24h) for each case, look-ahead-safe."""
    out = []
    for case in cases:
        _, history = models[case.persona]
        tx, scored_against = scoring_inputs(case, history)
        current, observed = range_signal.measure(tx, scored_against)
        out.append((case, current, observed))
    return out


def _range_metrics(measured, multiplier: float) -> dict:
    fired = [(c, range_signal.fires(cur, obs, multiplier)) for c, cur, obs in measured]
    negatives = [f for c, f in fired if c.label == 0]
    bursts = [f for c, f in fired if c.kind == "burst"]
    others = [f for c, f in fired if c.label == 1 and c.kind != "burst"]
    return {
        "burst_recall": _r(sum(bursts) / len(bursts)) if bursts else None,
        "bursts": len(bursts),
        "false_positive_rate": _r(sum(negatives) / len(negatives)) if negatives else None,
        "fired_on_negatives": sum(negatives), "negatives": len(negatives),
        "fired_on_other_anomaly_families": sum(others), "other_anomalies": len(others),
    }


def calibrate_range_multiplier(validation_cases, models) -> tuple[float, list[dict]]:
    """Chooses the multiplier from VALIDATION cases only. Refuses any other split,
    so a caller cannot hand it test cases by mistake."""
    splits = {c.split for c in validation_cases}
    if splits != {"validation"}:
        raise ValueError(f"calibration takes validation cases only, got {sorted(splits)}")
    measured = range_measurements(validation_cases, models)
    table = [{"multiplier": k, **_range_metrics(measured, k)} for k in RANGE_GRID]
    eligible = [row for row in table if row["false_positive_rate"] <= RANGE_MAX_FPR]
    if not eligible:
        raise ValueError("no multiplier meets the false-positive cap on validation")
    best = max(row["burst_recall"] for row in eligible)
    chosen = max(row["multiplier"] for row in eligible if row["burst_recall"] == best)
    return chosen, table


def _binary(labels, flags) -> dict:
    tp = sum(1 for y, f in zip(labels, flags) if y and f)
    fp = sum(1 for y, f in zip(labels, flags) if not y and f)
    fn = sum(1 for y, f in zip(labels, flags) if y and not f)
    tn = sum(1 for y, f in zip(labels, flags) if not y and not f)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    return {"confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "precision": _r(precision), "recall": _r(recall), "f1": _r(f1),
            "false_positive_rate": _r(fp / (fp + tn) if fp + tn else None)}


def _r(value):
    return None if value is None else round(value, 4)


def evaluate_held_out() -> dict:
    from sklearn.metrics import average_precision_score, roc_auc_score

    models = train_models()
    cases = build_cases()
    rows = []
    for case in cases:
        model, history = models[case.persona]
        tx, scored_against = scoring_inputs(case, history)
        evidence = model.score(tx, scored_against)
        rows.append((case, evidence.anomaly_score, evidence.risk_band))

    result = {}
    for split in ("validation", "test"):
        subset = [r for r in rows if r[0].split == split]
        labels = [r[0].label for r in subset]
        scores = [r[1] for r in subset]
        result[split] = {
            "cases": len(subset), "anomalies": sum(labels), "negatives": len(labels) - sum(labels),
            "roc_auc": _r(roc_auc_score(labels, scores)),
            "average_precision": _r(average_precision_score(labels, scores)),
            "at_medium_and_above": _binary(labels, [r[2] in ("MEDIUM", "HIGH") for r in subset]),
            "at_high_only": _binary(labels, [r[2] == "HIGH" for r in subset]),
            "recall_by_family": {
                family: _r(sum(1 for r in subset if r[0].kind == family and r[2] in ("MEDIUM", "HIGH"))
                           / max(1, sum(1 for r in subset if r[0].kind == family)))
                for family in FAMILIES},
            "hard_negatives_flagged": sum(1 for r in subset
                                          if r[0].kind == "hard_negative" and r[2] in ("MEDIUM", "HIGH")),
            "hard_negatives": sum(1 for r in subset if r[0].kind == "hard_negative"),
        }
    # The separate burst signal: calibrated on validation only, then applied to test.
    multiplier, table = calibrate_range_multiplier(
        [c for c in cases if c.split == "validation"], models)
    signal = {
        "name": "beyond_observed_range",
        "what": "separate evidence signal beside the Isolation Forest; it does not change "
                "risk_band, and a policy acts on it only through a BEYOND_OBSERVED_RANGE rule",
        "selected_multiplier": multiplier,
        "shipped_multiplier": range_signal.RANGE_MULTIPLIER,
        "selection_rule": f"largest multiplier in {list(RANGE_GRID)} with validation "
                          f"false-positive rate <= {RANGE_MAX_FPR} among those with the best "
                          f"validation burst recall; test split never used",
        "validation_table": table,
    }
    for split in ("validation", "test"):
        subset = [c for c in cases if c.split == split]
        signal[split] = _range_metrics(range_measurements(subset, models), multiplier)
        by_case = {id(c): f for c, f in (
            (c, range_signal.fires(cur, obs, multiplier))
            for c, cur, obs in range_measurements(subset, models))}
        split_rows = [r for r in rows if r[0].split == split]
        labels = [r[0].label for r in split_rows]
        either = [(r[2] in ("MEDIUM", "HIGH")) or by_case[id(r[0])] for r in split_rows]
        signal[split]["forest_medium_or_signal"] = _binary(labels, either)
    result["beyond_observed_range"] = signal

    result["design"] = {
        "personas": [p.subject for p in HELD_OUT_PERSONAS],
        "training_history_per_persona": 200,
        "splits": "validation seeds 20000-20059, test seeds 40000-40059, disjoint from each other "
                  "and from the training seeds 1000-1003",
        "thresholds": "fixed by design: MEDIUM = 90th, HIGH = 98th percentile of the persona's own "
                      "training scores; nothing tuned on validation or test",
        "anomaly_generator": "atlas_service/ml/evaluation.py, independent of synth.planted_anomalies",
        "no_look_ahead": "every case is scored against history dated strictly before it "
                         "(place_after_history, 2026-09-25)",
    }
    return result
