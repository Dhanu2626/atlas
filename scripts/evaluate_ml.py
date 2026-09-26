"""Measures what the ML evidence layer actually does: precision, recall, latency.

    python scripts/evaluate_ml.py            # human-readable
    python scripts/evaluate_ml.py --json     # the same numbers as JSON

Step 9's measurement set asked for ML precision and recall, and until
2026-09-18 the honest answer was "never measured". This is that measurement --
and the first thing to say about it is what it is NOT.

WHAT THIS MEASURES. Whether the per-subject Isolation Forest separates a
persona's ordinary transactions from deliberately planted deviations, at the
two band thresholds the service uses (MEDIUM at the 90th percentile of training
scores, HIGH at the 98th). Both classes come from atlas_service/ml/synth.py --
the same generator that produced the training history. Ordinary transactions
are unseen draws the model was not fitted on; the planted anomalies are the
six from the original research.

WHAT IT DOES NOT MEASURE. Fraud. There is no fraud in this data and no real
behaviour anywhere in ATLAS: a number here says the model can tell one
synthetic generator's normal from that same generator's deliberate outliers,
which is a far weaker claim than detection. One planted case is labelled
"legitimate_large_purchase" precisely because flagging it is correct anomaly
behaviour and wrong fraud behaviour, so the figures are reported twice: with it
counted as an anomaly, and with it excluded.

HELD-OUT EVALUATION (2026-09-22). A second, stricter measurement runs beside
the planted-case one: four held-out personas unlike the demo persona, disjoint
validation and test seed ranges, anomalies from an independent generator
(atlas_service/ml/evaluation.py) and hard negatives, with ROC-AUC and average
precision over the continuous score as well as confusion matrices at the bands.
Still synthetic; still not fraud detection.

Determinism: fixed seeds throughout, so the precision and recall figures repeat
exactly. Latency is wall-clock on the machine that runs it and does not.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT))

from atlas_service.ml.evaluation import evaluate_held_out, place_after_history  # noqa: E402
from atlas_service.ml.model import PersonaAnomalyModel  # noqa: E402
from atlas_service.ml.synth import (  # noqa: E402
    Persona,
    generate_normal_history,
    planted_anomalies,
)

#: Personas to fit, one model each. More seeds, more evaluation points.
TRAINING_SEEDS = (42, 7, 13, 99, 2026)
#: Unseen ordinary transactions per persona, each from its own seed.
ORDINARY_PER_PERSONA = 40
#: Index 1 of a fresh history: index 0 is the recurring rent payment, which is
#: legitimately large and would be an unfair "ordinary" example.
HOLDOUT_INDEX = 1
#: The planted case that is unusual on purpose but not misbehaviour.
LEGITIMATE = "legitimate_large_purchase"
#: The held-out evaluation takes about 20 s; a test that checks only the planted
#: figures can switch it off (it has its own tests in tests/test_ml_evaluation.py).
INCLUDE_HELD_OUT = True


def _counts(flags: list[bool]) -> int:
    return sum(1 for f in flags if f)


def _score_set(seed: int) -> tuple[list[bool], dict[str, str]]:
    """Returns (ordinary flagged?, planted case -> band) for one persona."""
    persona = Persona(subject=f"user-eval-{seed}")
    history = generate_normal_history(persona, n=200, seed=seed)
    model = PersonaAnomalyModel().fit(history)

    ordinary_bands = []
    for offset in range(ORDINARY_PER_PERSONA):
        unseen = generate_normal_history(persona, n=5, seed=100_000 + seed * 1000 + offset)
        # No look-ahead (2026-09-25): the ordinary case is dated in early January by
        # its generator, inside the Jan-Jun training history; it is moved to after
        # that history so it is never scored against its own future.
        ordinary, _ = place_after_history(history, unseen[HOLDOUT_INDEX])
        ordinary_bands.append(model.score(ordinary, history).risk_band)

    planted = {}
    for name, transactions in planted_anomalies(persona).items():
        target, preceding = place_after_history(history, transactions[-1], tuple(transactions[:-1]))
        planted[name] = model.score(target, history + list(preceding)).risk_band

    return ordinary_bands, planted


def _metrics(ordinary: list[str], planted: dict[str, str], *, flagged_bands: tuple[str, ...],
             include_legitimate: bool) -> dict:
    positives = {k: v for k, v in planted.items() if include_legitimate or k != LEGITIMATE}
    negatives = list(ordinary) + ([] if include_legitimate else
                                  [planted[LEGITIMATE]] * planted.__contains__(LEGITIMATE))
    tp = _counts([band in flagged_bands for band in positives.values()])
    fn = len(positives) - tp
    fp = _counts([band in flagged_bands for band in negatives])
    tn = len(negatives) - fp
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)
          if precision and recall and (precision + recall) else None)
    return {
        "true_positives": tp, "false_negatives": fn,
        "false_positives": fp, "true_negatives": tn,
        "precision": None if precision is None else round(precision, 4),
        "recall": None if recall is None else round(recall, 4),
        "f1": None if f1 is None else round(f1, 4),
        "false_positive_rate": round(fp / len(negatives), 4) if negatives else None,
    }


def _latency() -> dict:
    """Warm timings for the two operations a request pays for."""
    persona = Persona(subject="user-latency")
    history = generate_normal_history(persona, n=200, seed=42)
    model = PersonaAnomalyModel().fit(history)          # warm-up, discarded
    probe = generate_normal_history(persona, n=5, seed=555)[HOLDOUT_INDEX]
    model.score(probe, history)                          # warm-up, discarded

    fits = []
    for _ in range(5):
        start = time.perf_counter()
        PersonaAnomalyModel().fit(history)
        fits.append((time.perf_counter() - start) * 1000)

    scores = []
    for _ in range(50):
        start = time.perf_counter()
        model.score(probe, history)
        scores.append((time.perf_counter() - start) * 1000)

    return {
        "fit_ms_median": round(statistics.median(fits), 1),
        "fit_ms_max": round(max(fits), 1),
        "score_ms_median": round(statistics.median(scores), 2),
        "score_ms_p95": round(sorted(scores)[int(len(scores) * 0.95) - 1], 2),
        "score_ms_max": round(max(scores), 2),
        "history_size": len(history),
        "note": "wall clock on the machine that ran this; fitting is the explicit training step (scripts/train_models.py), scoring is what each request does",
    }


def evaluate() -> dict:
    ordinary: list[str] = []
    planted_bands: dict[str, list[str]] = {}
    for seed in TRAINING_SEEDS:
        persona_ordinary, persona_planted = _score_set(seed)
        ordinary.extend(persona_ordinary)
        for name, band in persona_planted.items():
            planted_bands.setdefault(name, []).append(band)

    flat_planted = {f"{name}#{i}": band
                    for name, bands in planted_bands.items()
                    for i, band in enumerate(bands)}
    flat_planted_names = {k: k.split("#")[0] for k in flat_planted}

    def subset(include_legitimate: bool, flagged: tuple[str, ...]) -> dict:
        planted = {k: v for k, v in flat_planted.items()
                   if include_legitimate or flat_planted_names[k] != LEGITIMATE}
        negatives = list(ordinary)
        if not include_legitimate:
            negatives += [v for k, v in flat_planted.items()
                          if flat_planted_names[k] == LEGITIMATE]
        tp = sum(1 for band in planted.values() if band in flagged)
        fp = sum(1 for band in negatives if band in flagged)
        fn, tn = len(planted) - tp, len(negatives) - fp
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
        return {
            "flagged_as": "MEDIUM or HIGH" if len(flagged) == 2 else "HIGH only",
            "planted": len(planted), "ordinary": len(negatives),
            "true_positives": tp, "false_negatives": fn,
            "false_positives": fp, "true_negatives": tn,
            "precision": None if precision is None else round(precision, 4),
            "recall": None if recall is None else round(recall, 4),
            "f1": None if f1 is None else round(f1, 4),
            "false_positive_rate": round(fp / len(negatives), 4) if negatives else None,
        }

    return {
        "measured_by": "scripts/evaluate_ml.py",
        "data": "synthetic, from atlas_service/ml/synth.py -- the same generator as the "
                "training history; no real behaviour and no fraud labels",
        "personas": len(TRAINING_SEEDS),
        "training_history_per_persona": 200,
        "at_medium_and_above": subset(True, ("MEDIUM", "HIGH")),
        "at_high_only": subset(True, ("HIGH",)),
        "at_medium_and_above_excluding_the_legitimate_large_purchase":
            subset(False, ("MEDIUM", "HIGH")),
        "per_planted_case": {name: sorted(set(bands)) for name, bands in sorted(planted_bands.items())},
        "held_out": evaluate_held_out() if INCLUDE_HELD_OUT else {"method": "not run"},
        "latency": _latency(),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="print JSON instead of prose")
    args = ap.parse_args()

    result = evaluate()
    if args.json:
        print(json.dumps(result, indent=2))
        return 0

    print(f"ML evidence, measured by {result['measured_by']}")
    print(f"  data: {result['data']}")
    print(f"  {result['personas']} personas, {result['training_history_per_persona']} "
          f"training transactions each")
    for key in ("at_medium_and_above", "at_high_only",
                "at_medium_and_above_excluding_the_legitimate_large_purchase"):
        m = result[key]
        print(f"\n  {key.replace('_', ' ')} (flagged = {m['flagged_as']})")
        print(f"    planted {m['planted']}, ordinary {m['ordinary']}")
        print(f"    precision {m['precision']}  recall {m['recall']}  F1 {m['f1']}  "
              f"false-positive rate {m['false_positive_rate']}")
    print("\n  per planted case:")
    for name, bands in result["per_planted_case"].items():
        print(f"    {name:34} {', '.join(bands)}")
    held = result["held_out"]
    if "test" not in held:
        return 0
    print()
    print("  held-out evaluation (independent generator, disjoint seeds; synthetic, not fraud):")
    for split in ("validation", "test"):
        s = held[split]
        m = s["at_medium_and_above"]
        print(f"    {split:10} {s['cases']} cases ({s['anomalies']} anomalies): ROC-AUC {s['roc_auc']}, "
              f"avg precision {s['average_precision']}; at MEDIUM+ precision {m['precision']} "
              f"recall {m['recall']} FPR {m['false_positive_rate']} {m['confusion_matrix']}")
    print("    test recall by family (the Isolation Forest alone):",
          ", ".join(f"{k} {v}" for k, v in held["test"]["recall_by_family"].items()))
    sig = held.get("beyond_observed_range")
    if sig:
        print(f"    separate beyond_observed_range signal (not the forest; evidence only), multiplier "
              f"{sig['selected_multiplier']} chosen on validation only:")
        for split in ("validation", "test"):
            s = sig[split]
            print(f"      {split:10} bursts flagged {s['burst_recall']} of {s['bursts']}; fired on "
                  f"{s['fired_on_negatives']} of {s['negatives']} ordinary/hard-negative cases")
    lat = result["latency"]
    print(f"\n  latency: score median {lat['score_ms_median']} ms, p95 {lat['score_ms_p95']} ms; "
          f"fit median {lat['fit_ms_median']} ms ({lat['history_size']} transactions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
