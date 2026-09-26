"""Independent benchmark of ATLAS's anomaly-detector CONFIGURATION on a public,
anonymised card-fraud dataset. Kept entirely outside ATLAS's transaction flow.

    python scripts/benchmark_public_dataset.py              # downloads once, then runs
    python scripts/benchmark_public_dataset.py --json

DATASET. "Credit Card Fraud Detection" (Machine Learning Group, ULB; Dal Pozzolo
et al.), OpenML data id 1597: 284,807 European card transactions from September
2013, 492 of them fraud (0.17%). Features V1-V28 are PCA components of the
original, undisclosed attributes; only Time and Amount are raw. Downloaded into
%LOCALAPPDATA%\\ATLAS\\datasets (outside the repository and OneDrive) and never
committed; only the aggregate metrics below are saved, to
docs/ml-public-benchmark.json.

WHAT IS BENCHMARKED -- precisely. The same detector ATLAS uses, configured the
same way: a StandardScaler fitted on training data only, then an Isolation
Forest (contamination 0.02, 200 trees, random_state 0), fitted on NORMAL
transactions only -- ATLAS's "learn what normal looks like" design -- and
evaluated with ATLAS's banding rule (MEDIUM at the 90th and HIGH at the 98th
percentile of training scores), plus ROC-AUC and average precision.

WHAT IS NOT BENCHMARKED. ATLAS itself. ATLAS's model is per customer, over ten
behavioural features (amount relative to that customer, new payee, new device,
velocity, hour, ...). This dataset has no customer identifiers and its features
are anonymised PCA components, so none of ATLAS's features can be computed from
it and it cannot pass through ATLAS's pipeline. The benchmark therefore says how
the detector configuration separates real fraud from real normal traffic in a
different feature space -- a methodological check on the algorithm and banding,
not a measurement of ATLAS's decisions, and not evidence that ATLAS detects fraud.

Splits: stratified 60/20/20 train/validation/test with a fixed seed; frauds in
the training split are discarded before fitting (the detector never sees one);
nothing is tuned on validation or test.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ATLAS_ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ATLAS_ROOT / "docs" / "ml-public-benchmark.json"
OPENML_ID = 1597
SEED = 0


def data_home() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    root = Path(base) / "ATLAS" if base else Path.home() / ".local" / "share" / "atlas"
    return root / "datasets"


def _binary(labels, flags) -> dict:
    tp = int(sum(1 for y, f in zip(labels, flags) if y and f))
    fp = int(sum(1 for y, f in zip(labels, flags) if not y and f))
    fn = int(sum(1 for y, f in zip(labels, flags) if y and not f))
    tn = int(sum(1 for y, f in zip(labels, flags) if not y and not f))
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * precision * recall / (precision + recall) if precision and recall else None
    rnd = lambda v: None if v is None else round(v, 4)  # noqa: E731
    return {"confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
            "precision": rnd(precision), "recall": rnd(recall), "f1": rnd(f1),
            "false_positive_rate": rnd(fp / (fp + tn) if fp + tn else None)}


def run_benchmark(X, y) -> dict:
    """X: numeric feature matrix (DataFrame or array); y: 0/1 labels (1 = fraud)."""
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.metrics import average_precision_score, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    X = np.asarray(X, dtype=float)
    y = np.asarray(y, dtype=int)
    X_train, X_rest, y_train, y_rest = train_test_split(X, y, test_size=0.4, stratify=y, random_state=SEED)
    X_val, X_test, y_val, y_test = train_test_split(X_rest, y_rest, test_size=0.5, stratify=y_rest,
                                                    random_state=SEED)
    normal_train = X_train[y_train == 0]          # the detector never sees a fraud
    scaler = StandardScaler().fit(normal_train)
    forest = IsolationForest(contamination=0.02, n_estimators=200, random_state=0)
    started = time.perf_counter()
    forest.fit(scaler.transform(normal_train))
    fit_seconds = time.perf_counter() - started
    train_scores = -forest.decision_function(scaler.transform(normal_train))
    p90, p98 = np.percentile(train_scores, [90, 98])

    def split_metrics(Xs, ys) -> dict:
        scores = -forest.decision_function(scaler.transform(Xs))
        return {
            "rows": int(len(ys)), "frauds": int(ys.sum()),
            "roc_auc": round(float(roc_auc_score(ys, scores)), 4),
            "average_precision": round(float(average_precision_score(ys, scores)), 4),
            "at_medium_and_above": _binary(ys, scores >= p90),
            "at_high_only": _binary(ys, scores >= p98),
        }

    return {
        "train_rows_used": int(len(normal_train)), "frauds_discarded_from_training": int(y_train.sum()),
        "fit_seconds": round(fit_seconds, 1),
        "validation": split_metrics(X_val, y_val),
        "test": split_metrics(X_test, y_test),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-save", action="store_true", help="do not write docs/ml-public-benchmark.json")
    args = ap.parse_args(argv)
    from sklearn.datasets import fetch_openml

    home = data_home()
    home.mkdir(parents=True, exist_ok=True)
    frame = fetch_openml(data_id=OPENML_ID, as_frame=True, data_home=str(home), parser="auto")
    X, y = frame.data, frame.target.astype(int)
    features = [c for c in X.columns if c != "Time"]
    result = {
        "measured_by": "scripts/benchmark_public_dataset.py",
        "measured_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "dataset": {
            "name": "Credit Card Fraud Detection (ULB Machine Learning Group; Dal Pozzolo et al.)",
            "source": f"OpenML data id {OPENML_ID}",
            "rows": int(len(y)), "frauds": int(y.sum()), "prevalence": round(float(y.mean()), 5),
            "features_used": features,
            "note": "V1-V28 are anonymised PCA components; no customer identifiers",
        },
        "benchmarked": "ATLAS's detector configuration (StandardScaler + IsolationForest, contamination "
                       "0.02, 200 trees, random_state 0, trained on normal rows only) and its banding "
                       "rule -- NOT ATLAS's per-customer model or features, which this data cannot supply",
        "splits": "stratified 60/20/20 train/validation/test, seed 0; training frauds discarded; "
                  "nothing tuned on validation or test",
        "results": run_benchmark(X[features], y),
    }
    if not args.no_save:
        OUTPUT.write_text(json.dumps(result, indent=1) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(result, indent=2))
        return 0
    r = result["results"]
    print(f"{result['dataset']['name']}: {result['dataset']['rows']} rows, {result['dataset']['frauds']} frauds")
    print(f"  benchmarked: {result['benchmarked']}")
    for split in ("validation", "test"):
        s = r[split]
        print(f"  {split:10} ROC-AUC {s['roc_auc']}  average precision {s['average_precision']}")
        for band in ("at_medium_and_above", "at_high_only"):
            m = s[band]
            print(f"    {band:20} precision {m['precision']} recall {m['recall']} F1 {m['f1']} "
                  f"FPR {m['false_positive_rate']} {m['confusion_matrix']}")
    if not args.no_save:
        print(f"  saved aggregate metrics to {OUTPUT.relative_to(ATLAS_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
