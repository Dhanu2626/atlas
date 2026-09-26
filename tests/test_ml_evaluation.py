"""The ML evaluations' methodology (2026-09-22), pinned so it cannot drift.

Held-out evaluation (atlas_service/ml/evaluation.py): training, validation and
test come from disjoint seeds; the anomaly generator is independent of the
research's planted cases; nothing is tuned on validation or test; the result is
deterministic. Public benchmark (scripts/benchmark_public_dataset.py): the
detector is fitted on normal rows only, the splits are disjoint, and the saved
figures say plainly what they benchmark -- the configuration, not ATLAS.
"""

from __future__ import annotations

import inspect
import json
import sys
from pathlib import Path

import numpy as np
import pytest

from atlas_service.ml import evaluation

ATLAS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ATLAS_ROOT / "scripts"))
import benchmark_public_dataset as bench  # noqa: E402


@pytest.fixture(scope="module")
def held_out():
    return evaluation.evaluate_held_out()


def test_training_validation_and_test_seeds_are_disjoint():
    train = set(evaluation.TRAIN_SEEDS.values())
    validation, test = set(evaluation.VALIDATION_SEEDS), set(evaluation.TEST_SEEDS)
    assert not (train & validation) and not (train & test) and not (validation & test)
    ids = [c.transaction.transaction_id + c.split for c in evaluation.build_cases()]
    assert len(ids) == len(set(ids))


def test_the_anomaly_generator_is_independent_of_the_planted_research_cases():
    import ast
    tree = ast.parse(inspect.getsource(evaluation))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    names |= {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    assert "planted_anomalies" not in names, "the held-out generator uses the research's planted cases"
    assert {p.subject for p in evaluation.HELD_OUT_PERSONAS}.isdisjoint({"user-demo-1", "user-test-1"})


def test_the_cases_are_deterministic():
    first = [(c.split, c.kind, c.transaction.transaction_id, str(c.transaction.amount))
             for c in evaluation.build_cases()]
    second = [(c.split, c.kind, c.transaction.transaction_id, str(c.transaction.amount))
              for c in evaluation.build_cases()]
    assert first == second


def test_the_held_out_figures_are_internally_consistent(held_out):
    for split in ("validation", "test"):
        s = held_out[split]
        for band in ("at_medium_and_above", "at_high_only"):
            cm = s[band]["confusion_matrix"]
            assert cm["tp"] + cm["fn"] == s["anomalies"]
            assert cm["fp"] + cm["tn"] == s["negatives"]
        assert 0.0 <= s["roc_auc"] <= 1.0 and 0.0 <= s["average_precision"] <= 1.0
        assert set(s["recall_by_family"]) == set(evaluation.FAMILIES)
    assert "nothing tuned" in held_out["design"]["thresholds"]


def test_the_benchmark_trains_on_normal_rows_only_and_uses_disjoint_splits():
    rng = np.random.default_rng(0)
    normal = rng.normal(0, 1, size=(3000, 6))
    fraud = rng.normal(6, 1, size=(60, 6))
    X = np.vstack([normal, fraud])
    y = np.array([0] * len(normal) + [1] * len(fraud))
    result = bench.run_benchmark(X, y)
    assert result["frauds_discarded_from_training"] == 36          # 60% of 60, stratified
    assert result["train_rows_used"] == 1800                         # 60% of 3000
    assert result["validation"]["rows"] + result["test"]["rows"] + 1836 == len(y)
    assert result["test"]["roc_auc"] > 0.9                           # well-separated toy data


def test_the_saved_public_benchmark_states_what_it_is_and_holds_no_data():
    path = ATLAS_ROOT / "docs" / "ml-public-benchmark.json"
    saved = json.loads(path.read_text(encoding="utf-8"))
    assert "NOT ATLAS's per-customer model" in saved["benchmarked"]
    assert saved["dataset"]["source"] == "OpenML data id 1597"
    for split in ("validation", "test"):
        assert set(saved["results"][split]) >= {"roc_auc", "average_precision", "at_medium_and_above"}
    assert path.stat().st_size < 20_000, "the saved benchmark should hold aggregate metrics only"
