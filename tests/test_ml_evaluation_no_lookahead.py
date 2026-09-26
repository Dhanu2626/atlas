"""No ML evaluation scores a case against its own future (2026-09-25).

Until 2026-09-25 both evaluations scored cases dated inside the training history
(6 February, or early January) against the whole Jan-Jun history, so the "new payee"
features, the amount baseline and the 24-hour count saw months of the case's future.
These tests record what every scoring call actually received and fail if any row of
the history it was given is dated at or after the transaction being scored. Under
the old code the held-out test fails on its first case.
"""

from __future__ import annotations

import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from atlas_service.ml import evaluation
from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.synth import Persona, generate_normal_history

ATLAS_ROOT = Path(__file__).resolve().parent.parent


def _ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@pytest.fixture
def recorded(monkeypatch):
    """Wraps PersonaAnomalyModel.score and keeps, for every call, the latest
    history timestamp next to the scored transaction's timestamp."""
    calls: list[tuple[str, datetime, datetime]] = []
    original = PersonaAnomalyModel.score

    def spy(self, transaction, history):
        latest = max(_ts(t.timestamp) for t in history)
        calls.append((transaction.transaction_id, _ts(transaction.timestamp), latest))
        return original(self, transaction, history)

    monkeypatch.setattr(PersonaAnomalyModel, "score", spy)
    return calls


def _future_leaks(calls):
    return [(tx_id, scored, latest) for tx_id, scored, latest in calls if latest >= scored]


def test_every_held_out_case_is_scored_only_against_earlier_history(recorded):
    evaluation.evaluate_held_out()
    assert len(recorded) == len(evaluation.build_cases())
    leaks = _future_leaks(recorded)
    assert not leaks, f"{len(leaks)} cases saw their own future, e.g. {leaks[:2]}"


def test_the_older_evaluation_scores_only_against_earlier_history(recorded, monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "atlas_evaluate_ml_lookahead", ATLAS_ROOT / "scripts" / "evaluate_ml.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ORDINARY_PER_PERSONA", 5)
    module._score_set(42)
    assert recorded, "nothing was scored"
    leaks = _future_leaks(recorded)
    assert not leaks, f"{len(leaks)} cases saw their own future, e.g. {leaks[:2]}"


def test_placement_keeps_the_hour_and_every_gap_inside_a_burst():
    history = generate_normal_history(Persona(subject="lookahead-test"), n=200, seed=7)
    target = history[40]                                  # dated inside the history
    burst = tuple(target.model_copy(update={
        "transaction_id": f"b{k}",
        "timestamp": (_ts(target.timestamp) - timedelta(minutes=4 * (k + 1))).isoformat()})
        for k in range(5))
    moved, moved_burst = evaluation.place_after_history(history, target, burst)

    last = max(_ts(t.timestamp) for t in history)
    assert min(_ts(t.timestamp) for t in (moved, *moved_burst)) > last
    assert _ts(moved.timestamp).hour == _ts(target.timestamp).hour
    assert _ts(moved.timestamp).minute == _ts(target.timestamp).minute
    for before, after in zip(burst, moved_burst):
        assert _ts(moved.timestamp) - _ts(after.timestamp) == _ts(target.timestamp) - _ts(before.timestamp)
    assert moved.model_dump(exclude={"timestamp"}) == target.model_dump(exclude={"timestamp"})


def test_a_case_already_after_the_history_is_left_where_it_is():
    history = generate_normal_history(Persona(subject="lookahead-test"), n=50, seed=3)
    later = history[-1].model_copy(update={
        "timestamp": (max(_ts(t.timestamp) for t in history) + timedelta(days=3)).isoformat()})
    moved, _ = evaluation.place_after_history(history, later)
    assert moved.timestamp == later.timestamp
