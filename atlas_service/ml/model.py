"""The per-user behavioral anomaly model.

Adapted from launderlab's `Isolation` wrapper (launderlab/src/launderlab/ml/models.py)
— same scaler-fitted-on-train-only discipline, same IsolationForest
decision_function negation (higher = more suspicious). The real difference from
launderlab's usage: launderlab trains ONE model across many accounts; ATLAS trains
one model PER SUBJECT, because there is no such thing as a global "normal
transaction" here — only a normal-for-this-person one (Day 7's Behavioral Baseline
concept). Isolation Forest was the explicit V1 choice made during Day 7's own
research ("fast, explainable, doesn't need fraud labels") — not re-litigated here.

Per ARCHITECTURE.md principle 1 ("ML is an advisor, never the judge"): this module
produces evidence only. It has no notion of ALLOW/DENY/STEP_UP — that's the policy
engine's job (step 2), which hasn't been built yet.

Known V1 simplification, documented rather than hidden: the amount baseline
(amount_zscore in features.py) is computed against a subject's *entire* history,
not per-beneficiary. A legitimately recurring large payment (rent, to the same
beneficiary every month) can therefore read as somewhat elevated by amount alone,
since it's compared against a mean pulled toward smaller day-to-day spending
rather than its own recurring pattern. A real system would likely want a
"recognized recurring payment" concept; deliberately not built here — it would be
gold-plating a research prototype's ML step rather than fixing something that
blocks the actual test scenarios in ledger/SYNTHESIS.md #4, none of which are
recurring-payment cases.
"""

from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from contracts import RiskEvidence, Transaction
from atlas_service.ml.features import FEATURE_NAMES, extract_features, extract_training_matrix, explain

RANDOM_STATE = 0


class PersonaAnomalyModel:
    """One Isolation Forest, trained on one subject's own transaction history."""

    def __init__(self, contamination: float = 0.02):
        self._scaler = StandardScaler()
        self._model = IsolationForest(
            contamination=contamination, random_state=RANDOM_STATE, n_estimators=200
        )
        self._train_mean: np.ndarray | None = None
        self._train_std: np.ndarray | None = None
        self._train_scores: np.ndarray | None = None
        self._fitted = False

    def fit(self, history: list[Transaction]) -> "PersonaAnomalyModel":
        if len(history) < 10:
            raise ValueError(
                "need at least 10 historical transactions to fit a per-subject "
                "baseline — this is a real constraint, not a placeholder: a model "
                "trained on too little history can't tell normal from anomalous"
            )
        vectors = extract_training_matrix(history)
        self._train_mean = vectors.mean(axis=0)
        self._train_std = vectors.std(axis=0)
        scaled = self._scaler.fit_transform(vectors)
        self._model.fit(scaled)
        # decision_function: higher = more normal, so negate for "suspicious"
        self._train_scores = -self._model.decision_function(scaled)
        self._fitted = True
        return self

    def score(self, transaction: Transaction, history: list[Transaction]) -> RiskEvidence:
        if not self._fitted:
            raise RuntimeError("call fit() with the subject's history before scoring")
        vector = extract_features(transaction, history)

        # Day 7 Q4's Travel Mode: "changes how behavioral evidence is interpreted...
        # but the model should stay active... rather than simply being turned off."
        # Relying on the Isolation Forest to *learn* this from a handful of travel
        # examples in training is fragile — a rare-but-legitimate pattern sitting
        # near the contamination rate gets treated as exactly the outlier the
        # forest is designed to isolate, which is backwards. Instead this is a
        # deterministic, explainable adjustment: when travel mode is declared, the
        # location/international signals are neutralized before scoring, since
        # they're expected (not anomalous) precisely because travel was declared.
        # Everything else (amount, new beneficiary/device, velocity, emergency)
        # still scores normally — travel mode doesn't blanket-suppress anomaly
        # detection, only the two signals it specifically explains.
        if transaction.declared_travel_mode:
            idx_intl = FEATURE_NAMES.index("is_international")
            idx_loc = FEATURE_NAMES.index("is_new_location")
            vector = vector.copy()
            vector[idx_intl] = self._train_mean[idx_intl]
            vector[idx_loc] = self._train_mean[idx_loc]

        scaled = self._scaler.transform(vector.reshape(1, -1))
        raw_score = float(-self._model.decision_function(scaled)[0])

        # risk band from where this score falls in the subject's OWN training
        # distribution — "more anomalous than 98% of your normal behavior" is an
        # interpretable statement; a raw isolation-forest number is not (Day 7's
        # explainability rule)
        p90, p98 = np.percentile(self._train_scores, [90, 98])
        if raw_score >= p98:
            band = "HIGH"
        elif raw_score >= p90:
            band = "MEDIUM"
        else:
            band = "LOW"

        reasons = explain(vector, self._train_mean, self._train_std)
        return RiskEvidence(anomaly_score=raw_score, risk_band=band, reasons=reasons)
