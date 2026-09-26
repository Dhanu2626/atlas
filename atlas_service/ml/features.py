"""Turn a raw Transaction plus a subject's own history into the numeric feature
vector the model actually sees.

Security note, directly from Day 13's own red team: the trusted layer must
re-verify transaction data itself rather than trust what the untrusted app
claims. `Transaction.is_new_beneficiary` / `is_new_device` are therefore treated
as the *client's* claim, not authoritative — this module recomputes both from the
subject's own history. Trusting the incoming flags directly would let a
compromised app simply claim `is_new_beneficiary=False` for an actually-new
beneficiary and evade detection.

Feature order matches FEATURE_NAMES exactly and must never drift out of sync with
it — the explainability step below depends on the two staying aligned.
"""

from __future__ import annotations

from datetime import datetime, timezone
from statistics import mean, pstdev

import numpy as np

from contracts import Transaction

FEATURE_NAMES = [
    "amount_zscore",
    "hour_of_day",
    "is_new_beneficiary",
    "is_new_device",
    "is_new_location",
    "is_new_merchant_category",
    "transactions_last_24h",
    "is_international",
    "declared_travel_mode",
    "is_emergency_request",
]

# Plain-language explanation shown when a feature is the reason a transaction was
# flagged — Day 7's explicit rule: "Risk = 0.37" is not an acceptable answer to
# "why", these are.
_REASON_TEXT = {
    "amount_zscore": "amount is far above your typical range",
    "hour_of_day": "unusual time of day for you",
    "is_new_beneficiary": "new beneficiary",
    "is_new_device": "new device",
    "is_new_location": "new location",
    "is_new_merchant_category": "unfamiliar merchant category",
    "transactions_last_24h": "unusually high transaction frequency",
    "is_international": "international transaction",
    "declared_travel_mode": "travel mode declared",
    "is_emergency_request": "emergency request",
}

# The wording above describes a value ABOVE this subject's usual level. explain()
# ranks features by the SIZE of the deviation, so a feature can also be a top
# reason because it is unusually LOW -- the only payment in 24 hours sits well
# below a history that averages 1.67, and was once explained as "unusually high
# transaction frequency", the opposite of what was measured. Every feature whose
# wording names a direction therefore has words for the other side. hour_of_day
# needs none: "unusual" is true either way.
_REASON_TEXT_BELOW = {
    "amount_zscore": "amount is far below your typical range",
    "is_new_beneficiary": "a known beneficiary, though new ones are usual for you",
    "is_new_device": "a known device, though new ones are usual for you",
    "is_new_location": "a known location, though new ones are usual for you",
    "is_new_merchant_category": "a familiar merchant category, though new ones are usual for you",
    "transactions_last_24h": "fewer transactions than usual in the last 24 hours",
    "is_international": "a domestic transaction, though yours are usually international",
    "declared_travel_mode": "no travel mode declared, though you usually declare it",
    "is_emergency_request": "not an emergency request, though yours usually are",
}


def _utc(ts: str) -> datetime:
    """Every timestamp this module reads, as an instant in UTC.

    UTC IS THE CANONICAL TIME BASIS FOR ML FEATURES (D2, 2026-09-18). Training
    history is generated in UTC (synth.generate_normal_history), and hour_of_day
    is the UTC hour, so one instant has one feature vector no matter which
    offset the caller wrote it in. Until 2026-09-18 the hour came from
    `datetime.fromisoformat(ts).hour` -- the raw hour of whatever offset
    arrived -- so the same moment sent as +05:30 and as +00:00 produced
    different hours, different scores and sometimes different reasons, while the
    model had only ever seen UTC hours during training.

    A timestamp with no offset is read as UTC rather than as the machine's local
    time, so a laptop's own zone can never move a score. This is deliberately
    NOT what policy_hour() does for TIME_WINDOW rules: "odd hours" is a
    statement about a person's night and is evaluated in the user's own
    timezone. That rule is about people; this feature is about instants.
    """
    parsed = datetime.fromisoformat(ts)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _hour(ts: str) -> int:
    return _utc(ts).hour


def extract_features(transaction: Transaction, history: list[Transaction]) -> np.ndarray:
    """history must be the subject's own prior transactions, oldest-first is not
    required. Does not include `transaction` itself."""
    amounts = [float(t.amount) for t in history]
    if len(amounts) >= 2:
        avg, std = mean(amounts), pstdev(amounts)
    elif amounts:
        avg, std = amounts[0], 0.0
    else:
        avg, std = 0.0, 0.0
    amount_zscore = 0.0 if std == 0 else (float(transaction.amount) - avg) / std
    if std == 0 and avg > 0:
        # no variance to compare against (e.g. a brand-new subject) — fall back to
        # a simple ratio so a wildly larger amount still registers as unusual
        amount_zscore = (float(transaction.amount) - avg) / avg

    known_beneficiaries = {t.beneficiary for t in history}
    known_devices = {t.device_id for t in history}
    known_locations = {t.location for t in history}
    known_merchants = {t.merchant_category for t in history if t.merchant_category}

    tx_time = _utc(transaction.timestamp)
    transactions_last_24h = 1 + sum(
        1 for t in history
        if abs((tx_time - _utc(t.timestamp)).total_seconds()) <= 86400
    )

    values = [
        amount_zscore,
        float(_hour(transaction.timestamp)),
        float(transaction.beneficiary not in known_beneficiaries),
        float(transaction.device_id not in known_devices),
        float(transaction.location not in known_locations),
        float(bool(transaction.merchant_category) and transaction.merchant_category not in known_merchants),
        float(transactions_last_24h),
        float(transaction.is_international),
        float(transaction.declared_travel_mode),
        float(transaction.is_emergency_request),
    ]
    return np.array(values, dtype=float)


def extract_training_matrix(history: list[Transaction]) -> np.ndarray:
    """Same features as extract_features, computed for an entire chronological
    history at once — used only by PersonaAnomalyModel.fit().

    Two things this fixes relative to naively calling extract_features() in a
    loop over "all other transactions": (1) each transaction's features are
    computed only from transactions strictly *before* it — calling
    extract_features(t, [everything except t]) lets a transaction "see" ones that
    happen after it chronologically, e.g. a January payment could get marked
    is_new_beneficiary=False because the same beneficiary recurs in June, which a
    real system could never know at the time. That's data leakage, not just
    slow. (2) it parses each timestamp once and builds the known-beneficiary/
    device/location/merchant sets incrementally instead of rebuilding them from
    scratch for every transaction, which is what made fit() take tens of seconds
    on 200 transactions instead of a fraction of one.

    history must already be in chronological order (synth.py generates it that
    way; this function does not sort).
    """
    n = len(history)
    parsed_times = [_utc(t.timestamp) for t in history]
    amounts = [float(t.amount) for t in history]

    known_beneficiaries: set[str] = set()
    known_devices: set[str] = set()
    known_locations: set[str] = set()
    known_merchants: set[str] = set()

    rows = np.zeros((n, len(FEATURE_NAMES)), dtype=float)
    window_start = 0  # two-pointer index into the 24h lookback window
    for i, t in enumerate(history):
        prior_amounts = amounts[:i]
        if len(prior_amounts) >= 2:
            avg, std = mean(prior_amounts), pstdev(prior_amounts)
        elif prior_amounts:
            avg, std = prior_amounts[0], 0.0
        else:
            avg, std = 0.0, 0.0
        amount_zscore = 0.0 if std == 0 else (amounts[i] - avg) / std
        if std == 0 and avg > 0:
            amount_zscore = (amounts[i] - avg) / avg

        # advance the window past anything more than 24h before this transaction
        while window_start < i and (parsed_times[i] - parsed_times[window_start]).total_seconds() > 86400:
            window_start += 1
        transactions_last_24h = (i - window_start) + 1

        rows[i] = [
            amount_zscore,
            float(parsed_times[i].hour),
            float(t.beneficiary not in known_beneficiaries),
            float(t.device_id not in known_devices),
            float(t.location not in known_locations),
            float(bool(t.merchant_category) and t.merchant_category not in known_merchants),
            float(transactions_last_24h),
            float(t.is_international),
            float(t.declared_travel_mode),
            float(t.is_emergency_request),
        ]

        known_beneficiaries.add(t.beneficiary)
        known_devices.add(t.device_id)
        known_locations.add(t.location)
        if t.merchant_category:
            known_merchants.add(t.merchant_category)

    return rows


def explain(feature_vector: np.ndarray, training_mean: np.ndarray, training_std: np.ndarray, top_n: int = 3) -> list[str]:
    """Which features deviate most from this subject's own training distribution,
    in plain language — populates RiskEvidence.reasons."""
    deviations = []
    for i, name in enumerate(FEATURE_NAMES):
        std = training_std[i] if training_std[i] > 1e-9 else 1.0
        signed = (feature_vector[i] - training_mean[i]) / std
        # Ranked by size alone, exactly as before; the sign only chooses the words.
        deviations.append((abs(signed), name, signed))
    deviations.sort(reverse=True)
    return [
        _REASON_TEXT_BELOW.get(name, _REASON_TEXT[name]) if signed < 0 else _REASON_TEXT[name]
        for z, name, signed in deviations[:top_n]
        if z > 0.5
    ]
