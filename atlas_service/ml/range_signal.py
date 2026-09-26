"""`beyond_observed_range`: a separate burst evidence signal (2026-09-25).

WHY IT EXISTS. The Isolation Forest does not see bursts, and cannot be made to:
a forest only ever splits inside the range of the data it was trained on, so a
24-hour count above the training maximum follows exactly the same path as the
maximum (measured 2026-09-25: of 625 splits on that feature, the highest sits at
the training maximum; a burst of 103 payments scores like a normal day of 2).
Retraining it on bursts would be training "normal" on anomalies. So the forest is
left exactly as it is, and this module answers the one question it cannot:

    Is this customer's activity in the 24 hours up to this payment beyond the
    busiest 24 hours in that customer's own earlier history?

WHAT IT COMPUTES, all from rows dated no later than the payment being judged
(a row dated after it is ignored -- the look-ahead rule of 2026-09-25):

  current_24h       this payment plus the customer's payments in the 24 hours
                    before it: the window (t - 24h, t];
  observed_max_24h  the busiest 24 hours among the customer's payments that lie
                    OUTSIDE that window (every one at or before t - 24h), each
                    counted the same way -- itself plus the 24 hours before it;
  fired             current_24h > RANGE_MULTIPLIER x observed_max_24h.

When no earlier payment lies outside the current window there is no observed
range to compare with, and the signal does not fire (observed_max_24h is None).

WHAT IT IS AND IS NOT. Evidence, reported beside the forest's anomaly score in
RiskEvidence.range_signal and, when it fires, as one plain-language reason. It
does not change risk_band, no policy rule reads it, and so it changes no payment
decision; bursts are still REFUSED by the deterministic velocity_burst rule. It is
computed only where the ML layer operates -- a customer below the 200-payment
minimum gets INSUFFICIENT_HISTORY and no signal (registry.TrainedModel.score).
Its separation of bursts is measured on synthetic data only
(atlas_service/ml/evaluation.py): that is not evidence about real-world fraud.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from contracts import RangeSignal, Transaction

WINDOW = timedelta(hours=24)

#: Chosen on the VALIDATION split only, by evaluation.calibrate_range_multiplier(),
#: under a rule fixed before it was run: the largest multiplier in RANGE_GRID whose
#: validation false-positive rate is at most 1% and whose validation burst recall
#: is the best any such multiplier reaches. The test split never informs it, and
#: tests/test_range_signal.py recomputes it and fails if this constant drifts.
RANGE_MULTIPLIER = 6.0


def _ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _busiest_24h(times: list[datetime]) -> int:
    """The largest count, over the rows in `times`, of a row plus the rows in the
    24 hours before it. `times` must be sorted."""
    best, start = 0, 0
    for i, t in enumerate(times):
        while t - times[start] >= WINDOW:
            start += 1
        best = max(best, i - start + 1)
    return best


def measure(transaction: Transaction, history: list[Transaction]) -> tuple[int, int | None]:
    """(current_24h, observed_max_24h) -- the two numbers the signal compares.
    Rows dated after the transaction are ignored."""
    t = _ts(transaction.timestamp)
    past = sorted(ts for ts in (_ts(h.timestamp) for h in history) if ts <= t)
    window_start = t - WINDOW
    current = 1 + sum(1 for ts in past if ts > window_start)
    baseline = [ts for ts in past if ts <= window_start]
    return current, (_busiest_24h(baseline) if baseline else None)


def fires(current: int, observed_max: int | None, multiplier: float) -> bool:
    return observed_max is not None and current > multiplier * observed_max


def beyond_observed_range(transaction: Transaction, history: list[Transaction],
                          multiplier: float = RANGE_MULTIPLIER) -> RangeSignal:
    current, observed = measure(transaction, history)
    return RangeSignal(fired=fires(current, observed, multiplier), current_24h=current,
                       observed_max_24h=observed, multiplier=multiplier)


def range_reason(signal: RangeSignal) -> str:
    """The reason line shown when the signal fires. Worded so it cannot be read as
    the anomaly score's own finding."""
    return (f"{signal.current_24h} payments in the last 24 hours, more than "
            f"{signal.multiplier:g}x this customer's busiest earlier 24 hours "
            f"({signal.observed_max_24h}) -- the beyond_observed_range signal, "
            f"separate from the anomaly score")
