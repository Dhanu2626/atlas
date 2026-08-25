"""Currency conversion for rail adapters -- a hardcoded, illustrative rate.

BUILD-PLAN.md's V1-vs-deferred table is explicit that V1 gets "a fixed,
hardcoded conversion rate for the demo" and defers "live FX feeds,
timing/rounding edge cases." This file is that fixed rate, and it is
deliberately NOT presented as solving anything.

Why this matters more than it looks: ARCHITECTURE.md's red team rates
cross-rail/cross-border incompatibility as the single hardest open problem
(RQ-16/18/19/25/26), specifically naming "currency conversion timing, fees,
rounding" -- and this module is where that shows up concretely. A MAX_AMOUNT
limit expressed in INR does not cleanly become a limit in BRL: two-decimal
money rounding alone means converting and converting back does not return
the original amount. tests/test_adapters.py demonstrates that divergence
rather than hiding it.

The rate below is invented for the demo. It is not a market rate, was never
a market rate, and no part of this system should be read as claiming
otherwise.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

# Illustrative only -- see module docstring. One direction is stored; the
# reverse is derived, so the pair can never drift out of sync with itself.
_RATES: dict[tuple[str, str], Decimal] = {
    ("INR", "BRL"): Decimal("0.065"),
}

_MONEY = Decimal("0.01")


class UnsupportedCurrencyPairError(Exception):
    """Fail-closed: an unknown pair raises rather than passing the amount
    through unconverted, which would silently present an INR figure as if it
    were BRL."""


def convert(amount: Decimal, from_currency: str, to_currency: str) -> Decimal:
    """Converts and quantizes to 2 decimal places (ROUND_HALF_UP).

    The quantization is the honest part: real money has a smallest unit, and
    rounding to it is exactly what makes conversion lossy and
    non-round-trippable. Keeping full precision internally would hide the
    very problem this prototype is supposed to be able to point at.
    """
    if from_currency == to_currency:
        return amount.quantize(_MONEY, rounding=ROUND_HALF_UP)

    if (from_currency, to_currency) in _RATES:
        rate = _RATES[(from_currency, to_currency)]
    elif (to_currency, from_currency) in _RATES:
        rate = Decimal(1) / _RATES[(to_currency, from_currency)]
    else:
        raise UnsupportedCurrencyPairError(f"no rate for {from_currency}->{to_currency}")

    return (amount * rate).quantize(_MONEY, rounding=ROUND_HALF_UP)
