"""Synthetic per-user transaction data.

Real transaction data is never used — Day 7 explicitly decided synthetic data is
both safer and appropriate for this research prototype. Every planted anomaly below
is one of the specific examples from the original research conversation, not an
invented substitute (see ledger/SYNTHESIS.md #4) — so the model gets validated
against the exact scenarios that motivated ATLAS's ML component in the first place,
not generic stand-ins.

Normal histories aren't flat random noise either: they include a recurring monthly
pattern (salary, rent, groceries) per the "Financial Behaviour Timeline" idea from
the very first pre-Day-1 discussion, so the baseline the model learns is a rhythm,
not just an average.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from contracts import Transaction


@dataclass
class Persona:
    """One synthetic user's "normal." Everything downstream is defined relative
    to this — there is no global notion of a normal transaction in ATLAS, only a
    normal-for-this-person one (Day 7's Behavioral Baseline concept)."""

    subject: str
    home_location: str = "Bengaluru,IN"
    devices: tuple[str, ...] = ("device-primary-01",)
    known_beneficiaries: tuple[str, ...] = ("ben-mother", "ben-friend", "ben-grocery")
    known_merchant_categories: tuple[str, ...] = (
        "amazon", "flipkart", "zomato", "electricity",
    )
    normal_amount_low: Decimal = Decimal("500")
    normal_amount_high: Decimal = Decimal("3000")
    normal_hour_low: int = 8
    normal_hour_high: int = 20
    auth_methods: tuple[str, ...] = ("pin", "biometric")


def _rand_amount(low: Decimal, high: Decimal, rng: random.Random) -> Decimal:
    span = float(high - low)
    return (low + Decimal(str(round(rng.uniform(0, span), 2)))).quantize(Decimal("0.01"))


def _tx_id(prefix: str, i: int) -> str:
    return f"{prefix}-{i:05d}"


def generate_normal_history(
    persona: Persona,
    n: int = 200,
    start: datetime | None = None,
    seed: int = 0,
    travel_locations: tuple[str, ...] = ("Paris,FR", "Dubai,AE"),
) -> list[Transaction]:
    """A realistic recurring pattern, not flat noise.

    Every 30 transactions or so is a "salary" credit-adjacent day (modelled here as
    a low-anomaly recurring rent/subscription payment on a fixed day-of-month,
    since Transaction models outgoing payments) — the point is the model sees the
    same beneficiary/amount/day combination recur, the way a real rent payment
    would, rather than every transaction being independently random.

    Also includes occasional genuine travel (every ~40 transactions,
    declared_travel_mode=True + international + a different location). This isn't
    decorative: Day 7 Q4's whole point was that Travel Mode should change how
    behavioral evidence is *interpreted*, which for an Isolation Forest only works
    if the model has actually seen that combination as part of someone's normal
    pattern during training — without it, there's nothing to distinguish
    legitimate travel from the device/location anomaly case at all.
    """
    rng = random.Random(seed)
    start = start or datetime(2026, 1, 1, tzinfo=timezone.utc)
    out: list[Transaction] = []
    for i in range(n):
        day_offset = i * (30.0 / max(n, 1)) * 6  # spread across ~6 synthetic months
        is_recurring_rent = i % 30 == 0
        is_travel = (not is_recurring_rent) and i % 40 == 20
        ts = start + timedelta(days=day_offset, hours=rng.randint(
            persona.normal_hour_low, persona.normal_hour_high
        ), minutes=rng.randint(0, 59))
        if is_recurring_rent:
            amount = Decimal("15000.00")
            beneficiary = "ben-landlord"
            merchant_category = None
            location = persona.home_location
        elif is_travel:
            amount = _rand_amount(Decimal("1500"), Decimal("4000"), rng)
            beneficiary = f"ben-travel-{i}"
            merchant_category = "hospitality"
            location = rng.choice(travel_locations)
        else:
            amount = _rand_amount(persona.normal_amount_low, persona.normal_amount_high, rng)
            beneficiary = rng.choice(persona.known_beneficiaries)
            merchant_category = rng.choice(persona.known_merchant_categories)
            location = persona.home_location
        out.append(Transaction(
            transaction_id=_tx_id(f"{persona.subject}-normal", i),
            subject=persona.subject,
            amount=amount,
            currency="EUR" if is_travel else "INR",
            beneficiary=beneficiary,
            location=location,
            device_id=rng.choice(persona.devices),
            merchant_category=merchant_category,
            authentication_method=rng.choice(persona.auth_methods),
            is_new_beneficiary=False,
            is_new_device=False,
            is_international=is_travel,
            declared_travel_mode=is_travel,
            is_emergency_request=False,
            timestamp=ts.isoformat(),
        ))
    return out


def planted_anomalies(persona: Persona, history_end: datetime | None = None) -> dict[str, list[Transaction]]:
    """The specific examples from the original research, not invented substitutes.

    See ledger/SYNTHESIS.md #4 for exactly which conversation each one traces to.
    Each value is a list because the velocity case needs many transactions to
    demonstrate a burst; everything else is a single-element list for uniformity.
    """
    base = history_end or datetime(2026, 7, 1, tzinfo=timezone.utc)

    time_amount_anomaly = Transaction(
        transaction_id=f"{persona.subject}-anom-time-amount",
        subject=persona.subject,
        amount=Decimal("70000.00"),
        currency="INR",
        beneficiary="ben-unknown-1",
        location=persona.home_location,
        device_id=persona.devices[0],
        merchant_category=None,
        authentication_method="pin",
        is_new_beneficiary=True,
        is_new_device=False,
        is_international=False,
        declared_travel_mode=False,
        is_emergency_request=False,
        timestamp=base.replace(hour=3, minute=12).isoformat(),
    )

    velocity_burst = [
        Transaction(
            transaction_id=f"{persona.subject}-anom-velocity-{i:02d}",
            subject=persona.subject,
            amount=_rand_amount(Decimal("100"), Decimal("500"), random.Random(i)),
            currency="INR",
            beneficiary=persona.known_beneficiaries[i % len(persona.known_beneficiaries)],
            location=persona.home_location,
            device_id=persona.devices[0],
            merchant_category=None,
            authentication_method="pin",
            is_new_beneficiary=False,
            is_new_device=False,
            is_international=False,
            declared_travel_mode=False,
            is_emergency_request=False,
            timestamp=(base + timedelta(seconds=i * 2)).isoformat(),
        )
        for i in range(45)
    ]

    unknown_merchant = Transaction(
        transaction_id=f"{persona.subject}-anom-merchant",
        subject=persona.subject,
        amount=Decimal("2000.00"),
        currency="INR",
        beneficiary="ben-crypto-exchange",
        location=persona.home_location,
        device_id=persona.devices[0],
        merchant_category="cryptocurrency_exchange",
        authentication_method="pin",
        is_new_beneficiary=True,
        is_new_device=False,
        is_international=False,
        declared_travel_mode=False,
        is_emergency_request=False,
        timestamp=base.replace(hour=14).isoformat(),
    )

    device_location_anomaly = Transaction(
        transaction_id=f"{persona.subject}-anom-device-location",
        subject=persona.subject,
        amount=Decimal("2500.00"),
        currency="EUR",
        beneficiary="ben-unknown-2",
        location="Paris,FR",
        device_id="device-unknown-99",
        merchant_category="amazon",
        authentication_method="pin",
        is_new_beneficiary=True,
        is_new_device=True,
        is_international=True,
        declared_travel_mode=False,
        is_emergency_request=False,
        timestamp=base.replace(hour=15).isoformat(),
    )

    legitimate_large_purchase = Transaction(
        transaction_id=f"{persona.subject}-legit-laptop",
        subject=persona.subject,
        amount=Decimal("85000.00"),
        currency="INR",
        beneficiary="ben-electronics-store",
        location=persona.home_location,
        device_id=persona.devices[0],
        merchant_category="electronics",
        authentication_method="biometric",
        is_new_beneficiary=True,
        is_new_device=False,
        is_international=False,
        declared_travel_mode=False,
        is_emergency_request=False,
        timestamp=base.replace(hour=16).isoformat(),
    )

    travel_mode_international = Transaction(
        transaction_id=f"{persona.subject}-travel-intl",
        subject=persona.subject,
        amount=Decimal("2200.00"),
        currency="EUR",
        beneficiary="ben-hotel-paris",
        location="Paris,FR",
        device_id=persona.devices[0],
        merchant_category="hospitality",
        authentication_method="biometric",
        is_new_beneficiary=True,
        is_new_device=False,
        is_international=True,
        declared_travel_mode=True,
        is_emergency_request=False,
        timestamp=base.replace(hour=17).isoformat(),
    )

    return {
        "time_amount_anomaly": [time_amount_anomaly],
        "velocity_burst": velocity_burst,
        "unknown_merchant": [unknown_merchant],
        "device_location_anomaly": [device_location_anomaly],
        "legitimate_large_purchase": [legitimate_large_purchase],
        "travel_mode_international": [travel_mode_international],
    }
