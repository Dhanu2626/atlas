"""Shared types for the payment-rail adapters.

Separate from __init__.py purely to avoid a circular import: __init__.py
imports the concrete adapters to build its registry, and the concrete
adapters need RailSemantics -- so the shared types have to live somewhere
neither side owns.

The adapters are, per ARCHITECTURE.md's Embedded Interface Emulator section,
on the UNTRUSTED side of the trust boundary: "Everything on the untrusted
side (UI, network, payment adapter) only ever calls through this interface --
it never sees the private key or the raw policy-evaluation internals."
BUILD-PLAN.md's folder structure nonetheless places them under
atlas_service/, so that property is enforced structurally instead of by
convention -- see tests/test_adapters.py's import check, which fails the
build if an adapter ever reaches for atlas_service.crypto, .policy, or .ml.
"""

from __future__ import annotations

from pydantic import BaseModel


class UnknownRailError(Exception):
    """Raised for a rail with no registered adapter. Fail-closed on purpose,
    matching policy/engine.py's unknown-condition-key behavior: an
    unrecognized rail must never quietly fall back to a default one, which
    would mean silently sending a payment somewhere nobody asked for."""


class RailSemantics(BaseModel):
    """The rail-independent meaning recoverable from any rail payload.

    The actual point of this step: two genuinely differently-shaped payloads
    must reduce to an identical RailSemantics. Each adapter implements
    semantic_view() by reversing its OWN shape, so the equality test in
    tests/test_adapters.py compares two independent implementations rather
    than one shared extractor checking its own work.

    signed_amount/signed_currency are deliberately the values from the SIGNED
    assertion, never a rail-converted amount. A rail may present a converted
    figure for local display (see pix_adapter's BRL conversion), but the
    signed original is what the bank verifies and what any policy limit was
    actually evaluated against -- so it is what "the meaning" refers to here.
    """

    transaction_id: str
    subject: str
    beneficiary: str
    decision: str
    policy_version: int
    policy_hash: str
    signed_amount: str
    signed_currency: str
