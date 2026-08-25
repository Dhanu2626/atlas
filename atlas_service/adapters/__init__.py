"""Payment-rail adapters -- the "one policy, many rail shapes" layer.

This is the bottom half of ARCHITECTURE.md's Day 12 Policy Semantic Layer
diagram. The top half (a rail-independent policy vocabulary: MAX_AMOUNT,
NEW_BENEFICIARY, INTERNATIONAL, TIME_WINDOW, VELOCITY, RISK_THRESHOLD) was
already achieved in Step 2 -- the policy YAML contains no UPI-specific terms.
Step 7 completes the picture on the output side, translating one decided,
signed transaction into differently-shaped rail payloads.

Scope, stated plainly so it is not overclaimed later: two toy adapters
agreeing in a simulation is NOT evidence that policy semantics survive
translation across real payment systems. ARCHITECTURE.md's red team rates
cross-rail/cross-border incompatibility as the single hardest open problem
and it stays open (RQ-16/18/19/25/26). pix_adapter's deliberate
signed-vs-converted amount divergence is this step pointing AT that problem,
not solving it.

Only UPI and Pix are registered. A third (FPS) sits in BUILD-PLAN.md's
deferred column; the registry below is what makes adding one later a
one-line change rather than a refactor.
"""

from __future__ import annotations

from atlas_service.adapters import pix_adapter, upi_adapter
from atlas_service.adapters.base import RailSemantics, UnknownRailError
from contracts import SignedAssertion

RAIL_ADAPTERS = {
    upi_adapter.RAIL: upi_adapter,
    pix_adapter.RAIL: pix_adapter,
}

SUPPORTED_RAILS = tuple(RAIL_ADAPTERS)

DEFAULT_RAIL = upi_adapter.RAIL

__all__ = [
    "DEFAULT_RAIL",
    "RAIL_ADAPTERS",
    "SUPPORTED_RAILS",
    "RailSemantics",
    "UnknownRailError",
    "semantic_view",
    "to_rail_payload",
]


def _adapter_for(rail: str):
    try:
        return RAIL_ADAPTERS[rail]
    except KeyError:
        raise UnknownRailError(
            f"unknown rail {rail!r}; supported rails: {', '.join(SUPPORTED_RAILS)}"
        ) from None


def to_rail_payload(rail: str, signed: SignedAssertion) -> dict:
    """Frames a signed assertion in the named rail's shape. Raises
    UnknownRailError for anything unregistered -- never falls back to a
    default, which would mean silently routing a payment over a rail nobody
    selected."""
    return _adapter_for(rail).to_payload(signed)


def semantic_view(rail: str, payload: dict) -> RailSemantics:
    """Recovers rail-independent meaning from a rail-shaped payload."""
    return _adapter_for(rail).semantic_view(payload)
