"""UPI-shaped rail adapter (India, INR).

A toy, illustrative shape -- ARCHITECTURE.md's own scoping note is explicit
that these adapters are "not attempts to replicate Brazil's or the UK's real
payment-message formats," and the same applies to UPI here. The borrowed
vocabulary (VPA handles, a txn_ref) is there to make the shape recognizably
UPI-flavored, not to be wire-compatible with anything NPCI operates.

The one genuinely load-bearing rule, which every adapter must follow: the
SignedAssertion is carried through UNMODIFIED, nested as-is. Step 5's
signature covers the canonical AssertionPayload bytes, so an adapter that
renamed a field or rewrote an amount *inside* the assertion would break
verification at the bank. An adapter frames; it never edits through.
"""

from __future__ import annotations

from atlas_service.adapters.base import RailSemantics
from contracts import SignedAssertion

RAIL = "UPI"

# Toy handle suffix, the UPI "user@bank" VPA convention in shape only.
_VPA_SUFFIX = "@atlasbank"


def to_payload(signed: SignedAssertion) -> dict:
    """Frames an assertion as a UPI-flavored payment instruction.

    Takes only the SignedAssertion -- not the Transaction, not the
    PolicyDecision -- because the assertion already carries every field the
    rail needs (subject, beneficiary, amount, currency, transaction_id,
    decision, policy_version, policy_hash). That keeps the adapter provably
    clear of ML/policy internals, which is what makes the untrusted-side
    property in base.py's docstring true rather than aspirational.
    """
    payload = signed.payload
    return {
        "rail": RAIL,
        "txn_ref": payload.transaction_id,
        "payer_vpa": f"{payload.subject}{_VPA_SUFFIX}",
        "payee_vpa": f"{payload.beneficiary}{_VPA_SUFFIX}",
        "amount": {"value": payload.amount, "currency": payload.currency},
        "atlas_policy": {
            "decision": payload.decision.value,
            "policy_version": payload.policy_version,
            "policy_hash": payload.policy_hash,
        },
        # Carried intact -- see module docstring.
        "atlas_assertion": signed.model_dump(mode="json"),
    }


def semantic_view(payload: dict) -> RailSemantics:
    """Reverses this adapter's own shape back to rail-independent meaning."""
    return RailSemantics(
        transaction_id=payload["txn_ref"],
        subject=payload["payer_vpa"].removesuffix(_VPA_SUFFIX),
        beneficiary=payload["payee_vpa"].removesuffix(_VPA_SUFFIX),
        decision=payload["atlas_policy"]["decision"],
        policy_version=payload["atlas_policy"]["policy_version"],
        policy_hash=payload["atlas_policy"]["policy_hash"],
        signed_amount=payload["amount"]["value"],
        signed_currency=payload["amount"]["currency"],
    )
