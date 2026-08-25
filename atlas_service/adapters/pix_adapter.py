"""Pix-shaped rail adapter (Brazil, BRL).

Toy and illustrative, exactly like upi_adapter -- see ARCHITECTURE.md's
scoping note. The Portuguese-flavored vocabulary (txid, pagador, recebedor,
valor, chave) and the nested grouping exist to make this shape genuinely,
visibly different from the UPI one; if both adapters emitted near-identical
dicts, "same policy, different rail output" would be a claim rather than a
demonstration.

Two things worth reading before changing anything here:

1. The SignedAssertion is carried through UNMODIFIED (same rule as every
   adapter -- see upi_adapter's docstring for why).

2. valor is a CONVERTED, BRL figure; valor_origem is what was actually
   signed. These deliberately disagree. That disagreement is not a bug to
   tidy up -- it is the concrete, runnable form of ARCHITECTURE.md's hardest
   unsolved problem (RQ-16/18/19/25/26, cross-rail/cross-border semantics,
   rated red by the red team). semantic_view() therefore reports
   valor_origem, never valor: the signed amount is what the bank verifies
   and what the policy limit was evaluated against, so it is what the
   transaction actually MEANS. The BRL figure is local presentation only.

semantic_view() deliberately reverses this module's own rail-level fields
rather than reading the embedded assertion. Reading the nested assertion
would make the cross-adapter equality test in tests/test_adapters.py
vacuous -- both adapters would be echoing one identical blob instead of two
independent translations agreeing.
"""

from __future__ import annotations

from decimal import Decimal

from atlas_service.adapters import fx
from atlas_service.adapters.base import RailSemantics
from contracts import SignedAssertion

RAIL = "PIX"

RAIL_CURRENCY = "BRL"

# Toy Pix "chave" (key) convention -- shape only, not a real key format.
_CHAVE_SUFFIX = "@atlas.br"


def to_payload(signed: SignedAssertion) -> dict:
    payload = signed.payload
    converted = fx.convert(Decimal(payload.amount), payload.currency, RAIL_CURRENCY)
    return {
        "rail": RAIL,
        "txid": payload.transaction_id,
        "pagador": {"chave": f"{payload.subject}{_CHAVE_SUFFIX}"},
        "recebedor": {"chave": f"{payload.beneficiary}{_CHAVE_SUFFIX}"},
        # Local, converted presentation -- see module docstring.
        "valor": {"original": str(converted), "moeda": RAIL_CURRENCY},
        # What was actually signed, and what the decision really means.
        "valor_origem": {"original": payload.amount, "moeda": payload.currency},
        "atlas": {
            "decisao": payload.decision.value,
            "politica_versao": payload.policy_version,
            "politica_hash": payload.policy_hash,
        },
        # Carried intact.
        "atlas_assertion": signed.model_dump(mode="json"),
    }


def semantic_view(payload: dict) -> RailSemantics:
    """Reverses this adapter's own shape back to rail-independent meaning."""
    return RailSemantics(
        transaction_id=payload["txid"],
        subject=payload["pagador"]["chave"].removesuffix(_CHAVE_SUFFIX),
        beneficiary=payload["recebedor"]["chave"].removesuffix(_CHAVE_SUFFIX),
        decision=payload["atlas"]["decisao"],
        policy_version=payload["atlas"]["politica_versao"],
        policy_hash=payload["atlas"]["politica_hash"],
        signed_amount=payload["valor_origem"]["original"],
        signed_currency=payload["valor_origem"]["moeda"],
    )
