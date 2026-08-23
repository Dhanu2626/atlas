"""atlas_service — the trusted core. Runs ML (Step 1) + policy (Step 2), and
for ALLOW decisions, calls out to bank_service to check. Holds the private key
once Step 5 exists; holds no bank-ledger data ever, by construction (there is
no ledger import here, and never will be).

Known, temporary simplification (not a design flaw, worth naming explicitly):
with no persistence layer yet (that's Step 4), the ML model is fit fresh on
each request from synth.py's demo persona rather than loaded from a cached,
previously-trained model per subject. Fine for this step's actual purpose
(proving the service boundary and communication handling); would need real
model persistence before this is anything but a demo.

Conservative, flagged design choice for the DENY side: if the policy engine's
own decision is already DENY, this never calls bank_service at all — there's
nothing to ask, and ARCHITECTURE.md's RQ-13/28/29 (what happens when ATLAS
says DENY and the bank would've said yes) is explicitly unresolved research,
not something to quietly decide by writing code that assumes an answer.
"""

from __future__ import annotations

import httpx
from fastapi import Depends, FastAPI
from pydantic import BaseModel

from atlas_service.bank_client import BankUnreachableError, verify_with_bank
from atlas_service.ml.model import PersonaAnomalyModel
from atlas_service.ml.synth import Persona, generate_normal_history
from atlas_service.policy.engine import POLICIES_DIR, evaluate, load_policy
from contracts import Decision, Transaction

app = FastAPI(title="atlas_service")

BANK_SERVICE_URL = "http://127.0.0.1:8100"


def get_bank_client() -> httpx.Client:
    """Real network client by default. Tests override this (via FastAPI's
    dependency_overrides) to point at an in-process bank_service for the
    happy-path cases, or at a genuinely closed port for the failure case —
    the same production code path exercised either way, not a mock of it."""
    return httpx.Client()


def _demo_model_and_history(subject: str) -> tuple[PersonaAnomalyModel, list[Transaction]]:
    history = generate_normal_history(Persona(subject=subject), n=200, seed=42)
    model = PersonaAnomalyModel().fit(history)
    return model, history


@app.post("/evaluate")
def evaluate_endpoint(transaction: Transaction) -> dict:
    """ML + policy only — no bank contact. Matches Step 1/2's already-verified
    behavior exactly; this endpoint is those two steps made reachable over
    HTTP, nothing new added to the decision logic itself."""
    model, history = _demo_model_and_history(transaction.subject)
    risk = model.score(transaction, history)
    policy = load_policy(POLICIES_DIR / f"{transaction.subject}.yaml")
    decision = evaluate(transaction, risk, history, policy)
    return {"risk": risk.model_dump(), "decision": decision.model_dump()}


@app.post("/transact")
def transact_endpoint(
    transaction: Transaction, bank_client: httpx.Client = Depends(get_bank_client)
) -> dict:
    """The full slice available at this stage: ML -> policy -> (if ALLOW) bank.
    No signing yet (Step 5), no persistent state machine yet (Step 4) — those
    still need to be layered in before this is the real thing."""
    model, history = _demo_model_and_history(transaction.subject)
    risk = model.score(transaction, history)
    policy = load_policy(POLICIES_DIR / f"{transaction.subject}.yaml")
    decision = evaluate(transaction, risk, history, policy)

    result = {"risk": risk.model_dump(), "decision": decision.model_dump()}

    if decision.decision != Decision.ALLOW:
        result["bank_verdict"] = None
        result["final_status"] = decision.decision.value
        return result

    try:
        verdict = verify_with_bank(bank_client, BANK_SERVICE_URL, transaction)
    except BankUnreachableError:
        result["bank_verdict"] = None
        result["final_status"] = "PENDING"
        return result

    result["bank_verdict"] = verdict.model_dump()
    # ATLAS ALLOW + bank DENY -> DENY, always (the authority hierarchy, not a
    # judgment call — ARCHITECTURE.md's "the bank wins" rule).
    result["final_status"] = "ALLOW" if verdict.approved else "DENY"
    return result
