"""bank_service — the independent verifier. Holds only what it needs to make
its own decision; never imports atlas_service.policy or atlas_service.ml (see
tests/test_bank_boundary.py's source-level check for this).
"""

from __future__ import annotations

from decimal import Decimal

from fastapi import FastAPI
from pydantic import BaseModel

from bank_service.ledger import status, verify

app = FastAPI(title="bank_service")


class VerifyRequest(BaseModel):
    subject: str
    amount: Decimal
    transaction_id: str


@app.post("/verify")
def verify_endpoint(req: VerifyRequest) -> dict:
    approved, reason = verify(req.subject, req.amount, req.transaction_id)
    return {"transaction_id": req.transaction_id, "approved": approved, "reason": reason}


@app.get("/status/{transaction_id}")
def status_endpoint(transaction_id: str) -> dict:
    return {"transaction_id": transaction_id, "status": status(transaction_id)}
