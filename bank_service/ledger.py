"""A toy bank ledger. Independent of everything in atlas_service on purpose —
this file must never import anything from atlas_service.policy or
atlas_service.ml (see tests/test_bank_boundary.py, which checks this at the
source level, not just by convention).

Reason strings match Day 10 Q2's own enumerated list of why ATLAS=ALLOW can
still fail at the bank (insufficient funds, account restrictions, bank fraud
controls, regulatory requirements, payment-system failure, beneficiary
problems, authentication failure, network failure) — reusing the research's own
vocabulary rather than inventing new reason text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal


@dataclass
class Account:
    subject: str
    balance: Decimal
    frozen: bool = False


# Toy accounts for demo/testing. Real persistence is not this step's job.
_ACCOUNTS: dict[str, Account] = {
    "user-demo-1": Account(subject="user-demo-1", balance=Decimal("200000.00")),
    "user-frozen-1": Account(subject="user-frozen-1", balance=Decimal("500000.00"), frozen=True),
    "user-poor-1": Account(subject="user-poor-1", balance=Decimal("100.00")),
}


_PROCESSED: dict[str, tuple[bool, str]] = {}


def verify(subject: str, amount: Decimal, transaction_id: str) -> tuple[bool, str]:
    """The bank's own, independent check. Nothing here looks at ATLAS's policy
    decision, ML risk, or anything from atlas_service — by construction, since
    this function's only inputs are the subject, amount, and transaction ID.

    Idempotent by transaction_id: a resent request for one already seen
    returns the original result rather than re-evaluating the account (which
    could legitimately differ by then — the bank must answer "what happened
    to THIS transaction", not "what would happen now"). Also what makes
    Step 4's reconciliation possible at all: without remembering outcomes,
    there would be nothing to ask the bank about after a restart.
    """
    if transaction_id in _PROCESSED:
        return _PROCESSED[transaction_id]

    account = _ACCOUNTS.get(subject)
    if account is None:
        result = (False, "account restrictions")  # unknown account -> refuse, don't guess
    elif account.frozen:
        result = (False, "account restrictions")
    elif amount > account.balance:
        result = (False, "insufficient funds")
    else:
        result = (True, "approved")

    _PROCESSED[transaction_id] = result
    return result


def status(transaction_id: str) -> str:
    """CONFIRMED / REJECTED / NOT_FOUND -- what atlas_service's reconciliation
    (state_machine.py) asks after a restart, per Day 3's own reasoning: check
    the authoritative side's record rather than assume an outcome."""
    if transaction_id not in _PROCESSED:
        return "NOT_FOUND"
    approved, _ = _PROCESSED[transaction_id]
    return "CONFIRMED" if approved else "REJECTED"
