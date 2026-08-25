"""Enforces the frozen transaction lifecycle and implements reconciliation.

The transition graph below is exactly ARCHITECTURE.md's frozen state list:
CREATED -> EVALUATING -> [DENIED / ALLOWED -> SIGNED -> SUBMITTED ->
[CONFIRMED / UNKNOWN -> RECONCILING -> CONFIRMED or FAILED]]

Fail-closed vs. reconcile (frozen principle 6) is structural here, not a
convention to remember: a security failure (DENIED) is a dead end reachable
only from EVALUATING, immediately. An availability failure (UNKNOWN) can only
be resolved through RECONCILING, never by jumping straight back to ALLOWED or
being silently treated as CONFIRMED.
"""

from __future__ import annotations

import httpx

from atlas_service.db import TransactionStore
from contracts import TxnState

VALID_TRANSITIONS: dict[TxnState, set[TxnState]] = {
    TxnState.CREATED: {TxnState.EVALUATING},
    TxnState.EVALUATING: {TxnState.DENIED, TxnState.ALLOWED},
    TxnState.DENIED: set(),
    TxnState.ALLOWED: {TxnState.SIGNED},
    TxnState.SIGNED: {TxnState.SUBMITTED},
    # FAILED is reachable directly from SUBMITTED (Step 6), not just via
    # RECONCILING: a synchronous bank response of "no" (frozen account,
    # insufficient funds) is resolved immediately, with no ambiguity to
    # reconcile later -- forcing it through UNKNOWN/RECONCILING first would
    # misrepresent an immediate answer as a temporarily-unknown one.
    TxnState.SUBMITTED: {TxnState.CONFIRMED, TxnState.UNKNOWN, TxnState.FAILED},
    TxnState.CONFIRMED: set(),
    TxnState.UNKNOWN: {TxnState.RECONCILING},
    TxnState.RECONCILING: {TxnState.CONFIRMED, TxnState.FAILED},
    TxnState.FAILED: set(),
}

TERMINAL_STATES = {TxnState.DENIED, TxnState.CONFIRMED, TxnState.FAILED}

# States a transaction can be "stuck" in after an interruption -- exactly
# what a restart needs to find and reconcile.
NEEDS_RECONCILIATION = {TxnState.SUBMITTED, TxnState.UNKNOWN}


class InvalidTransitionError(Exception):
    def __init__(self, transaction_id: str, current: TxnState, attempted: TxnState):
        self.transaction_id = transaction_id
        self.current = current
        self.attempted = attempted
        super().__init__(
            f"{transaction_id}: cannot transition {current.value} -> {attempted.value}"
        )


def transition(store: TransactionStore, transaction_id: str, new_state: TxnState, now: str) -> None:
    current = store.get_state(transaction_id)
    if current is None:
        raise InvalidTransitionError(transaction_id, TxnState.CREATED, new_state)
    if new_state not in VALID_TRANSITIONS.get(current, set()):
        raise InvalidTransitionError(transaction_id, current, new_state)
    store.set_state(transaction_id, new_state, now)


def reconcile(
    store: TransactionStore,
    bank_client: httpx.Client,
    bank_url: str,
    transaction_id: str,
    now: str,
) -> TxnState:
    """Never assumes an outcome (Day 3's core rule). Queries the bank's own
    record of what happened, using the SAME transaction_id -- never a new one,
    which is what would turn "checking" into "accidentally retrying"."""
    current = store.get_state(transaction_id)
    if current == TxnState.UNKNOWN:
        transition(store, transaction_id, TxnState.RECONCILING, now)
        current = TxnState.RECONCILING
    if current != TxnState.RECONCILING:
        raise InvalidTransitionError(transaction_id, current, TxnState.RECONCILING)

    try:
        response = bank_client.get(f"{bank_url}/status/{transaction_id}", timeout=2.0)
        response.raise_for_status()
        status = response.json()["status"]
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError):
        # Still can't reach the bank -- stay in RECONCILING. Never guess.
        return TxnState.RECONCILING

    if status == "CONFIRMED":
        transition(store, transaction_id, TxnState.CONFIRMED, now)
        return TxnState.CONFIRMED
    if status in ("NOT_FOUND", "REJECTED"):
        # NOT_FOUND: the bank never saw it, safe to retry later with a fresh
        # transaction. REJECTED: the bank saw it and independently said no
        # (frozen account, insufficient funds) -- also a resolved outcome,
        # not an ambiguous one. Both are FAILED; neither should be left in
        # RECONCILING waiting for a status that will never change on a later
        # poll (Step 6 finding: this case was previously unhandled and fell
        # through to the line below, meaning a bank-side rejection
        # discovered only via reconciliation -- not the synchronous
        # response path -- got stuck in RECONCILING forever).
        transition(store, transaction_id, TxnState.FAILED, now)
        return TxnState.FAILED
    # bank has it but hasn't resolved it either -- stay in RECONCILING
    return TxnState.RECONCILING
