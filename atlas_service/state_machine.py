"""Enforces the frozen transaction lifecycle and implements reconciliation.

The transition graph below is ARCHITECTURE.md's frozen state list, plus one
addition (AWAITING_STEP_UP, 2026-09-11) that gives the STEP_UP verdict a second
half instead of collapsing it into DENIED:
CREATED -> EVALUATING -> [DENIED / AWAITING_STEP_UP -> [ALLOWED / DENIED] /
ALLOWED -> SIGNED -> SUBMITTED ->
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
    TxnState.EVALUATING: {TxnState.DENIED, TxnState.ALLOWED, TxnState.AWAITING_STEP_UP},
    # AWAITING_STEP_UP is the only non-terminal, non-reconcilable pause in the
    # lifecycle: the transaction is waiting on a HUMAN, not on a network. That
    # distinction matters -- it must never be reconciled against the bank
    # (the bank has never heard of it) and must never be resolved by guessing.
    #
    # Exactly two exits, and both are decided by
    # atlas_service/step_up/resolver.py: ALLOWED when bounded re-resolution
    # says yes, DENIED for literally everything else including expiry. There
    # is deliberately no path back to EVALUATING -- re-evaluating is the thing
    # this whole design exists to prevent.
    TxnState.AWAITING_STEP_UP: {TxnState.ALLOWED, TxnState.DENIED},
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

# Stuck differently: a transaction here is waiting on a person, not on the
# bank, so it must NOT be reconciled -- the bank has never seen it. A restart
# resolves these by expiry, which always means DENIED, never ALLOWED.
NEEDS_STEP_UP_EXPIRY = {TxnState.AWAITING_STEP_UP}


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
        if not isinstance(status, str):
            raise TypeError("status is not a string")
    except (httpx.TransportError, httpx.HTTPStatusError, ValueError, KeyError, TypeError):
        # Still can't reach the bank, or its answer is unusable (TLS failure,
        # malformed body) -- stay in RECONCILING. Never guess.
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
