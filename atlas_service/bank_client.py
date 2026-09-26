"""atlas_service's only door into bank_service. This direction of communication
is expected (ATLAS asks the bank to check); the reverse must never exist.

Implements ARCHITECTURE.md's failure-mode table exactly: "Bank unavailable ->
pending." An unreachable or slow bank must never be silently treated as
approval — that would turn a network problem into a security hole. This is the
one behavior in this file that's a frozen rule, not my own judgment call.
"""

from __future__ import annotations

import httpx

from contracts import BankVerdict, SignedAssertion


class BankUnreachableError(Exception):
    """Raised when bank_service can't be reached or doesn't respond in time.
    Callers must treat this as PENDING, never as an implicit approval."""


class BankResponseError(BankUnreachableError):
    """The bank answered, but not with a usable verdict for THIS transaction:
    not JSON, missing or mistyped fields, or a verdict naming another
    transaction_id. The bank may or may not have processed the payment, so the
    outcome is unknown -- exactly the case reconciliation exists for. It is a
    subclass of BankUnreachableError so every caller already settles it PENDING,
    never approval. (Until 2026-09-22 such a reply raised an unhandled KeyError
    that left the transaction stranded in SUBMITTED.)"""


def verify_with_bank(
    client: httpx.Client, base_url: str, signed: SignedAssertion, timeout: float = 2.0
) -> BankVerdict:
    """Sends an already-built, already-signed assertion and parses the
    verdict. Deliberately doesn't build or sign anything itself -- assembling
    the AssertionPayload (nonce, timestamps, policy fields) is
    atlas_service/main.py's job (build_signed_assertion()), keeping this
    function's scope to what its own docstring already promises: the door
    into bank_service, nothing about assertion construction."""
    txn_id = signed.payload.transaction_id
    try:
        response = client.post(
            f"{base_url}/verify",
            json=signed.model_dump(mode="json"),
            timeout=timeout,
        )
        response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise BankUnreachableError(
            f"bank_service answered HTTP {exc.response.status_code} for {txn_id}") from exc
    except httpx.TransportError as exc:
        # Connection refused, TLS handshake or certificate failure, timeout,
        # protocol error: the payment's fate is unknown or it was never sent.
        # Either way: PENDING, then reconcile -- never a guess, never a retry.
        raise BankUnreachableError(
            f"bank_service unreachable for {txn_id}: {type(exc).__name__}") from exc

    try:
        body = response.json()
    except ValueError as exc:
        raise BankResponseError(f"bank reply for {txn_id} is not JSON") from exc
    if (not isinstance(body, dict)
            or body.get("transaction_id") != txn_id
            or not isinstance(body.get("approved"), bool)
            or not isinstance(body.get("reason"), str)):
        raise BankResponseError(f"bank reply for {txn_id} is malformed or names another transaction")
    return BankVerdict(transaction_id=txn_id, approved=body["approved"], reason=body["reason"])
