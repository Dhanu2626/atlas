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


def verify_with_bank(
    client: httpx.Client, base_url: str, signed: SignedAssertion, timeout: float = 2.0
) -> BankVerdict:
    """Sends an already-built, already-signed assertion and parses the
    verdict. Deliberately doesn't build or sign anything itself -- assembling
    the AssertionPayload (nonce, timestamps, policy fields) is
    atlas_service/main.py's job (build_signed_assertion()), keeping this
    function's scope to what its own docstring already promises: the door
    into bank_service, nothing about assertion construction."""
    try:
        response = client.post(
            f"{base_url}/verify",
            json=signed.model_dump(mode="json"),
            timeout=timeout,
        )
        response.raise_for_status()
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
        raise BankUnreachableError(
            f"bank_service unreachable for {signed.payload.transaction_id}: {exc}"
        ) from exc

    body = response.json()
    return BankVerdict(
        transaction_id=body["transaction_id"],
        approved=body["approved"],
        reason=body["reason"],
    )
