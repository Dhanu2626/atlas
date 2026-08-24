"""Verifies a SignedAssertion from atlas_service against four independent
checks: signature validity, revocation, expiry, replay. ARCHITECTURE.md's
red-team scorecard treats forged signature, revoked device, expired
assertion, and replay as separate attack rows for exactly this reason --
each needs its own defense, and passing one check says nothing about the
others.

Check order matters: signature verification runs first, because every field
in payload (including atlas_key_id, which revocation keys off) is
unauthenticated data until the signature proves it genuinely came from the
claimed key. Deciding trust based on fields nobody has yet proven authentic
would be backwards. Replay marking runs last and only on full success --
a rejected assertion must not burn its nonce, since it never actually
succeeded.

Not wired into bank_service/main.py's live /verify endpoint yet -- per the
Step 5 proposal, that HTTP-level integration is Step 6's job. This module
is tested directly against SignedAssertion objects.
"""

from __future__ import annotations

from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from bank_service.replay_cache import ReplayCache
from bank_service.revocation import is_revoked
from contracts import SignedAssertion, canonical_assertion_bytes


def verify_assertion(
    signed: SignedAssertion,
    atlas_public_key_hex: str,
    replay_cache: ReplayCache,
    now: datetime | None = None,
) -> tuple[bool, str]:
    """Returns (approved, reason) -- same shape as bank_service/ledger.py's
    verify(), for consistency with the one convention this codebase already
    uses for a bank-side yes/no-with-reason result."""
    payload = signed.payload
    now = now or datetime.now(timezone.utc)

    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(atlas_public_key_hex))
        public_key.verify(bytes.fromhex(signed.signature), canonical_assertion_bytes(payload))
    except (InvalidSignature, ValueError):
        return False, "invalid signature"

    if is_revoked(payload.atlas_key_id):
        return False, "key revoked"

    expires_at = datetime.fromisoformat(payload.expires_at)
    if now >= expires_at:
        return False, "assertion expired"

    if replay_cache.already_consumed(payload.transaction_id, payload.nonce):
        return False, "replayed assertion"

    replay_cache.mark_consumed(payload.transaction_id, payload.nonce, now.isoformat())
    return True, "verified"
