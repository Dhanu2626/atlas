"""Revocation enforcement -- bank_service is the real security boundary here,
not atlas_service/crypto.py's revoke(). A device that's actually compromised
can't be trusted to revoke itself; the verifier has to be the one that
refuses to trust a key, independent of whatever the device claims about its
own state.

Still deliberately minimal: a set of revoked key ids, not the full
ACTIVE/SUSPENDED/REVOKED lifecycle with an audit trail across parties
(ARCHITECTURE.md's RQ-14 and BUILD-PLAN.md's V1-vs-deferred table name that as
deferred). What changed on 2026-09-22 is durability: until then the set lived in
memory, so a revoked ATLAS key was trusted again after a bank_service restart.
It is now stored in the bank's own ledger file (bank_service/db.py), so a
revocation survives a restart like the replay cache always did.
"""

from __future__ import annotations

from bank_service import db


def revoke(key_id: str) -> None:
    db.revoke_key(key_id)


def is_revoked(key_id: str) -> bool:
    return db.is_key_revoked(key_id)


def reset() -> None:
    """Test-only: clears every revocation from the current ledger file."""
    db.clear_revocations()
