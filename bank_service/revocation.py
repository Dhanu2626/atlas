"""Revocation enforcement -- bank_service is the real security boundary here,
not atlas_service/crypto.py's revoke(). A device that's actually compromised
can't be trusted to revoke itself; the verifier has to be the one that
refuses to trust a key, independent of whatever the device claims about its
own state.

Deliberately a small in-memory set for the prototype, not the full
ACTIVE/SUSPENDED/REVOKED lifecycle with audit trail (ARCHITECTURE.md's RQ-14
and BUILD-PLAN.md's V1-vs-deferred table both name that as deferred, not
built here). Known, documented limitation: this does not survive a
bank_service restart, unlike the replay cache -- BUILD-PLAN.md's Step 5 line
only calls the replay cache out as needing to be "persisted"; revocation is
described as "minimal." Flagging the distinction rather than silently
upgrading scope.
"""

from __future__ import annotations

_REVOKED_KEY_IDS: set[str] = set()


def revoke(key_id: str) -> None:
    _REVOKED_KEY_IDS.add(key_id)


def is_revoked(key_id: str) -> bool:
    return key_id in _REVOKED_KEY_IDS


def reset() -> None:
    """Test-only escape hatch -- module-level state needs clearing between
    tests since nothing else owns this set's lifetime yet."""
    _REVOKED_KEY_IDS.clear()
