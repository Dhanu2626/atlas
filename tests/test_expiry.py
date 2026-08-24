"""Assertion-expiry tests -- verify_assertion's fourth independent check.
Not in BUILD-PLAN.md's original Step 5 test-file list (that list predates
this step's detailed design), added because expires_at is a frozen
AssertionPayload field and expiry was explicitly named, alongside tampering/
replay/revocation, as a case to deliberately test.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from atlas_service import crypto
from bank_service import revocation
from bank_service.replay_cache import ReplayCache
from bank_service.verify import verify_assertion
from contracts import AssertionPayload, Decision, SignedAssertion


@pytest.fixture(autouse=True)
def _reset_revocation():
    revocation.reset()
    yield
    revocation.reset()


def _signed_assertion(keys_dir, issued_at, expires_at, nonce="nonce-expiry-1"):
    payload = AssertionPayload(
        issuer="atlas-demo",
        subject="user-demo-1",
        transaction_id="txn-expiry-1",
        amount="1500.00",
        currency="INR",
        beneficiary="ben-1",
        policy_version=1,
        policy_hash="deadbeef",
        decision=Decision.ALLOW,
        nonce=nonce,
        issued_at=issued_at.isoformat(),
        expires_at=expires_at.isoformat(),
        audience="bank_service",
        atlas_key_id="atlas-demo-key-1",
    )
    signature = crypto.secure_sign(payload, keys_dir=keys_dir)
    public_key_hex = crypto.get_public_key(keys_dir=keys_dir)
    return SignedAssertion(payload=payload, signature=signature), public_key_hex


def test_assertion_within_window_is_accepted(tmp_path):
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    now = datetime.now(timezone.utc)
    signed, public_key_hex = _signed_assertion(keys_dir, now, now + timedelta(seconds=90))

    ok, reason = verify_assertion(signed, public_key_hex, cache, now=now)
    assert ok is True


def test_expired_assertion_is_rejected(tmp_path):
    """BUILD-PLAN.md's named window is 60-120s -- this uses an assertion
    that expired 80s ago, well outside even the generous end of that."""
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    now = datetime.now(timezone.utc)
    issued = now - timedelta(seconds=200)
    expired_at = now - timedelta(seconds=80)
    signed, public_key_hex = _signed_assertion(keys_dir, issued, expired_at)

    ok, reason = verify_assertion(signed, public_key_hex, cache, now=now)
    assert ok is False
    assert reason == "assertion expired"


def test_assertion_at_the_exact_expiry_instant_is_rejected(tmp_path):
    """Boundary case, matching test_policy_engine.py's own convention of
    testing exact-boundary conditions explicitly (its TIME_WINDOW tests are
    start-inclusive/end-exclusive) rather than only interior points.
    expires_at is treated as an exclusive boundary: valid strictly before
    it, not through it."""
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    now = datetime.now(timezone.utc)
    signed, public_key_hex = _signed_assertion(keys_dir, now - timedelta(seconds=60), now)

    ok, reason = verify_assertion(signed, public_key_hex, cache, now=now)
    assert ok is False
    assert reason == "assertion expired"


def test_assertion_one_second_before_expiry_is_accepted(tmp_path):
    """The other side of the same boundary -- guards against an off-by-one
    that rejects everything near the edge instead of just at/past it."""
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    now = datetime.now(timezone.utc)
    signed, public_key_hex = _signed_assertion(
        keys_dir, now - timedelta(seconds=59), now + timedelta(seconds=1)
    )

    ok, reason = verify_assertion(signed, public_key_hex, cache, now=now)
    assert ok is True


def test_expired_assertion_is_not_marked_consumed(tmp_path):
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    now = datetime.now(timezone.utc)
    signed, public_key_hex = _signed_assertion(
        keys_dir, now - timedelta(seconds=200), now - timedelta(seconds=80)
    )

    verify_assertion(signed, public_key_hex, cache, now=now)

    assert cache.already_consumed(signed.payload.transaction_id, signed.payload.nonce) is False
