"""Tests for bank_service/replay_cache.py and the replay half of
verify_assertion -- BUILD-PLAN.md Step 5's second named scenario: a valid,
untampered, unexpired assertion must still be rejected on resend. Deliberately
a separate file from test_crypto.py's tamper tests -- replay is a different
attack from tampering and needs its own defense (ARCHITECTURE.md is explicit
about not conflating the two).
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


def _signed_assertion(keys_dir, **overrides) -> tuple[SignedAssertion, str]:
    # Relative to "now", not a hardcoded date -- a fixed absolute timestamp
    # here previously broke every test in this file the day after it was
    # written, once expires_at silently fell into the past (caught during
    # Step 6's full-suite run when the calendar rolled over).
    now = datetime.now(timezone.utc)
    fields = dict(
        issuer="atlas-demo",
        subject="user-demo-1",
        transaction_id="txn-replay-1",
        amount="1500.00",
        currency="INR",
        beneficiary="ben-1",
        policy_version=1,
        policy_hash="deadbeef",
        decision=Decision.ALLOW,
        nonce="nonce-replay-1",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=300)).isoformat(),
        audience="bank_service",
        atlas_key_id="atlas-demo-key-1",
    )
    fields.update(overrides)
    payload = AssertionPayload(**fields)
    signature = crypto.secure_sign(payload, keys_dir=keys_dir)
    public_key_hex = crypto.get_public_key(keys_dir=keys_dir)
    return SignedAssertion(payload=payload, signature=signature), public_key_hex


def test_first_presentation_is_accepted(tmp_path):
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    signed, public_key_hex = _signed_assertion(keys_dir)

    ok, reason = verify_assertion(signed, public_key_hex, cache)
    assert ok is True
    assert reason == "verified"


def test_resending_the_same_assertion_is_rejected(tmp_path):
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    signed, public_key_hex = _signed_assertion(keys_dir)

    first_ok, _ = verify_assertion(signed, public_key_hex, cache)
    second_ok, second_reason = verify_assertion(signed, public_key_hex, cache)

    assert first_ok is True
    assert second_ok is False
    assert second_reason == "replayed assertion"


def test_replay_cache_persists_across_process_restart(tmp_path):
    """The whole point of "persisted": a fresh ReplayCache object pointed at
    the same file must still remember what an earlier one consumed -- the
    same restart scenario test_state_machine.py already proves for
    transaction state, applied here to the replay cache."""
    keys_dir = tmp_path / "keys"
    db_path = tmp_path / "replay.db"
    signed, public_key_hex = _signed_assertion(keys_dir)

    first_cache = ReplayCache(db_path)
    verify_assertion(signed, public_key_hex, first_cache)
    first_cache.close()

    second_cache = ReplayCache(db_path)
    ok, reason = verify_assertion(signed, public_key_hex, second_cache)
    assert ok is False
    assert reason == "replayed assertion"


def test_different_nonce_same_transaction_is_not_a_replay(tmp_path):
    """Guards against an over-broad implementation keying the cache on
    transaction_id alone -- a legitimately re-issued assertion (e.g. after a
    STEP_UP confirmation) carries a new nonce and must not be blocked by an
    earlier, different assertion for the same transaction."""
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    signed_1, public_key_hex = _signed_assertion(keys_dir, nonce="nonce-a")
    signed_2, _ = _signed_assertion(keys_dir, nonce="nonce-b")

    ok_1, _ = verify_assertion(signed_1, public_key_hex, cache)
    ok_2, _ = verify_assertion(signed_2, public_key_hex, cache)

    assert ok_1 is True
    assert ok_2 is True


def test_replay_cache_isolates_different_db_files(tmp_path):
    """Sanity check on the fixture itself: two independent cache files must
    not somehow share state."""
    keys_dir = tmp_path / "keys"
    signed, public_key_hex = _signed_assertion(keys_dir)

    cache_a = ReplayCache(tmp_path / "a.db")
    cache_b = ReplayCache(tmp_path / "b.db")

    verify_assertion(signed, public_key_hex, cache_a)
    ok, _ = verify_assertion(signed, public_key_hex, cache_b)
    assert ok is True
