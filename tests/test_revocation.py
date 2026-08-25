"""bank_service-side revocation tests -- the actual enforcement path. See
bank_service/revocation.py's module docstring for why this, not
atlas_service/crypto.py's device-side revoke(), is what really stops a
revoked key from passing verification: a compromised device can't be
trusted to revoke itself, so the verifier has to be the one holding this
authority.
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


def _signed_assertion(keys_dir, key_id="atlas-demo-key-1", **overrides):
    # Relative to "now", not a hardcoded date -- see test_replay.py's
    # matching helper for why (Step 6 found the same staleness bug here).
    now = datetime.now(timezone.utc)
    fields = dict(
        issuer="atlas-demo",
        subject="user-demo-1",
        transaction_id="txn-revoke-1",
        amount="1500.00",
        currency="INR",
        beneficiary="ben-1",
        policy_version=1,
        policy_hash="deadbeef",
        decision=Decision.ALLOW,
        nonce="nonce-revoke-1",
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=300)).isoformat(),
        audience="bank_service",
        atlas_key_id=key_id,
    )
    fields.update(overrides)
    payload = AssertionPayload(**fields)
    signature = crypto.secure_sign(payload, keys_dir=keys_dir)
    public_key_hex = crypto.get_public_key(keys_dir=keys_dir)
    return SignedAssertion(payload=payload, signature=signature), public_key_hex


def test_valid_key_is_accepted(tmp_path):
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    signed, public_key_hex = _signed_assertion(keys_dir)

    ok, reason = verify_assertion(signed, public_key_hex, cache)
    assert ok is True


def test_revoked_key_is_rejected_even_with_a_valid_signature(tmp_path):
    """The core case: a genuinely, correctly signed assertion -- not a
    forgery -- from a key bank_service has separately decided to no longer
    trust. Signature validity and trustworthiness are different questions."""
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    signed, public_key_hex = _signed_assertion(keys_dir, key_id="atlas-demo-key-1")

    revocation.revoke("atlas-demo-key-1")
    ok, reason = verify_assertion(signed, public_key_hex, cache)

    assert ok is False
    assert reason == "key revoked"


def test_revoking_one_key_id_does_not_affect_another(tmp_path):
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    signed, public_key_hex = _signed_assertion(keys_dir, key_id="atlas-other-key")

    revocation.revoke("atlas-demo-key-1")
    ok, reason = verify_assertion(signed, public_key_hex, cache)

    assert ok is True


def test_revoked_assertion_is_not_marked_consumed_in_replay_cache(tmp_path):
    """A rejected-for-revocation assertion must not burn its nonce -- it
    never actually succeeded, so a legitimate resend after the key is fixed
    (new assertion, in practice) shouldn't be blocked by a phantom replay
    entry from the rejected attempt."""
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    signed, public_key_hex = _signed_assertion(keys_dir)

    revocation.revoke("atlas-demo-key-1")
    verify_assertion(signed, public_key_hex, cache)

    assert cache.already_consumed(signed.payload.transaction_id, signed.payload.nonce) is False


def test_revoke_is_idempotent(tmp_path):
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    signed, public_key_hex = _signed_assertion(keys_dir)

    revocation.revoke("atlas-demo-key-1")
    revocation.revoke("atlas-demo-key-1")  # must not raise or double-add
    ok, reason = verify_assertion(signed, public_key_hex, cache)

    assert ok is False
    assert reason == "key revoked"
