"""Tests for atlas_service/crypto.py -- the software-only trusted-core
signing interface. Covers BUILD-PLAN.md Step 5's tamper-detection scenario
(both at the raw-signature level and through the real bank_service
verification path), device identity persistence, and the device-side half
of revocation.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from atlas_service import crypto
from bank_service import revocation
from bank_service.replay_cache import ReplayCache
from bank_service.verify import verify_assertion
from contracts import AssertionPayload, Decision, SignedAssertion, canonical_assertion_bytes


@pytest.fixture(autouse=True)
def _reset_revocation():
    revocation.reset()
    yield
    revocation.reset()


def _sample_payload(**overrides) -> AssertionPayload:
    fields = dict(
        issuer="atlas-demo",
        subject="user-demo-1",
        transaction_id="txn-crypto-1",
        amount="1500.00",
        currency="INR",
        beneficiary="ben-1",
        policy_version=1,
        policy_hash="deadbeef",
        decision=Decision.ALLOW,
        nonce="nonce-crypto-1",
        issued_at="2026-08-24T10:00:00+00:00",
        expires_at="2026-08-24T10:02:00+00:00",
        audience="bank_service",
        atlas_key_id="atlas-demo-key-1",
    )
    fields.update(overrides)
    return AssertionPayload(**fields)


# --- sign / verify round-trip -------------------------------------------------


def test_sign_then_verify_succeeds(tmp_path):
    keys_dir = tmp_path / "keys"
    payload = _sample_payload()
    signature_hex = crypto.secure_sign(payload, keys_dir=keys_dir)
    public_key_hex = crypto.get_public_key(keys_dir=keys_dir)

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    public_key.verify(bytes.fromhex(signature_hex), canonical_assertion_bytes(payload))


def test_signing_same_payload_twice_is_deterministic(tmp_path):
    """Ed25519 signatures are deterministic (RFC 8032, unlike ECDSA) --
    confirms canonical_assertion_bytes and secure_sign are both stable
    rather than accidentally depending on something non-reproducible."""
    keys_dir = tmp_path / "keys"
    payload = _sample_payload()
    sig_1 = crypto.secure_sign(payload, keys_dir=keys_dir)
    sig_2 = crypto.secure_sign(payload, keys_dir=keys_dir)
    assert sig_1 == sig_2


# --- tamper detection (BUILD-PLAN.md Step 5's first named scenario) ---------


def test_tampered_payload_fails_verification(tmp_path):
    """Raw-signature-level version: flip one field after signing, the
    original signature must not validate against the new bytes."""
    keys_dir = tmp_path / "keys"
    payload = _sample_payload()
    signature_hex = crypto.secure_sign(payload, keys_dir=keys_dir)
    public_key_hex = crypto.get_public_key(keys_dir=keys_dir)

    tampered = payload.model_copy(update={"amount": "9999999.00"})

    public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
    with pytest.raises(InvalidSignature):
        public_key.verify(bytes.fromhex(signature_hex), canonical_assertion_bytes(tampered))


def test_tampered_assertion_fails_through_verify_assertion(tmp_path):
    """Same property, exercised through the real bank_service verification
    path rather than raw cryptography primitives -- this is the path an
    actual tampered-in-transit assertion would hit."""
    keys_dir = tmp_path / "keys"
    cache = ReplayCache(tmp_path / "replay.db")
    payload = _sample_payload()
    signature_hex = crypto.secure_sign(payload, keys_dir=keys_dir)
    public_key_hex = crypto.get_public_key(keys_dir=keys_dir)

    tampered_payload = payload.model_copy(update={"amount": "9999999.00"})
    tampered_signed = SignedAssertion(payload=tampered_payload, signature=signature_hex)

    ok, reason = verify_assertion(tampered_signed, public_key_hex, cache)
    assert ok is False
    assert reason == "invalid signature"


# --- device identity -----------------------------------------------------------


def test_same_device_identity_persists_across_calls(tmp_path):
    keys_dir = tmp_path / "keys"
    crypto.init_device(keys_dir=keys_dir)
    key_1 = crypto.get_public_key(keys_dir=keys_dir)
    key_2 = crypto.get_public_key(keys_dir=keys_dir)
    assert key_1 == key_2


def test_secure_sign_auto_initializes_a_device_identity(tmp_path):
    """No init_device() call first -- secure_sign should still work, matching
    the "idempotent, safe to call any time" framing of the interface."""
    keys_dir = tmp_path / "keys"
    signature_hex = crypto.secure_sign(_sample_payload(), keys_dir=keys_dir)
    assert len(bytes.fromhex(signature_hex)) == 64  # Ed25519 signatures are 64 bytes


# --- device-side revocation (NOT the enforcement path -- see crypto.py) ------


def test_revoke_disables_further_signing(tmp_path):
    keys_dir = tmp_path / "keys"
    crypto.init_device(keys_dir=keys_dir)
    crypto.revoke(keys_dir=keys_dir)

    with pytest.raises(crypto.DeviceRevokedError):
        crypto.secure_sign(_sample_payload(), keys_dir=keys_dir)


def test_init_device_does_not_silently_clear_a_revocation(tmp_path):
    """A defensive init_device() call elsewhere in the codebase must not
    accidentally un-revoke a device just because the private key file is
    gone -- only an explicit generate_identity() call may re-enroll."""
    keys_dir = tmp_path / "keys"
    crypto.init_device(keys_dir=keys_dir)
    crypto.revoke(keys_dir=keys_dir)

    with pytest.raises(crypto.DeviceRevokedError):
        crypto.init_device(keys_dir=keys_dir)


def test_generate_identity_after_revoke_re_enrolls_with_a_new_key(tmp_path):
    keys_dir = tmp_path / "keys"
    crypto.init_device(keys_dir=keys_dir)
    old_public_key = crypto.get_public_key(keys_dir=keys_dir)

    crypto.revoke(keys_dir=keys_dir)
    crypto.generate_identity(keys_dir=keys_dir)
    new_public_key = crypto.get_public_key(keys_dir=keys_dir)

    assert new_public_key != old_public_key
    crypto.secure_sign(_sample_payload(), keys_dir=keys_dir)  # signing works again
