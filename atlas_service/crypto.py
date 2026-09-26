"""atlas_service's trusted-core crypto interface -- the software-only stand-in
for ARCHITECTURE.md's Embedded Interface Emulator. Of its 7 named functions,
this implements the 5 that Step 5 scopes: init_device, generate_identity,
get_public_key, secure_sign, revoke. verify_policy is already covered by
policy/engine.py's hash + rollback check (Step 2); attest() stays deferred --
BUILD-PLAN.md's V1-vs-deferred table is explicit that real attestation needs
real hardware and stays simulated by design.

Software-only, and honest about it (ARCHITECTURE.md principle 4): since
2026-09-22 the private key is encrypted at rest by keystore.py (Windows DPAPI by
default), not held by a secure element. A process running as the same user can
still use it, so this must never be presented as hardware-equivalent security.

Every function takes an optional keys_dir so tests can point at an isolated
tmp_path instead of the real device identity -- same testability shape as
atlas_service/db.py's TransactionStore(db_path).
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import keystore
from contracts import AssertionPayload, canonical_assertion_bytes

DEFAULT_KEYS_DIR = Path(__file__).parent / "keys"
DEFAULT_KEY_ID = "atlas-demo-key-1"

_PRIVATE_KEY_FILENAME = "atlas_ed25519.key"
_KEY_PURPOSE = "atlas-signing"
_REVOKED_MARKER_FILENAME = "REVOKED"


class DeviceRevokedError(Exception):
    """Raised when signing is attempted against a revoked device identity.

    This is the device-side symptom of revocation, not the security
    enforcement itself -- a genuinely compromised device can't be trusted to
    honor its own revocation. The enforcement path bank_service actually
    relies on is bank_service/revocation.py, checked independently during
    verification.
    """


def _private_key_path(keys_dir: Path) -> Path:
    return keys_dir / _PRIVATE_KEY_FILENAME


def _revoked_marker_path(keys_dir: Path) -> Path:
    return keys_dir / _REVOKED_MARKER_FILENAME


def init_device(keys_dir: Path = DEFAULT_KEYS_DIR) -> None:
    """Ensures a device identity exists. Idempotent -- safe to call on every
    startup. Refuses to silently paper over a prior revocation; re-enrollment
    after revoke() requires an explicit generate_identity() call, not an
    incidental init_device() side effect."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    if _revoked_marker_path(keys_dir).exists():
        raise DeviceRevokedError(
            "device identity has been revoked; call generate_identity() to re-enroll"
        )
    if not _private_key_path(keys_dir).exists():
        generate_identity(keys_dir)


def generate_identity(keys_dir: Path = DEFAULT_KEYS_DIR) -> None:
    """Generates a fresh Ed25519 keypair and persists the private key.
    Called once per device in real usage; here, once per demo unless the
    key file is deleted or revoke() is called. Also the re-enrollment path:
    calling this after revoke() deliberately clears the REVOKED marker,
    since generating a genuinely new identity is exactly what re-enrollment
    means (ARCHITECTURE.md's red team: compromised keys need "revocation +
    re-enrollment", not just revocation)."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    marker = _revoked_marker_path(keys_dir)
    if marker.exists():
        marker.unlink()

    private_key = Ed25519PrivateKey.generate()
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Written encrypted (keystore.py), never as raw bytes on disk.
    keystore.write_secret(_private_key_path(keys_dir), raw, _KEY_PURPOSE)


def revoke(keys_dir: Path = DEFAULT_KEYS_DIR) -> None:
    """Device-side half of revocation: deletes the local private key and
    marks this identity disabled, so further secure_sign() calls fail
    loudly instead of silently continuing to sign with a key that's
    supposed to be dead. NOT the security-enforcement path -- see the
    DeviceRevokedError docstring above and bank_service/revocation.py."""
    keys_dir.mkdir(parents=True, exist_ok=True)
    path = _private_key_path(keys_dir)
    if path.exists():
        path.unlink()
    _revoked_marker_path(keys_dir).touch()


def _load_private_key(keys_dir: Path) -> Ed25519PrivateKey:
    if _revoked_marker_path(keys_dir).exists():
        raise DeviceRevokedError(
            "device identity has been revoked; call generate_identity() to re-enroll"
        )
    path = _private_key_path(keys_dir)
    if not path.exists():
        init_device(keys_dir)
    # Decrypted into memory only for the operation at hand. An unprotected
    # legacy key file is refused, never used as a fallback (keystore.py).
    return Ed25519PrivateKey.from_private_bytes(keystore.read_secret(path, _KEY_PURPOSE))


def get_public_key(keys_dir: Path = DEFAULT_KEYS_DIR) -> str:
    """Returns the hex-encoded raw public key bytes."""
    private_key = _load_private_key(keys_dir)
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw.hex()


def secure_sign(payload: AssertionPayload, keys_dir: Path = DEFAULT_KEYS_DIR) -> str:
    """Signs an assertion payload's canonical bytes. Returns a hex-encoded
    signature. payload.atlas_key_id is expected to already identify this
    device's own key -- there's only one identity per keys_dir in this V1
    design, so no separate key-lookup-by-id exists yet."""
    private_key = _load_private_key(keys_dir)
    signature = private_key.sign(canonical_assertion_bytes(payload))
    return signature.hex()
