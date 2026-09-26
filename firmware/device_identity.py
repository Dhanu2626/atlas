"""Device-side cryptographic identity (Phase 3.2).

The device half of Blueprint 24.3: *"Device identity: a key pair generated
on-device (generate_identity()) ... an atlas_key_id-equivalent identifies THIS
DEVICE, distinct from the subject's ATLAS policy identity"* and *"Every request
signed with the device's private key (secure_sign())."*

THIS KEY IS NOT THE ATLAS KEY. atlas_service/crypto.py holds ATLAS's key, which
signs assertions TO THE BANK. This module holds a different key, on a different
box, proving a different thing:

    device key  ->  "this hardware authored this request"     (device -> ATLAS)
    ATLAS key   ->  "ATLAS authorized this payment"           (ATLAS -> bank)

Mixing them would let a compromised device mint bank assertions. They must never
share storage, key ids, or code paths.

WHAT THIS DOES NOT PROVE -- stated plainly because the whole point of Phase 3 is
not overclaiming:

  * The private key sits in a file encrypted at rest by keystore.py (since
    2026-09-22; Windows DPAPI by default) -- and on real hardware, in ordinary
    flash, where anyone with physical access plus esptool can read it. So a
    valid signature proves "someone who has this key", NOT "this physical
    device".
  * That gap closes only with a hardware-backed key -- an ATECC608-class secure
    element or ESP32 eFuse/HMAC identity -- where the private key provably never
    leaves the chip. Neither exists here, and Wokwi cannot simulate either.
  * ARCHITECTURE.md principle 4 applies at full force: the software-only
    prototype must never claim hardware-equivalent security.

The interface below is deliberately shaped so a secure element can be dropped in
later: callers only ever ask for a signature over bytes and never touch key
material, so a hardware implementation can satisfy the same surface.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import keystore

DEFAULT_DEVICE_KEYS_DIR = Path(__file__).parent / "device_keys"

_PRIVATE_KEY_FILENAME = "device_ed25519.key"
_KEY_PURPOSE = "device-signing"
_KEY_ID_FILENAME = "device_key_id.txt"
_COUNTER_FILENAME = "counter.txt"


class DeviceIdentityError(Exception):
    pass


#: Accept str or Path throughout, matching DeviceStore(str | Path). Callers
#: include a CLI, tests, and the device loop; requiring one type at every
#: entry point was a needless trap.
def _dir(keys_dir) -> Path:
    return Path(keys_dir)


def _key_path(keys_dir) -> Path:
    return _dir(keys_dir) / _PRIVATE_KEY_FILENAME


def _key_id_path(keys_dir) -> Path:
    return _dir(keys_dir) / _KEY_ID_FILENAME


def _counter_path(keys_dir) -> Path:
    return _dir(keys_dir) / _COUNTER_FILENAME


def generate_identity(keys_dir=DEFAULT_DEVICE_KEYS_DIR) -> str:
    """Creates this device's keypair. Returns the new device_key_id.

    Called once per device at provisioning. Regenerating produces a NEW
    identity that the registry has never seen, so it fails closed until
    enrolled -- which is the correct behaviour for a wiped device, not a bug.
    """
    _dir(keys_dir).mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    keystore.write_secret(
        _key_path(keys_dir),
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        _KEY_PURPOSE,
    )
    key_id = f"dev-{secrets.token_hex(8)}"
    _key_id_path(keys_dir).write_text(key_id)
    return key_id


def init_device(keys_dir=DEFAULT_DEVICE_KEYS_DIR) -> str:
    """Idempotent: returns the existing device_key_id, creating one only if
    this device has no identity yet."""
    if _key_path(keys_dir).exists() and _key_id_path(keys_dir).exists():
        return get_key_id(keys_dir)
    return generate_identity(keys_dir)


def get_key_id(keys_dir=DEFAULT_DEVICE_KEYS_DIR) -> str:
    path = _key_id_path(keys_dir)
    if not path.exists():
        raise DeviceIdentityError("device has no identity; call init_device() first")
    return path.read_text().strip()


def get_public_key(keys_dir=DEFAULT_DEVICE_KEYS_DIR) -> str:
    """Hex-encoded raw public key -- the only key material that ever leaves
    the device, and the only key material the registry stores."""
    private_key = _load_private_key(keys_dir)
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


def _load_private_key(keys_dir: Path) -> Ed25519PrivateKey:
    path = _key_path(keys_dir)
    if not path.exists():
        raise DeviceIdentityError("device has no identity; call init_device() first")
    return Ed25519PrivateKey.from_private_bytes(keystore.read_secret(path, _KEY_PURPOSE))


def secure_sign(data: bytes, keys_dir=DEFAULT_DEVICE_KEYS_DIR) -> str:
    """Signs raw bytes. Callers pass canonical_envelope_bytes(...) -- this
    function deliberately knows nothing about envelopes, so a hardware secure
    element implementing the same 'sign these bytes' surface can replace it
    without touching any caller."""
    return _load_private_key(keys_dir).sign(data).hex()


# --- monotonic counter -----------------------------------------------------
# On real hardware this belongs in NVS / secure storage. Here it is a file,
# which is the same trust level as the key beside it. Wokwi does not reliably
# persist flash across sessions -- see firmware/README.md and the
# SIMULATION_ALLOW_COUNTER_RESET note in atlas_service/device/envelope.py.


def next_counter(keys_dir=DEFAULT_DEVICE_KEYS_DIR) -> int:
    """Reads, increments, and PERSISTS before returning.

    Persisting before use is deliberate: if the device dies between issuing a
    request and recording it, the counter must have already moved, so the
    same value is never reused. Losing a counter value is harmless; reusing
    one is a replay window.
    """
    _dir(keys_dir).mkdir(parents=True, exist_ok=True)
    path = _counter_path(keys_dir)
    current = int(path.read_text().strip()) if path.exists() else 0
    nxt = current + 1
    path.write_text(str(nxt))
    return nxt


def peek_counter(keys_dir=DEFAULT_DEVICE_KEYS_DIR) -> int:
    path = _counter_path(keys_dir)
    return int(path.read_text().strip()) if path.exists() else 0


def reset_counter(keys_dir=DEFAULT_DEVICE_KEYS_DIR) -> None:
    """Simulates flash loss / a factory reset. Test-and-simulation only --
    a real device doing this silently would be indistinguishable from an
    attacker rewinding the counter, which is exactly why the server rejects
    a regression unless the simulation flag is explicitly on."""
    path = _counter_path(keys_dir)
    if path.exists():
        path.unlink()
